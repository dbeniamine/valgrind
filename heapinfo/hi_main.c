#include "pub_tool_vki.h"
#include "pub_tool_basics.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_libcproc.h"
#include "pub_tool_vki.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_machine.h"      // VG_(fnptr_to_fnentry)
#include "pub_tool_mallocfree.h"
#include "pub_tool_options.h"
#include "pub_tool_replacemalloc.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_wordfm.h"
#include "pub_tool_hashtable.h"

#include "hi_list.h"
#include "hi_array.h"
#include "heapinfo.h"

#define MAX(a,b) (((a)>(b))? (a):(b))
#define MIN(a,b) (((a)<(b))? (a):(b))

#define READ 0
#define WRITE 1

//Execution time
static ULong time;
static ULong numAcc=0;
static ULong nbFlush=0;
static ULong timeToFlush=10000000;
//time of the last call to flush
static ULong lastFlush;
static Bool showBlocksOnNextFlush=True;
//Needed for merge
static Addr MERGE_ADDR_MASK=0;
static Char *mergeGranularity="page";
static ULong mergeSize=0;
static int  mergeTimeThreshold=0;

//Only analyse between start and stop markers
static Bool clo_start_stop_marker = False;
static Bool clo_ignore_events = False;

//Is the output made for gnuplot ?
static Bool clo_gnuplot_output = False;
static Bool clo_gnuplot_output_file = False;
static Bool clo_gnuplot_plot_file = False;

//Data for gnuplot's output

//min and max for gnuplots graphics
static Addr minAddr=-1;
Addr maxAddr=0;

int currentIndex=1;

//Boolean for gnuplots keys
static Bool bc=False;
static Bool bnc=False;

//gnuplots filesnames
static Char *plotFileN;
static Char *outputFileN;

//gnuplot filesdescriptors
static  int plotFile;
static  int plotFileTemp;

//Informations about one acces
typedef struct HI_ACC
{
    //for vg_hashTable
    struct _VgHashNode *next;
    Addr accesAt; //hashMap key
    ULong size;
    ULong time;
    ULong lastTime;
    Bool concurrentAcc;
    ThreadId tid;
    ULong numAcc[2];
}HI_Acces;

//Informations about one allocated Block
typedef struct HI_BLK
{
    Addr start;
    SizeT size;
    ThreadId creatorId;
    Bool sharedBlock;
    Bool ignored;
    list acces;
    char* name;
}HI_Block;

hi_array *allocTable;
static VgHashTable lastAcces;
static int oldestMergableAcc;
static int nextMergableAcc;
static Addr *mergableAcc;
static Char BUFF[500], errBUFF[600];


/* parsing  arguments*/
static Bool hi_process_cmd_line_option(Char * arg)
{
    if VG_BOOL_CLO(arg, "--gnuplot-output", clo_gnuplot_output){}
    else if VG_BOOL_CLO(arg, "--use-start-stop-markers", clo_start_stop_marker){
        clo_ignore_events=True;
    }
    else if (VG_STR_CLO(arg, "--gnuplot-output-file", outputFileN)){
        clo_gnuplot_output_file=True;
    }
    else if (VG_STR_CLO(arg, "--gnuplot-plot-file", plotFileN)){
        clo_gnuplot_plot_file=True;
    }else if(VG_STR_CLO(arg, "--merge-granularity", mergeGranularity)){
    }
    else if(VG_INT_CLO(arg, "--merge-time-threshold", mergeTimeThreshold)){}
    else
        return False;
    return True;
}

static void hi_print_usage(void)
{
    VG_(printf)(
            "   --merge-time-threshold=N change the threshold for merging to acces [0]\n"
            "   --merge-granularity=<page|cache-line|none> [page]\n"
            "   --gnuplot-output no|yes preformat output for gnuplot [no]\n"
            "   --gnuplot-output-file=file change gnuplot's output file [hi_pid.ps]\n"
            "   --gnuplot-plot-file=file change gnuplot's plot file [hi_pid.gnuplot]\n"
            "   --gnuplot-data-file=file change gnuplot's data file [hi_pid.dat]\n"
            "   --use-start-stop-markers analyse only the part of code between markers [no]\n"
            );
}
static void hi_print_debug_usage(void)
{
    VG_(printf)("none\n");
}

//------------------------------------------------------------//
//--- Block and lists management                           ---//
//------------------------------------------------------------//

//write the string in buff ended by '\0'
static void fwrite(int fd, char * buff)
{
    SizeT size=VG_(strlen)(buff), ws;
    //VG_(printf)("write %lu o\n", size);
    if((ws=VG_(write)(fd, buff, size))!=size){
        VG_(snprintf)(errBUFF,600,"error while writing %s, only %lu bytes writed successful", BUFF, ws); 
        VG_(tool_panic)(errBUFF);
    }
}

static void display(HI_Acces *a, int index)
{
    ULong ratio=(100*a->numAcc[READ]/(a->numAcc[READ]+a->numAcc[WRITE]));
    if(!clo_gnuplot_output){
        VG_(printf)("%llu\%% read : at : %lx fom time : %llu to : %llu concurrent acces : %s size : %llu \n",ratio, a->accesAt, a->time, a->time+mergeTimeThreshold, (a->concurrentAcc ? "True" : "False" ),a->size);
    }else{
        int r,g,b;
        //define the color gradient
        if(a->concurrentAcc){
            //purple concurent read / orange write
            r=255;
            g=(int)(100-ratio)*200/100;
            b=(int)(255*ratio/100);
        }else{
            //blue read / green write
            r=0;
            g=(int)(100-ratio)*255/100;
            b=(int)(255*ratio/100);
        }
        //gnuplot instruction
        VG_(snprintf)(BUFF, 500, "set object %d rect from %llu, %lu to %llu,%llu fc rgb '#%02x%02x%02x' fs noborder\n", index, a->time, a->accesAt, a->lastTime, a->accesAt+a->size, r,g,b);
        fwrite(plotFileTemp, BUFF);
    }

}
static void flush(void)
{
    int i=0;
    Bool blockNotIgnored=False; //True if at least one unignored block have been flushed
    HI_Acces *curAcc=NULL;
    HI_Block *curb=NULL;
    //gnuplot specific output
    if(clo_gnuplot_output && showBlocksOnNextFlush){
        //gnuplot headers
        if(nbFlush==0){
            for(i=0;i<array_size(allocTable);i++){
                curb=(HI_Block*)elementAt(allocTable,i);
                if(!curb->ignored && curb->name!=NULL){
                    blockNotIgnored=True;
                    VG_(snprintf)(BUFF,500, "set label \"%s\" at 0,%lu\n", 
                            curb->name, curb->start+curb->size/2);
                    fwrite(plotFileTemp, BUFF);
                }
            }
            if(blockNotIgnored)
            {
                fwrite(plotFile, "plot ");
            }
        }
        i=0;
        //Blocks lines
        for(i=0;i<array_size(allocTable);i++){
            curb=(HI_Block*)elementAt(allocTable,i);
            if(curb->ignored)
                continue;
            if(nbFlush!=0 && !blockNotIgnored)
            {
                //first interesting block of this flush
                fwrite(plotFile, "replot");
                blockNotIgnored=True;
            }
            //begin line
            if(curb->sharedBlock){
                VG_(snprintf)(BUFF,500, "%lu lt 1 lc rgb 'black' %s, ", curb->start, (!bc ? "title 'concurrent data structure bounds'" : "notitle"));
                bc=True; 
            }else{
                VG_(snprintf)(BUFF,500, "%lu lt 1 lc rgb 'yellow' %s, ", curb->start, (!bnc ? "title 'non concurrent data structure bounds'" : "notitle")); 
                bnc=True;
            }
            fwrite(plotFile, BUFF);
            VG_(snprintf)(BUFF,500, "%lu lt 1 lc rgb '%s' notitle %s ", curb->start+curb->size, curb->sharedBlock?"black":"yellow", ((i==array_size(allocTable)-1)?"\\\n":",")); 
            fwrite(plotFile, BUFF);
        }
        fwrite(plotFile, ";\n");
    }
    if(!clo_gnuplot_output && showBlocksOnNextFlush ){
        VG_(printf)("Display block\n");
    }
    for(i=0;i<array_size(allocTable);i++){
        curb=(HI_Block*)elementAt(allocTable,i);
        if(curb->ignored)
        {
            tl_assert(isEmpty(curb->acces));
            continue;
        }
        if(!clo_gnuplot_output && showBlocksOnNextFlush ){
            blockNotIgnored=True;
            //Normal block display
            VG_(printf)("Block : %s %lx size : %lu alloc by : %d sharedBlock : %s\n", (curb->name==NULL?"":curb->name),curb->start, curb->size, (int)curb->creatorId, curb->sharedBlock?"True":"False");
        }
        while(!isEmpty(curb->acces)){
            curAcc=(HI_Acces *)removeFirst(curb->acces);
            display(curAcc, currentIndex);
            VG_(HT_remove)(lastAcces, curAcc->accesAt);
            currentIndex++;
            VG_(free)(curAcc);
        }
    }
    //empty the hashtable
    oldestMergableAcc=0;
    nextMergableAcc=0;
    lastFlush+=time;
    time=0;
    numAcc=0;
    if(blockNotIgnored)
        nbFlush++; // The flush is considered as effective only if there was at least one block printed
    showBlocksOnNextFlush=False;
}

static Bool addBlock(ThreadId tid, Addr start, SizeT size)
{
    HI_Block *temp=VG_(malloc)("hi.addBlock.1",sizeof(struct HI_BLK));
    temp->start=start;
    temp->size=size;
    temp->creatorId=tid;
    temp->sharedBlock=False;
    temp->name=NULL;
    temp->acces=newList();
    temp->ignored=clo_ignore_events;
    if(!addElement(allocTable, temp)){
        VG_(free)(temp);
        return False;
    }
    return True;
}

static int inBlock(void* e, void *accesAt)
{
    HI_Block *b= (HI_Block*)e;
    tl_assert(b!=NULL);
    if( b->start <= (Addr)accesAt){
        if( b->start+b->size > (Addr)accesAt){
            return 0;
        }
        return -1;
    }
    return 1;
}
static int compBlock(void *e1, void*e2)
{
    HI_Block *b1= (HI_Block*)e1;
    HI_Block *b2= (HI_Block*)e2;
    tl_assert(b1!=NULL);
    tl_assert(b2!=NULL);
    return (int)(b1->start-b2->start);
}


static void addAcces(HI_Block *b, Addr accesAt, SizeT size, ThreadId tid, int accesType)
{
    accesAt&=MERGE_ADDR_MASK;
    if(clo_gnuplot_output){
        //for gnuplot graphics
        if(minAddr==-1){
            minAddr=accesAt;
        }else{
            minAddr=MIN(accesAt, minAddr);
        }
        maxAddr=MAX(accesAt+size, maxAddr); 
    }
    //if the current thread isn't the block's creator, the bloc is a
    //shared block
    if(b->creatorId!=tid){
        //if we have changed the status of the block, then we have to 
        //display the block on next flush
        showBlocksOnNextFlush=showBlocksOnNextFlush || !(b->sharedBlock);
        b->sharedBlock=True;
    }
    HI_Acces *last=(HI_Acces *)VG_(HT_lookup)(lastAcces, accesAt);
    if(last!=NULL){
        last->concurrentAcc=(tid!=last->tid)|| last->concurrentAcc;
        last->numAcc[accesType]++;
        last->lastTime=time+lastFlush;
        if(mergeSize==0){
            last->size=MAX(size, last->size);
        }else{
            last->size=mergeSize;
        }
        time++;
    }else{
        //Allocation of meta data
        HI_Acces *a=(HI_Acces *)VG_(malloc)("hi.addAccess", sizeof(struct HI_ACC));
        if(!a){
            VG_(tool_panic)("Allocation error");
        }
        //write the meta data
        a->time=(time+lastFlush);
        a->lastTime=(time+lastFlush);
        a->accesAt=accesAt;
        a->tid=tid;
        a->concurrentAcc=False;
        a->numAcc[accesType]=1;
        a->numAcc[(accesType+1)%2]=0;
        a->size=size;
        append(b->acces, (void *)a);
        if(b->ignored)
            showBlocksOnNextFlush=True;
        b->ignored=False; // We don't ignore the bloc anymore
        time++;
        numAcc++;
        //add the access to the hash table and remove the oldest entry 
        if(mergeTimeThreshold>0)
        {
            last=VG_(HT_lookup)(lastAcces,mergableAcc[oldestMergableAcc]);
            while(last!=NULL && last->time+mergeTimeThreshold<time+lastFlush){
                void *old=VG_(HT_remove)(lastAcces,mergableAcc[oldestMergableAcc]);
                tl_assert(old!=NULL);  
                oldestMergableAcc=(oldestMergableAcc+1)%mergeTimeThreshold;
                last=VG_(HT_lookup)(lastAcces,mergableAcc[oldestMergableAcc]);
            }
            VG_(HT_add_node)(lastAcces, a);
            mergableAcc[nextMergableAcc]=accesAt;
            nextMergableAcc=(nextMergableAcc+1)%mergeTimeThreshold;
        }
    }
    if(numAcc==timeToFlush){
        flush();
    }
}
//------------------------------------------------------------//
//--- Malloc replacement                                   ---//
//------------------------------------------------------------//
    static
void* new_block ( ThreadId tid, void* p, SizeT req_szB, SizeT req_alignB,
        Bool is_zeroed )
{
    tl_assert(p == NULL); // don't handle custom allocators right now
    if ((SSizeT)req_szB < 0) return NULL;

    // Allocate and zero if necessary
    p = VG_(cli_malloc)( req_alignB, req_szB );
    if (!p) {
        VG_(printf)("malloc fail : %lu %p\n", req_szB, p);
        return NULL;
    }
    if (is_zeroed){ 
        VG_(memset)(p, 0, req_szB);
    }
    //Generate the meta data 
    if(addBlock(tid, (Addr)p, req_szB) ){
        //a block has been added so we have to show it on next flush
        if(!clo_ignore_events)
            showBlocksOnNextFlush=True;
        return p;
    }
    VG_(printf)("addBlock fail : %lu %p\n", req_szB, p);
    //addBlock has fail
    if(p){
        //the first alloc has worked, we free the block
        VG_(cli_free)(p);
    }
    return NULL;
}


static void deleteBlock(void *p)
{
    HI_Block *b;
    //We flush the data to keep the coherency 
    flush();
    //then we find the block and delete it
    b=(HI_Block*)delElement(allocTable, p);
    if(b){
        removeList(b->acces);
        VG_(free)(b);
    }
}

static void* renew_block ( ThreadId tid, void* p_old, SizeT new_req_szB )
{
    int index=getIndex(allocTable,p_old);
    void* p_new = NULL;
    //update meta data
    HI_Block *b=(HI_Block*)elementAt(allocTable,index);
    tl_assert(b);
    // Actually do the allocation, if necessary.
    if (new_req_szB <= b->size) {

        // New size is smaller or same; block not moved.
        return p_old;

    }
    // New size is bigger;  make new block, copy shared contents, free old.
    p_new = VG_(cli_malloc)(VG_(clo_alignment), new_req_szB);
    if (!p_new) {
        // Nb: if realloc fails, NULL is returned but the old block is not
        // touched.  What an awful function.
        return NULL;
    }
    tl_assert(p_new != p_old);

    //Copy the data
    VG_(memcpy)(p_new, p_old, b->size);
    if(!clo_ignore_events)
    {
        flush();
    }
    //update the meta data
    tl_assert(delElementAt(allocTable,index)!=NULL);
    b->start=(Addr)p_new;
    b->size=new_req_szB;
    if(!addElement(allocTable,b)){
        VG_(tool_panic)("renew_block : error adding element");
    }
    if(!b->ignored)
        showBlocksOnNextFlush=True;
    VG_(cli_free)(p_old);
    return p_new;
}

static void* hi_malloc ( ThreadId tid, SizeT szB )
{
    return new_block( tid, NULL, szB, VG_(clo_alignment), /*is_zeroed*/False );
}

static void* hi___builtin_new ( ThreadId tid, SizeT szB )
{
    return new_block( tid, NULL, szB, VG_(clo_alignment), /*is_zeroed*/False );
}

static void* hi___builtin_vec_new ( ThreadId tid, SizeT szB )
{
    return new_block( tid, NULL, szB, VG_(clo_alignment), /*is_zeroed*/False );
}

static void* hi_calloc ( ThreadId tid, SizeT m, SizeT szB )
{

    //void *p=VG_(cli_malloc)(VG_(clo_alignment),m*szB);
    //VG_(memset)(p, 0, m*szB);
    //return p;
    return new_block( tid, NULL, m*szB, VG_(clo_alignment), /*is_zeroed*/True );
}

static void *hi_memalign ( ThreadId tid, SizeT alignB, SizeT szB )
{
    return new_block( tid, NULL, szB, alignB, False );
}

static void hi_free ( ThreadId tid __attribute__((unused)), void* p )
{
    deleteBlock(p);
    VG_(cli_free)(p);
}

static void hi___builtin_delete ( ThreadId tid, void* p )
{
    deleteBlock(p);
    VG_(cli_free)(p);
}

static void hi___builtin_vec_delete ( ThreadId tid, void* p )
{
    deleteBlock(p);
    VG_(cli_free)(p);
}

static void* hi_realloc ( ThreadId tid, void* p_old, SizeT new_szB )
{
    if (p_old == NULL) {
        return hi_malloc(tid, new_szB);
    }
    if (new_szB == 0) {
        hi_free(tid, p_old);
        return NULL;
    }
    return renew_block(tid, p_old, new_szB);
}

static SizeT hi_malloc_usable_size ( ThreadId tid, void* p )
{                                                            
    tl_assert(0);
}                                                            


//------------------------------------------------------------//
//--- Read and Write handlers                              ---//
//------------------------------------------------------------//


static void hi_handle_write(Addr addr, SizeT size, ThreadId tid)
{
    //    if(!clo_ignore_events)
    //        return;
    HI_Block *b;
    if((b=(HI_Block*)lookup(allocTable,(void*)addr))){
        addAcces(b,addr,size,tid, WRITE);
    }
}

static void hi_handle_read(Addr addr, SizeT size, ThreadId tid)
{
    //    if(!clo_ignore_events)
    //        return;
    HI_Block *b;
    if((b=(HI_Block*)lookup(allocTable,(void*)addr))){
        addAcces(b,addr,size,tid, READ);
    }
}
    static
void hi_handle_noninsn_read ( CorePart part, ThreadId tid, Char* s,
        Addr base, SizeT size )
{
    switch (part) {
        case Vg_CoreSysCall:
            hi_handle_read(base, size, tid);
            break;
        case Vg_CoreSysCallArgInMem:
            break;
        case Vg_CoreTranslate:
            break;
        default:
            break;
            //tl_assert(0);
    }
}

    static
void hi_handle_noninsn_write ( CorePart part, ThreadId tid,
        Addr base, SizeT size )
{
    switch (part) {
        case Vg_CoreSysCall:
            hi_handle_write(base, size, tid);
            break;
        case Vg_CoreSignal:
            break;
        default:
            break;
            //tl_assert(0);
    }
}
static Bool hi_handle_client_request(ThreadId tid, UWord*arg, UWord* ret)
{
    HI_Block* b;
    switch (arg[0]){
        case VG_USERREQ__NAME_STRUCT :
            b=(HI_Block*)lookup(allocTable, (void*)arg[1]);
            if(b){
                b->name=(char*)arg[2];
                return True;
            }
            return False;
            break;
        case VG_USERREQ__IGNORE_STRUCT:
            //Find and delete the block corresponding to the address in arg 1
            b=(HI_Block*)delElement(allocTable, (void*)arg[1]);
            if(!b){
                return False;
            }
            //if the block exist, we delete all entries without displaying it

            while(!isEmpty(b->acces)){
                VG_(free)(removeFirst(b->acces));  
            }
            removeList(b->acces);

            break;
        case VG_USERREQ__START_HI_ANALYSE:
            if(clo_start_stop_marker) clo_ignore_events=False;
            break;
        case VG_USERREQ__STOP_HI_ANALYSE:
            if(clo_start_stop_marker) clo_ignore_events=True;
        case VG_USERREQ__RESIZE_STRUCT :
            b=(HI_Block*)lookup(allocTable, (void*)arg[1]);
            if(b){
                VG_(printf)("arg2 %lu\n", *((SizeT*)arg[2]));
                b->size=*((SizeT *)arg[2]);
                return True;
            }
            return False;
            break;
        default : 
            return False;
    }
    return True;
}

//------------------------------------------------------------//
//--- Instrumentation                                      ---//
//------------------------------------------------------------//

#define binop(_op, _arg1, _arg2) IRExpr_Binop((_op),(_arg1),(_arg2))
#define mkexpr(_tmp)             IRExpr_RdTmp((_tmp))
#define mkU32(_n)                IRExpr_Const(IRConst_U32(_n))
#define mkU64(_n)                IRExpr_Const(IRConst_U64(_n))
#define assign(_t, _e)           IRStmt_WrTmp((_t), (_e))
    static
void addMemEvent(IRSB* sbOut, Bool isWrite, Int szB, IRExpr* addr,
        Int goff_sp, ThreadId tid)
{

    IRType   tyAddr   = Ity_INVALID;
    HChar*   hName    = NULL;
    void*    hAddr    = NULL;
    IRExpr** argv     = NULL;
    IRDirty* di       = NULL;

    const Int THRESH = 4096 * 4; // somewhat arbitrary
    const Int rz_szB = VG_STACK_REDZONE_SZB;

    tyAddr = typeOfIRExpr( sbOut->tyenv, addr );
    tl_assert(tyAddr == Ity_I32 || tyAddr == Ity_I64);

    if (isWrite) {
        hName = "hi_handle_write";
        hAddr = &hi_handle_write;
    } else {
        hName = "hi_handle_read";
        hAddr = &hi_handle_read;
    }

    argv = mkIRExprVec_3( addr, mkIRExpr_HWord(szB), mkIRExpr_HWord(tid) );

    /* Add the helper. */
    tl_assert(hName);
    tl_assert(hAddr);
    tl_assert(argv);
    di = unsafeIRDirty_0_N( 2/*regparms*/,
            hName, VG_(fnptr_to_fnentry)( hAddr ),
            argv );
    /* Generate the guard condition: "(addr - (SP - RZ)) >u N", for
       some arbitrary N.  If that fails then addr is in the range (SP -
       RZ .. SP + N - RZ).  If N is smallish (a page?) then we can say
       addr is within a page of SP and so can't possibly be a heap
       access, and so can be skipped. */
    IRTemp sp = newIRTemp(sbOut->tyenv, tyAddr);
    addStmtToIRSB( sbOut, assign(sp, IRExpr_Get(goff_sp, tyAddr)));

    IRTemp sp_minus_rz = newIRTemp(sbOut->tyenv, tyAddr);
    addStmtToIRSB(
            sbOut,
            assign(sp_minus_rz,
                tyAddr == Ity_I32
                ? binop(Iop_Sub32, mkexpr(sp), mkU32(rz_szB))
                : binop(Iop_Sub64, mkexpr(sp), mkU64(rz_szB)))
            );

    IRTemp diff = newIRTemp(sbOut->tyenv, tyAddr);
    addStmtToIRSB(
            sbOut,
            assign(diff,
                tyAddr == Ity_I32 
                ? binop(Iop_Sub32, addr, mkexpr(sp_minus_rz))
                : binop(Iop_Sub64, addr, mkexpr(sp_minus_rz)))
            );

    IRTemp guard = newIRTemp(sbOut->tyenv, Ity_I1);
    addStmtToIRSB(
            sbOut,
            assign(guard,
                tyAddr == Ity_I32 
                ? binop(Iop_CmpLT32U, mkU32(THRESH), mkexpr(diff))
                : binop(Iop_CmpLT64U, mkU64(THRESH), mkexpr(diff)))
            );
    di->guard = mkexpr(guard);

    addStmtToIRSB( sbOut, IRStmt_Dirty(di) );
}

    static
IRSB* hi_instrument ( VgCallbackClosure* closure,
        IRSB* sbIn,
        VexGuestLayout* layout,
        VexGuestExtents* vge,
        IRType gWordTy, IRType hWordTy )
{
    Int   i, n = 0;
    IRSB* sbOut;
    IRTypeEnv* tyenv = sbIn->tyenv;

    const Int goff_sp = layout->offset_SP;

    // We increment the instruction count in two places:
    // - just before any Ist_Exit statements;
    // - just before the IRSB's end.
    // In the former case, we zero 'n' and then continue instrumenting.

    sbOut = deepCopyIRSBExceptStmts(sbIn);

    // Copy verbatim any IR preamble preceding the first IMark
    i = 0;
    while (i < sbIn->stmts_used && sbIn->stmts[i]->tag != Ist_IMark) {
        addStmtToIRSB( sbOut, sbIn->stmts[i] );
        i++;
    }

    for (/*use current i*/; i < sbIn->stmts_used; i++) {
        IRStmt* st = sbIn->stmts[i];

        if (!st || st->tag == Ist_NoOp) continue;

        if(!clo_ignore_events)
        {
            switch (st->tag) {

                case Ist_IMark: {
                                    n++;
                                    break;
                                }

                case Ist_Exit: {
                                   /*if (n > 0) {
                                   // Add an increment before the Exit statement, then reset 'n'.
                                   add_counter_update(sbOut, n);
                                   n = 0;
                                   }*/
                                   //add the block to the list
                                   break;
                               }

                case Ist_WrTmp: {
                                    IRExpr* data = st->Ist.WrTmp.data;
                                    if (data->tag == Iex_Load) {
                                        IRExpr* aexpr = data->Iex.Load.addr;
                                        // Note also, endianness info is ignored.  I guess
                                        // that's not interesting.
                                        addMemEvent( sbOut, False/*!isWrite*/,
                                                sizeofIRType(data->Iex.Load.ty),
                                                aexpr, goff_sp , closure->tid);
                                    }
                                    break;
                                }

                case Ist_Store: {
                                    IRExpr* data  = st->Ist.Store.data;
                                    IRExpr* aexpr = st->Ist.Store.addr;
                                    addMemEvent( sbOut, True/*isWrite*/, 
                                            sizeofIRType(typeOfIRExpr(tyenv, data)),
                                            aexpr, goff_sp , closure->tid);
                                    break;
                                }

                case Ist_Dirty: {
                                    Int      dataSize;
                                    IRDirty* d = st->Ist.Dirty.details;
                                    if (d->mFx != Ifx_None) {
                                        /* This dirty helper accesses memory.  Collect the details. */
                                        tl_assert(d->mAddr != NULL);
                                        tl_assert(d->mSize != 0);
                                        dataSize = d->mSize;
                                        // Large (eg. 28B, 108B, 512B on x86) data-sized
                                        // instructions will be done inaccurately, but they're
                                        // very rare and this avoids errors from hitting more
                                        // than two cache lines in the simulation.
                                        if (d->mFx == Ifx_Read || d->mFx == Ifx_Modify)
                                        {
                                            addMemEvent( sbOut, False/*!isWrite*/,
                                                    dataSize, d->mAddr, goff_sp , closure->tid);
                                        }
                                        if (d->mFx == Ifx_Write || d->mFx == Ifx_Modify)
                                        {
                                            addMemEvent( sbOut, True/*isWrite*/,
                                                    dataSize, d->mAddr, goff_sp , closure->tid);
                                        }
                                    } else {
                                        tl_assert(d->mAddr == NULL);
                                        tl_assert(d->mSize == 0);
                                    }
                                    break;
                                }

                case Ist_CAS: {
                                  /* We treat it as a read and a write of the location.  I
                                     think that is the same behaviour as it was before IRCAS
                                     was introduced, since prior to that point, the Vex
                                     front ends would translate a lock-prefixed instruction
                                     into a (normal) read followed by a (normal) write. */
                                  Int    dataSize;
                                  IRCAS* cas = st->Ist.CAS.details;
                                  tl_assert(cas->addr != NULL);
                                  tl_assert(cas->dataLo != NULL);
                                  dataSize = sizeofIRType(typeOfIRExpr(tyenv, cas->dataLo));
                                  if (cas->dataHi != NULL)
                                      dataSize *= 2; /* since it's a doubleword-CAS */
                                  addMemEvent( sbOut, False/*!isWrite*/,
                                          dataSize, cas->addr, goff_sp , closure->tid);
                                  addMemEvent( sbOut, True/*isWrite*/,
                                          dataSize, cas->addr, goff_sp , closure->tid);
                                  break;
                              }

                case Ist_LLSC: {
                                   IRType dataTy;
                                   if (st->Ist.LLSC.storedata == NULL) {
                                       /* LL */
                                       dataTy = typeOfIRTemp(tyenv, st->Ist.LLSC.result);

                                       addMemEvent( sbOut, False/*!isWrite*/,
                                               sizeofIRType(dataTy),
                                               st->Ist.LLSC.addr, goff_sp , closure->tid);
                                   } else {
                                       /* SC */
                                       dataTy = typeOfIRExpr(tyenv, st->Ist.LLSC.storedata);
                                       addMemEvent( sbOut, True/*isWrite*/,
                                               sizeofIRType(dataTy),
                                               st->Ist.LLSC.addr, goff_sp , closure->tid);
                                   }
                                   break;
                               }

                default:
                               break;
            }
        }

        addStmtToIRSB( sbOut, st );
    }

    /*if (n > 0) {
    // Add an increment before the SB end.
    add_counter_update(sbOut, n);
    }*/
    return sbOut;
}

//------------------------------------------------------------//
//--- Initialisation                                       ---//
//------------------------------------------------------------//

static void hi_post_clo_init(void)
{
    if((allocTable=new_array(1024, compBlock, inBlock))==NULL){
        VG_(tool_panic)("alloc fail");
    }
    time=0;
    lastFlush=0;
    if((mergableAcc=(Addr *)VG_(malloc)("hi.hi_post_clo_init.2", sizeof(Addr)*mergeTimeThreshold))==NULL){
        VG_(tool_panic)("alloc fail");
    }
    oldestMergableAcc=0;
    if(!VG_(strcmp)(mergeGranularity, "none")){
        int i;
        for(i=0;i<8*sizeof(Addr);i++){
            MERGE_ADDR_MASK|=(~(Addr)0)<<i;
        }
    }else{
        if(!VG_(strcmp)(mergeGranularity, "page")){
            mergeSize=VKI_PAGE_SIZE;
        }else if(!VG_(strcmp)(mergeGranularity,"cache-line")){
            //Determinate the size of a cache line
            //will only work on linux ...
            int f=VG_(fd_open)("/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size", VKI_O_RDONLY, 0);
            if(f!=-1){
                char buff[5];
                buff[4]='\0';
                VG_(read)(f,buff,4);
                VG_(close)(f);
                mergeSize=VG_(strtoull10)(buff, NULL);
            }else{
                VG_(tool_panic)("unable to determinate cache line size");
            }
        }else{
            mergeSize=VG_(strtoull10)(mergeGranularity,NULL);
        }
        //in the page (or cache line)
        int lsize=VG_(log2_64)(mergeSize);
        int i;
        //The lsize Least Signifiant Bits are the offset, we set all the
        //others
        for(i=lsize; i<8*sizeof(Addr); i++){
            MERGE_ADDR_MASK|=(~((Addr)0)<<i); 
        }
    }
    //openning gnuplot's file if necessary
    if(clo_gnuplot_output){
        if(!clo_gnuplot_plot_file){
            if((plotFileN=VG_(malloc)("hi.post_clo_init.1", 20))==NULL){
                VG_(tool_panic)("alloc fail");
            }
            VG_(sprintf)(plotFileN, "hi_%d.gnuplot", (VG_(getpid)()));
        }
        if(!clo_gnuplot_output_file){
            if((outputFileN=VG_(malloc)("hi.post_clo_init.1", 20))==NULL){
                VG_(tool_panic)("alloc fail");
            }
            VG_(sprintf)(outputFileN, "hi_%d.ps", (VG_(getpid)()));
        }
        if((plotFile=VG_(fd_open)(plotFileN, VKI_O_RDWR | VKI_O_CREAT, (VKI_S_IRUSR | VKI_S_IWUSR)) )==-1){
            VG_(tool_panic)("open gnuplot's plot file fail");
        }
        VG_(snprintf)(BUFF,500,"%s_temp", plotFileN);
        if((plotFileTemp=VG_(fd_open)(BUFF, VKI_O_RDWR | VKI_O_CREAT, (VKI_S_IRUSR | VKI_S_IWUSR)) )==-1){
            VG_(tool_panic)("open gnuplot's plot temp file fail");
        }
    }
}
static void copyFile(int src, int dest)
{
    int sizeRead;
    while((sizeRead=VG_(read)(src,BUFF,500))>0){
        VG_(write)(dest,BUFF,sizeRead);
    }
}
static void hi_fini(Int exit_status)
{
    flush();
    if(clo_gnuplot_output){

        //merge the two parts of the plot file
        VG_(lseek)(plotFileTemp,0,VKI_SEEK_SET);
        copyFile(plotFileTemp, plotFile);
        VG_(close)(plotFileTemp);
        //remove the temporary file
        VG_(snprintf)(BUFF,500,"%s_temp", plotFileN);
        VG_(unlink)(BUFF);

        fwrite(plotFile,  "set term postscript enhanced color\n");
        VG_(snprintf)(BUFF,500, "set output '%s'\n", outputFileN);
        fwrite(plotFile, BUFF);
        fwrite(plotFile, "set format y \"%x\"\n");
        fwrite(plotFile, "set xlabel 'instruction number'\n");
        fwrite(plotFile, "set ylabel 'memory address'\n");
        fwrite(plotFile, "set key below\n");
        fwrite(plotFile, "set grid\n");
        VG_(snprintf)(BUFF,500,"set xrange[0:%llu]\n", time+lastFlush);
        fwrite(plotFile, BUFF);
        fwrite(plotFile,"replot\n");



        VG_(close)(plotFile);
    }
    VG_(exit)(exit_status);
}

static void hi_pre_clo_init(void)
{
    VG_(details_name)            ("HEAPINFO");
    VG_(details_version)         (NULL);
    VG_(details_description)     ("a heap analysis tool");
    VG_(details_copyright_author)("");
    VG_(details_bug_reports_to)  (VG_BUGS_TO);

    // Basic functions.
    VG_(basic_tool_funcs)          (hi_post_clo_init,
            hi_instrument,
            hi_fini);
    //command line
    VG_(needs_command_line_options)(hi_process_cmd_line_option, hi_print_usage, hi_print_debug_usage);
    //malloc replacement
    VG_(needs_malloc_replacement) (hi_malloc,
            hi___builtin_new,
            hi___builtin_vec_new,
            hi_memalign,
            hi_calloc,
            hi_free,
            hi___builtin_delete,
            hi___builtin_vec_delete,
            hi_realloc,
            hi_malloc_usable_size,
            0);
    //handle reads and writes
    VG_(track_pre_mem_read)        ( hi_handle_noninsn_read );
    VG_(track_post_mem_write)      ( hi_handle_noninsn_write );
    //Client requests
    VG_(needs_client_requests)(hi_handle_client_request);
    lastAcces=VG_(HT_construct)("heap info hashtable");

}

VG_DETERMINE_INTERFACE_VERSION(hi_pre_clo_init)
