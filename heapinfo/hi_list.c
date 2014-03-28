#include "hi_list.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcassert.h"

void append(list l, void * o){
    //alloc the new element
    tl_assert(l!=NULL);
    struct listElt * e=VG_(malloc)("HI_list.append.1", sizeof(struct listElt));
    if(!e){
        VG_(tool_panic)("list malloc err");
    }
    //initialize it
    e->next=NULL;
    e->obj=o;
    //add it to the list
    if(l->first==NULL){
        //first add
        l->first=e;
    }else{
        //append
        l->last->next=e;
    }
    l->last=e;
}
void removeList(list l){
    //The list must be empty
    tl_assert(isEmpty(l));
    //free the list
    VG_(free)(l);
}
void * removeFirst(list l){
    void * o=NULL;
    if(!isEmpty(l)){
        struct listElt *temp=l->first;
        l->first=l->first->next;
        o=temp->obj;
        VG_(free)(temp);
        if(l->first==NULL){
            l->last=NULL;
        }
    }
    return o;
}

void * getFirst(list l){
    return isEmpty(l)?NULL:l->first->obj;
}

void * getLast(list l){
    return isEmpty(l)?NULL:l->last->obj;
}
Bool isEmpty(list l){
    return (l->first==NULL);
}
list newList(void){
    list l=(list)VG_(malloc)("HI_list_newList.1", sizeof(struct LIST));
    if(!l){
        VG_(tool_panic)("list malloc err");
    }
    l->first=NULL;
    l->last=NULL;
    return l;
}
