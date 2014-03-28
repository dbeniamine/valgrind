#include "hi_array.h"
#include "pub_tool_mallocfree.h"

#define COMP_FN 0
#define MATCH_FN 1

hi_array*
new_array(int init_size, int(*cmp_fn)(void*,void*), int(*match_fn)(void*,void*)){
    hi_array *arr;
    if((arr=(hi_array*)VG_(malloc)("hi_array.new_array.1",sizeof(hi_array)))==NULL){
        return NULL;
    }
    arr->n_elt=0;
    arr->size=init_size;
    if((arr->table=(void **)VG_(malloc)("hi_array.new_array.2",init_size*sizeof(void *)))==NULL){
        VG_(free)(arr);
        return NULL;
    }
    arr->func[COMP_FN]=cmp_fn;
    arr->func[MATCH_FN]=match_fn;
    return arr;
}

static int
intLookup(hi_array *arr, void *o, int fn){
    int begin=0, end=arr->n_elt-1, middle,comp;
    while(begin<=end){
        middle=begin +(end-begin)/2;
        comp=arr->func[fn](arr->table[middle],o);
        if(comp==0){
            return middle;
        }else if (comp >0){
            end=middle-1;
        }else{
            begin=middle+1;
        }
    }
    if(comp>0){
        return middle;
    }else{
        return begin;
    }
}

void *
lookup(hi_array *arr, void *key){
    if(arr->n_elt>0){
        int ind=intLookup(arr,key, MATCH_FN);
        if(ind <arr->n_elt && arr->func[MATCH_FN](arr->table[ind],key)==0){
            return arr->table[ind];
        }
    }
    return NULL;
}
int 
getIndex(hi_array *arr,void *key){
    if(arr->n_elt>0){
        int ind=intLookup(arr,key, MATCH_FN);
        if(ind <arr->n_elt && arr->func[MATCH_FN](arr->table[ind],key)==0){
            return ind;
        }
    }
    return -1;
}


void *
elementAt(hi_array *arr, int i){
    return arr->table[i];
}

Bool
addElement(hi_array* arr,void *e){
    //first we find the place for e
    int ind,i,comp;
    if(arr->n_elt==0){
        ind=0;
    }else{
        ind=intLookup(arr,e, COMP_FN);
        if(ind <arr->n_elt && (comp=arr->func[COMP_FN](arr->table[ind],e))==0){
            //if e is already in the table, we don't add it
            return True;
        }
    }
    //increase the table size if needed
    if(arr->n_elt==arr->size){
        arr->size=2*arr->size;
        arr->table=VG_(realloc)("hi_array.addElement.1", arr->table,arr->size*sizeof(void*));
        if(arr->table==NULL){ return False;}
    }
    //add the element
    for(i=arr->n_elt;i>ind;i--){
        arr->table[i]=arr->table[i-1];
    }
    arr->table[ind]=e;
    arr->n_elt++;
    return True;
}

void *
delElementAt(hi_array *arr, int ind){
    int i;
    void *e=NULL;
    if(ind < arr->n_elt && ind >= 0){
        e=arr->table[ind];
        for(i=ind; i<arr->n_elt-1;i++){
            arr->table[i]=arr->table[i+1];
        }
        arr->n_elt--;
    }
    return e;
}

void *
delElement(hi_array *arr,void *key){
    if(arr->n_elt==0){
        return NULL;
    }
    return delElementAt(arr,intLookup(arr,key,MATCH_FN));
}



int
array_size(hi_array *arr){
    return arr->n_elt;
}






