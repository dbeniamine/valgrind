#ifndef HI_LIST_H
#define HI_LIST_H
#include "pub_tool_basics.h"
#include "heapinfo.h"

struct listElt{
    void * obj;
    struct listElt * next;
};

typedef struct LIST{
    struct listElt* first;
    struct listElt* last;
}*list;

void append(list l, void *o);

void *removeFirst(list l);

void removeList(list l);

void *getFirst(list l);

void *getLast(list l);

Bool isEmpty(list l);

list newList(void);
#endif
