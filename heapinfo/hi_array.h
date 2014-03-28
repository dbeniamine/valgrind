#ifndef HI_ARRAY_H
#define HI_ARRAy_H
#include "pub_tool_basics.h"

/*Provide a sorted array tool*/
typedef struct _hi_array{
    int n_elt;
    int size;
    void **table;
    int(*func[2])(void*,void*);
}hi_array;

/*Create a new array with an intial size of init_size elements, the array wwill
 * increase if needed
 * for the two fonction the value return is 0 if both element match, >0 if the
 * first is "bigger" else <0 */
extern hi_array *new_array(int init_size, int(*comp_fn)(void*e1,void*e2), int(match_fn)(void* elt, void*key));

/*find an element  O(log(n))*/
extern void *lookup(hi_array*, void *key);
extern int getIndex(hi_array *arr,void *key);

/*Acces O(1) */
extern void *elementAt(hi_array*,int);

/*Add an element a the good place, O(log(n)) true if the element has been added*/
extern Bool addElement(hi_array*, void *);

/*Delete and element matching with key
 * return NULL if there are no such element
 * or return the element removed*/
extern void *delElement(hi_array*,void* key);

/*Delete the element at the index ind  
 * return NULL if there are no such element
 * or return the element removed*/
extern void *delElementAt(hi_array *, int ind);

/*number of element in the array (O(1))*/
extern int array_size(hi_array*);

#endif
