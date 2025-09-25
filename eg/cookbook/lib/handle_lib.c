#include "handle_lib.h"
#include <stdlib.h>

// The actual, private definition of the struct.
struct my_handle {
    int value;
};

my_handle_t * create_handle(int initial_value) {
    my_handle_t * h = (my_handle_t *)malloc(sizeof(my_handle_t));
    if (h) {
        h->value = initial_value;
    }
    return h;
}

void destroy_handle(my_handle_t * handle) {
    free(handle);
}

int get_handle_value(my_handle_t * handle) {
    return handle ? handle->value : -1;  // Return -1 if handle is null
}
