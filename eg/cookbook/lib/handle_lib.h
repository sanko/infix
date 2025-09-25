#pragma once

// Opaque struct declaration. The implementation is hidden from the user.
struct my_handle;
typedef struct my_handle my_handle_t;

// C-style API for the opaque handle.
my_handle_t * create_handle(int initial_value);
void destroy_handle(my_handle_t * handle);
int get_handle_value(my_handle_t * handle);
