/**
 * @file 501_direct_marshalling.c
 * @brief Test suite for the high-performance direct marshalling API.
 *
 * This test acts as a "mock" language binding to validate the direct marshalling
 * feature. It defines its own simple object system (`MockObject`) and provides
 * marshaller/write-back handlers to convert between these mock objects and native
 * C types.
 */

// Define these before including double_tap to enable the harness and its implementation.
#define DBLTAP_IMPLEMENTATION
#include "common/compat_c23.h"
#include "common/double_tap.h"
#include "common/infix_config.h"
#include "common/infix_internals.h"
#include <infix/infix.h>
#include <string.h>

//
typedef struct {
    double x;
    double y;
} Point;
typedef struct {
    Point start;
    Point end;
} Line;
typedef struct {
#if defined(_MSC_VER)
    char dummy[0];  // MSVC does not support empty structs {}.
#endif
} EmptyStruct;
typedef int (*IntFunc)(int);

// A simple function to test struct-by-value and primitive arguments/return.
static Point add_points(Point p1, Point p2, int dummy_arg) {
    Point result;
    result.x = p1.x + p2.x + dummy_arg;
    result.y = p1.y + p2.y + dummy_arg;
    return result;
}

// A function to test "in-out" pointer-to-struct arguments.
static void move_point(Point * p, int32_t dx, int32_t dy) {
    if (p) {
        p->x += dx;
        p->y += dy;
    }
}

// A function with many arguments to test register spilling to the stack.
static double sum_mixed_types(double a, int b, float c, int d, double e, int f, float g) {
    note(
        "a: %f, b: %d, c: %f, d: %d, e: %f, f: %d, g: %f, total: %f", a, b, c, d, e, f, g, (a + b + c + d + e + f + g));
    return a + b + c + d + e + f + g;
}

// A function to test string handling and a simple pointer "out" parameter.
static const char * check_string(const char * s, int64_t * out_len) {
    if (s && out_len)
        *out_len = strlen(s);
    return s;
}

static int64_t sum_small_ints(unsigned char uc, short ss, uint32_t ui, int64_t ll) { return uc + ss + ui + ll; }

static double get_line_length(Line l) {
    double dx = l.end.x - l.start.x;
    double dy = l.end.y - l.start.y;
    // Don't need sqrt for test, just a predictable calculation.
    return (dx * dx) + (dy * dy);
}

static int takes_empty_struct(EmptyStruct es, int tag) {
    (void)es;
    return tag * 2;
}

static int execute_callback(IntFunc func, int value) {
    if (func)
        return func(value);
    return -1;
}

// A simple tagged union to simulate a dynamic language object (like an SV* or PyObject*).
typedef enum {
    MOCK_TYPE_INT,
    MOCK_TYPE_DOUBLE,
    MOCK_TYPE_FLOAT,
    MOCK_TYPE_POINT,
    MOCK_TYPE_STRING,
    MOCK_TYPE_LINE,
    MOCK_TYPE_FUNC
} MockObjectType;
typedef struct MockObject {
    MockObjectType type;
    union {
        int64_t i;
        double d;
        float f;
        const char * s;
        struct MockObject * fields;  // For structs, points to an array of field objects
        void * func_ptr;             // For function pointers
    } value;
} MockObject;

// Marshaller & Write-back Handlers for our Mock Language

static infix_direct_value_t mock_marshaller_int(void * source_obj) {
    MockObject * obj = (MockObject *)source_obj;
    infix_direct_value_t val;
    val.i64 = (obj && obj->type == MOCK_TYPE_INT) ? obj->value.i : 0;
    return val;
}

static infix_direct_value_t mock_marshaller_double(void * source_obj) {
    MockObject * obj = (MockObject *)source_obj;
    infix_direct_value_t val;
    val.f64 = (obj && (obj->type == MOCK_TYPE_DOUBLE || obj->type == MOCK_TYPE_FLOAT)) ? obj->value.d : 0.0;
    return val;
}

static infix_direct_value_t mock_marshaller_string(void * source_obj) {
    MockObject * obj = (MockObject *)source_obj;
    infix_direct_value_t val;
    val.ptr = (obj && obj->type == MOCK_TYPE_STRING) ? (void *)obj->value.s : NULL;
    return val;
}

static void mock_marshaller_point(void * source_obj, void * dest_buffer, const infix_type * type) {
    (void)type;
    MockObject * obj = (MockObject *)source_obj;
    Point * p = (Point *)dest_buffer;
    if (obj && obj->type == MOCK_TYPE_POINT) {
        p->x = obj->value.fields[0].value.d;
        p->y = obj->value.fields[1].value.d;
    }
    else {
        p->x = 0.0;
        p->y = 0.0;
    }
}

static void mock_writeback_point(void * source_obj, void * c_data_ptr, const infix_type * type) {
    (void)type;
    MockObject * obj = (MockObject *)source_obj;
    Point * p = (Point *)c_data_ptr;
    if (obj && obj->type == MOCK_TYPE_POINT) {
        obj->value.fields[0].value.d = p->x;
        obj->value.fields[1].value.d = p->y;
    }
}

static void mock_writeback_int64(void * source_obj, void * c_data_ptr, const infix_type * type) {
    (void)type;
    MockObject * obj = (MockObject *)source_obj;
    if (obj) {
        obj->type = MOCK_TYPE_INT;
        obj->value.i = *(int64_t *)c_data_ptr;
    }
}
static void mock_marshaller_line(void * source_obj, void * dest_buffer, const infix_type * type) {
    (void)type;
    MockObject * obj = (MockObject *)source_obj;
    Line * l = (Line *)dest_buffer;
    if (obj && obj->type == MOCK_TYPE_LINE) {
        // Manually marshal nested structs
        mock_marshaller_point(&obj->value.fields[0], &l->start, NULL);
        mock_marshaller_point(&obj->value.fields[1], &l->end, NULL);
    }
}

static infix_direct_value_t mock_marshaller_func_ptr(void * source_obj) {
    MockObject * obj = (MockObject *)source_obj;
    infix_direct_value_t val;
    val.ptr = (obj && obj->type == MOCK_TYPE_FUNC) ? obj->value.func_ptr : NULL;
    return val;
}

static int mock_c_callback(int a) { return a * a; }

TEST {
    plan(9);

    infix_registry_t * reg = infix_registry_create();
    ok(infix_register_types(reg,
                            "@Point = { x: double, y: double };"
                            "@Line = { start: @Point, end: @Point };"
                            "@Empty = {};"
                            "@IntFunc = (int)->int;") == INFIX_SUCCESS,
       "Successfully registered all test types");

    subtest("Test struct-by-value with add_points") {
        plan(4);

        infix_direct_arg_handler_t handlers[3] = {{.aggregate_marshaller = &mock_marshaller_point},
                                                  {.aggregate_marshaller = &mock_marshaller_point},
                                                  {.scalar_marshaller = &mock_marshaller_int}};

        infix_forward_t * trampoline = NULL;
        infix_status status = infix_forward_create_direct(
            &trampoline, "(@Point, @Point, int) -> @Point", (void *)&add_points, handlers, reg);

        ok(status == INFIX_SUCCESS, "Created direct trampoline for add_points");
        if (status != INFIX_SUCCESS) {
            diag("infix error: %s", infix_get_last_error().message);
            return;
        }

        infix_direct_cif_func cif = infix_forward_get_direct_code(trampoline);
        ok(cif != NULL, "Got direct CIF function pointer");

        MockObject p1_fields[] = {{.type = MOCK_TYPE_DOUBLE, .value.d = 10.0},
                                  {.type = MOCK_TYPE_DOUBLE, .value.d = 20.0}};
        MockObject p2_fields[] = {{.type = MOCK_TYPE_DOUBLE, .value.d = 5.0},
                                  {.type = MOCK_TYPE_DOUBLE, .value.d = -5.0}};
        MockObject mock_p1 = {.type = MOCK_TYPE_POINT, .value.fields = p1_fields};
        MockObject mock_p2 = {.type = MOCK_TYPE_POINT, .value.fields = p2_fields};
        MockObject mock_int = {.type = MOCK_TYPE_INT, .value.i = 2};

        void * lang_args[] = {&mock_p1, &mock_p2, &mock_int};
        Point result;

        cif(&result, lang_args);
        ok(result.x == 17.0, "Result x is correct (10 + 5 + 2)");
        ok(result.y == 17.0, "Result y is correct (20 + -5 + 2)");

        infix_forward_destroy(trampoline);
    };

    subtest("Test in-out pointer with move_point") {
        plan(4);

        infix_direct_arg_handler_t handlers[3] = {
            {.aggregate_marshaller = &mock_marshaller_point, .writeback_handler = &mock_writeback_point},
            {.scalar_marshaller = &mock_marshaller_int},
            {.scalar_marshaller = &mock_marshaller_int}};

        infix_forward_t * trampoline = NULL;
        infix_status status = infix_forward_create_direct(
            &trampoline, "(*@Point, int32, int32) -> void", (void *)&move_point, handlers, reg);

        ok(status == INFIX_SUCCESS, "Created direct trampoline for move_point");
        if (status != INFIX_SUCCESS) {
            diag("infix error: %s", infix_get_last_error().message);
            return;
        }

        infix_direct_cif_func cif = infix_forward_get_direct_code(trampoline);
        ok(cif != NULL, "Got direct CIF function pointer");

        MockObject p_fields[] = {{.type = MOCK_TYPE_DOUBLE, .value.d = 100.0},
                                 {.type = MOCK_TYPE_DOUBLE, .value.d = 200.0}};
        MockObject mock_p = {.type = MOCK_TYPE_POINT, .value.fields = p_fields};
        MockObject mock_dx = {.type = MOCK_TYPE_INT, .value.i = 50};
        MockObject mock_dy = {.type = MOCK_TYPE_INT, .value.i = -75};

        void * lang_args[] = {&mock_p, &mock_dx, &mock_dy};
        cif(NULL, lang_args);

        ok(mock_p.value.fields[0].value.d == 150.0, "In-out object x was written back correctly");
        ok(mock_p.value.fields[1].value.d == 125.0, "In-out object y was written back correctly");

        infix_forward_destroy(trampoline);
    };

    subtest("Test mixed types and stack arguments") {
        plan(3);
        const char * sig = "(double, int, float, int, double, int, float) -> double";

        infix_direct_arg_handler_t handlers[7] = {
            {.scalar_marshaller = &mock_marshaller_double},
            {.scalar_marshaller = &mock_marshaller_int},
            {.scalar_marshaller = &mock_marshaller_double},  // float is passed as double
            {.scalar_marshaller = &mock_marshaller_int},
            {.scalar_marshaller = &mock_marshaller_double},
            {.scalar_marshaller = &mock_marshaller_int},
            {.scalar_marshaller = &mock_marshaller_double}};

        infix_forward_t * trampoline = NULL;
        infix_status status = infix_forward_create_direct(&trampoline, sig, (void *)&sum_mixed_types, handlers, reg);
        ok(status == INFIX_SUCCESS, "Created direct trampoline for sum_mixed_types");
        if (status != INFIX_SUCCESS) {
            diag("Infix error: %s", infix_get_last_error().message);
            return;
        }

        infix_direct_cif_func cif = infix_forward_get_direct_code(trampoline);
        ok(cif != NULL, "Got CIF pointer for sum_mixed_types");

        MockObject args_data[] = {{.type = MOCK_TYPE_DOUBLE, .value.d = 1.5},
                                  {.type = MOCK_TYPE_INT, .value.i = 2},
                                  {.type = MOCK_TYPE_FLOAT, .value.d = 3.5},
                                  {.type = MOCK_TYPE_INT, .value.i = 4},
                                  {.type = MOCK_TYPE_DOUBLE, .value.d = 5.5},
                                  {.type = MOCK_TYPE_INT, .value.i = 6},
                                  {.type = MOCK_TYPE_FLOAT, .value.d = 7.5}};
        void * lang_args[] = {
            &args_data[0], &args_data[1], &args_data[2], &args_data[3], &args_data[4], &args_data[5], &args_data[6]};
        double result;

        cif(&result, lang_args);

        double expected = 1.5 + 2 + 3.5 + 4 + 5.5 + 6 + 7.5;
        ok(result == expected,
           "Correctly summed mixed register and stack arguments (got %f, want %f)",
           result,
           expected);

        infix_forward_destroy(trampoline);
    };

    subtest("Test C strings and pointer out-parameters") {
        plan(4);
        const char * sig = "(*char, *sint64) -> *char";

        infix_direct_arg_handler_t handlers[2] = {
            {.scalar_marshaller = &mock_marshaller_string},
            {.scalar_marshaller = NULL, .aggregate_marshaller = NULL, .writeback_handler = &mock_writeback_int64}};

        infix_forward_t * trampoline = NULL;
        infix_status status = infix_forward_create_direct(&trampoline, sig, (void *)&check_string, handlers, reg);
        ok(status == INFIX_SUCCESS, "Created direct trampoline for check_string");
        if (status != INFIX_SUCCESS) {
            diag("Infix error: %s", infix_get_last_error().message);
            return;
        }

        infix_direct_cif_func cif = infix_forward_get_direct_code(trampoline);
        ok(cif != NULL, "Got CIF pointer for check_string");

        MockObject mock_str = {.type = MOCK_TYPE_STRING, .value.s = "Hello, FFI!"};
        MockObject mock_out_len = {.type = MOCK_TYPE_INT, .value.i = 0};  // Will be written back to.

        void * lang_args[] = {&mock_str, &mock_out_len};
        const char * result_str = NULL;

        cif(&result_str, lang_args);

        ok(strcmp(result_str, "Hello, FFI!") == 0, "Correctly passed and returned C string");
        ok(mock_out_len.value.i == 11,
           "Correctly wrote back length via out-parameter (got %lld)",
           (long long)mock_out_len.value.i);

        infix_forward_destroy(trampoline);
    };
    subtest("Test various small integer types") {
        plan(2);
        const char * sig = "(uchar, short, uint, longlong) -> longlong";
        infix_direct_arg_handler_t handlers[4] = {{.scalar_marshaller = &mock_marshaller_int},
                                                  {.scalar_marshaller = &mock_marshaller_int},
                                                  {.scalar_marshaller = &mock_marshaller_int},
                                                  {.scalar_marshaller = &mock_marshaller_int}};

        infix_forward_t * trampoline = NULL;
        infix_status status = infix_forward_create_direct(&trampoline, sig, (void *)&sum_small_ints, handlers, reg);
        ok(status == INFIX_SUCCESS, "Created trampoline for sum_small_ints");

        MockObject args_data[] = {
            {.type = MOCK_TYPE_INT, .value.i = 200},     // uchar
            {.type = MOCK_TYPE_INT, .value.i = -1000},   // short
            {.type = MOCK_TYPE_INT, .value.i = 50000},   // uint
            {.type = MOCK_TYPE_INT, .value.i = 1000000}  // long long
        };
        void * lang_args[] = {&args_data[0], &args_data[1], &args_data[2], &args_data[3]};
        int64_t result;

        infix_direct_cif_func cif = infix_forward_get_direct_code(trampoline);
        cif(&result, lang_args);

        int64_t expected = 200 + (-1000) + 50000 + 1000000;
        ok(result == expected, "Correctly summed small integer types (got %lld)", (long long)result);
        infix_forward_destroy(trampoline);
    };

    subtest("Test nested structs") {
        plan(2);
        const char * sig = "(@Line) -> double";
        infix_direct_arg_handler_t handlers[1] = {{.aggregate_marshaller = &mock_marshaller_line}};

        infix_forward_t * trampoline = NULL;
        infix_status status = infix_forward_create_direct(&trampoline, sig, (void *)&get_line_length, handlers, reg);
        ok(status == INFIX_SUCCESS, "Created trampoline for get_line_length with nested struct");

        MockObject start_fields[] = {{.type = MOCK_TYPE_DOUBLE, .value.d = 1.0},
                                     {.type = MOCK_TYPE_DOUBLE, .value.d = 1.0}};
        MockObject end_fields[] = {{.type = MOCK_TYPE_DOUBLE, .value.d = 4.0},
                                   {.type = MOCK_TYPE_DOUBLE, .value.d = 5.0}};
        MockObject mock_start = {.type = MOCK_TYPE_POINT, .value.fields = start_fields};
        MockObject mock_end = {.type = MOCK_TYPE_POINT, .value.fields = end_fields};
        MockObject line_fields[] = {mock_start, mock_end};
        MockObject mock_line = {.type = MOCK_TYPE_LINE, .value.fields = line_fields};

        void * lang_args[] = {&mock_line};
        double result;

        infix_direct_cif_func cif = infix_forward_get_direct_code(trampoline);
        cif(&result, lang_args);

        // dx=3, dy=4. (3*3) + (4*4) = 9 + 16 = 25.
        ok(result == 25.0, "Correctly calculated with nested struct (got %f)", result);
        infix_forward_destroy(trampoline);
    };

    subtest("Test empty structs") {
        plan(2);
        const char * sig = "(@Empty, int) -> int";
        infix_direct_arg_handler_t handlers[2] = {
            {.aggregate_marshaller = NULL},  // No marshaller needed for empty struct
            {.scalar_marshaller = &mock_marshaller_int}};

        infix_forward_t * trampoline = NULL;
        infix_status status = infix_forward_create_direct(&trampoline, sig, (void *)&takes_empty_struct, handlers, reg);
        ok(status == INFIX_SUCCESS, "Created trampoline for takes_empty_struct");

        MockObject mock_empty = {0};
        MockObject mock_tag = {.type = MOCK_TYPE_INT, .value.i = 21};
        void * lang_args[] = {&mock_empty, &mock_tag};
        int result;

        infix_direct_cif_func cif = infix_forward_get_direct_code(trampoline);
        cif(&result, lang_args);

        ok(result == 42, "Correctly handled empty struct argument (got %d)", result);
        infix_forward_destroy(trampoline);
    };

    subtest("Test function pointer arguments") {
        plan(2);
        const char * sig = "(@IntFunc, int) -> int";
        infix_direct_arg_handler_t handlers[2] = {{.scalar_marshaller = &mock_marshaller_func_ptr},
                                                  {.scalar_marshaller = &mock_marshaller_int}};

        infix_forward_t * trampoline = NULL;
        infix_status status = infix_forward_create_direct(&trampoline, sig, (void *)&execute_callback, handlers, reg);
        ok(status == INFIX_SUCCESS, "Created trampoline for execute_callback");

        MockObject mock_func = {.type = MOCK_TYPE_FUNC, .value.func_ptr = (void *)&mock_c_callback};
        MockObject mock_val = {.type = MOCK_TYPE_INT, .value.i = 9};
        void * lang_args[] = {&mock_func, &mock_val};
        int result;

        infix_direct_cif_func cif = infix_forward_get_direct_code(trampoline);
        cif(&result, lang_args);

        ok(result == 81, "Correctly passed and executed function pointer (9*9)");
        infix_forward_destroy(trampoline);
    };

    infix_registry_destroy(reg);
    done();
}
