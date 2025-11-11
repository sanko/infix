/**
 * @file 302_aggregates.c
 * @brief Unit test for reverse trampolines (callbacks) with aggregate types.
 * @ingroup test_suite
 *
 * @details This test file verifies that `infix` can correctly create and execute
 * reverse trampolines for functions that take or return aggregate types (structs,
 * unions, etc.) by value. This is a critical test of the reverse-call JIT-compiler
 * and the ABI implementation's ability to correctly marshal arguments from their
 * native locations (registers/stack) into the generic format for the C handler.
 *
 * The test covers:
 * - **Small Structs:** A `Point` struct, which is typically passed in registers.
 *   Both the type-safe callback and generic closure models are tested.
 * - **Large Structs:** A `LargeStruct`, which is passed/returned by reference via
 *   a hidden pointer, testing the stub's ability to handle this ABI rule.
 * - **Structs with Arrays:** A `Vector4` struct, which may be an HFA on some platforms.
 * - **Unions:** A `Number` union, testing the handling of this aggregate type.
 * - **Packed Structs:** A `PackedStruct` with non-natural alignment, testing that
 *   the raw bytes are correctly marshalled regardless of internal layout.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include "types.h"
#include <infix/infix.h>
#include <math.h>
#include <string.h>
Point point_callback_handler(Point p) {
    note("point_callback_handler received p={%.1f, %.1f}", p.x, p.y);
    return (Point){p.x * 2.0, p.y * 2.0};
}
int large_struct_pass_handler(LargeStruct s) {
    note("large_struct_pass_handler received s.a=%d, s.f=%d", s.a, s.f);
    return s.a - s.f;
}
LargeStruct large_struct_return_handler(int a) {
    note("large_struct_return_handler called with a=%d", a);
    return (LargeStruct){a, a + 1, a + 2, a + 3, a + 4, a + 5};
}
int vector4_callback_handler(Vector4 v) { return (int)(v.v[0] + v.v[1] + v.v[2] + v.v[3]); }
Number number_union_return_handler(float f) {
    Number n;
    n.f = f * 10.0f;
    return n;
}
void point_closure_handler(infix_context_t * ctx, void * ret, void ** args) {
    (void)ctx;
    Point p = *(Point *)args[0];
    Point result = {p.x * 2.0, p.y * 2.0};
    memcpy(ret, &result, sizeof(Point));
}
void execute_point_callback(Point (*func_ptr)(Point), Point p) {
    Point result = func_ptr(p);
    ok(fabs(result.x - p.x * 2.0) < 0.001 && fabs(result.y - p.y * 2.0) < 0.001, "Callback returned correct Point");
}
void execute_large_struct_pass_callback(int (*func_ptr)(LargeStruct), LargeStruct s) {
    int result = func_ptr(s);
    ok(result == (s.a - s.f), "Callback returned correct int from LargeStruct");
}
void execute_large_struct_return_callback(LargeStruct (*func_ptr)(int), int a) {
    LargeStruct s = func_ptr(a);
    ok(s.a == a && s.b == a + 1 && s.f == a + 5, "Callback returned correct LargeStruct");
}
void execute_vector4_callback(int (*func_ptr)(Vector4), Vector4 v, int expected) {
    int result = func_ptr(v);
    ok(result == expected, "Callback returned correct sum from Vector4 (got %d, expected %d)", result, expected);
}
void execute_number_union_return_callback(Number (*func_ptr)(float), float f) {
    Number result = func_ptr(f);
    ok(fabs(result.f - (f * 10.0f)) < 0.001, "Callback returned correct Number union");
}
int process_packed_struct(PackedStruct p) {
    note("C target received PackedStruct with a='%c', b=%" PRIu64, p.a, p.b);
    if (p.a == 'X' && p.b == 0xDEADBEEFCAFEBABE)
        return 42;
    return -1;
}
TEST {
    plan(6);
    subtest("Callback with small struct: Point(Point)") {
        plan(5);
        infix_arena_t * arena = infix_arena_create(4096);
        infix_struct_member members[] = {
            infix_type_create_member("x", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), offsetof(Point, x)),
            infix_type_create_member("y", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), offsetof(Point, y))};
        infix_type * point_type = nullptr;
        if (!ok(infix_type_create_struct(arena, &point_type, members, 2) == INFIX_SUCCESS,
                "Point infix_type created")) {
            skip(4, "Test skipped");
            infix_arena_destroy(arena);
            return;
        }
        infix_reverse_t * rt_cb = nullptr;
        ok(infix_reverse_create_callback_manual(
               &rt_cb, point_type, &point_type, 1, 1, (void *)point_callback_handler) == INFIX_SUCCESS,
           "Type-safe callback created");
        if (rt_cb)
            execute_point_callback((Point(*)(Point))infix_reverse_get_code(rt_cb), (Point){10.0, -5.0});
        else
            skip(1, "Test skipped");
        infix_reverse_t * rt_cl = nullptr;
        ok(infix_reverse_create_closure_manual(&rt_cl, point_type, &point_type, 1, 1, point_closure_handler, nullptr) ==
               INFIX_SUCCESS,
           "Generic closure created");
        if (rt_cl)
            execute_point_callback((Point(*)(Point))infix_reverse_get_code(rt_cl), (Point){-2.0, 3.0});
        else
            skip(1, "Test skipped");
        infix_reverse_destroy(rt_cb);
        infix_reverse_destroy(rt_cl);
        infix_arena_destroy(arena);
    }
    subtest("Callback with large struct argument: int(LargeStruct)") {
        plan(2);
        infix_arena_t * arena = infix_arena_create(4096);
        infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
        infix_struct_member members[6];
        for (int i = 0; i < 6; ++i)
            members[i] =
                infix_type_create_member(nullptr, infix_type_create_primitive(INFIX_PRIMITIVE_SINT32), sizeof(int) * i);
        infix_type * large_struct_type = nullptr;
        if (infix_type_create_struct(arena, &large_struct_type, members, 6) != INFIX_SUCCESS) {
            fail("Failed to create LargeStruct type");
            skip(1, "Cannot proceed");
            infix_arena_destroy(arena);
            return;
        }
        infix_reverse_t * rt = nullptr;
        infix_status status = infix_reverse_create_callback_manual(
            &rt, ret_type, &large_struct_type, 1, 1, (void *)large_struct_pass_handler);
        ok(status == INFIX_SUCCESS, "Reverse trampoline created");
        if (rt)
            execute_large_struct_pass_callback((int (*)(LargeStruct))infix_reverse_get_code(rt),
                                               (LargeStruct){100, 0, 0, 0, 0, 25});
        else
            skip(1, "Test skipped");
        infix_reverse_destroy(rt);
        infix_arena_destroy(arena);
    }
    subtest("Callback returning large struct: LargeStruct(int)") {
        plan(2);
        infix_arena_t * arena = infix_arena_create(4096);
        infix_struct_member members[6];
        for (int i = 0; i < 6; ++i)
            members[i] =
                infix_type_create_member(nullptr, infix_type_create_primitive(INFIX_PRIMITIVE_SINT32), sizeof(int) * i);
        infix_type * large_struct_type = nullptr;
        if (infix_type_create_struct(arena, &large_struct_type, members, 6) != INFIX_SUCCESS) {
            fail("Failed to create LargeStruct type");
            skip(1, "Cannot proceed");
            infix_arena_destroy(arena);
            return;
        }
        infix_type * arg_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
        infix_reverse_t * rt = nullptr;
        infix_status status = infix_reverse_create_callback_manual(
            &rt, large_struct_type, &arg_type, 1, 1, (void *)large_struct_return_handler);
        ok(status == INFIX_SUCCESS, "Reverse trampoline created");
        if (rt)
            execute_large_struct_return_callback((LargeStruct(*)(int))infix_reverse_get_code(rt), 50);
        else
            skip(1, "Test skipped");
        infix_reverse_destroy(rt);
        infix_arena_destroy(arena);
    }
    subtest("Callback with struct containing array: int(Vector4)") {
        plan(3);
        infix_arena_t * arena = infix_arena_create(4096);
        infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
        infix_type * array_type = nullptr;
        if (infix_type_create_array(arena, &array_type, infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT), 4) !=
            INFIX_SUCCESS) {
            fail("Failed to create array type");
            skip(2, "Cannot proceed");
            infix_arena_destroy(arena);
            return;
        }
        infix_struct_member members[] = {infix_type_create_member("v", array_type, offsetof(Vector4, v))};
        infix_type * struct_type = nullptr;
        if (!ok(infix_type_create_struct(arena, &struct_type, members, 1) == INFIX_SUCCESS,
                "Vector4 infix_type created")) {
            skip(2, "Test skipped");
            infix_arena_destroy(arena);
            return;
        }
        infix_reverse_t * rt = nullptr;
        infix_status status =
            infix_reverse_create_callback_manual(&rt, ret_type, &struct_type, 1, 1, (void *)vector4_callback_handler);
        ok(status == INFIX_SUCCESS, "Reverse trampoline created");
        if (rt)
            execute_vector4_callback(
                (int (*)(Vector4))infix_reverse_get_code(rt), (Vector4){{4.0f, 6.0f, 8.0f, 12.0f}}, 30);
        else
            skip(1, "Test skipped");
        infix_reverse_destroy(rt);
        infix_arena_destroy(arena);
    }
    subtest("Callback returning union: Number(float)") {
        plan(2);
        infix_arena_t * arena = infix_arena_create(4096);
        infix_struct_member members[] = {
            infix_type_create_member("i", infix_type_create_primitive(INFIX_PRIMITIVE_SINT32), 0),
            infix_type_create_member("f", infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT), 0)};
        infix_type * union_type = nullptr;
        if (infix_type_create_union(arena, &union_type, members, 2) != INFIX_SUCCESS) {
            fail("Failed to create union type");
            skip(1, "Cannot proceed");
            infix_arena_destroy(arena);
            return;
        }
        infix_type * arg_type = infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT);
        infix_reverse_t * rt = nullptr;
        infix_status status =
            infix_reverse_create_callback_manual(&rt, union_type, &arg_type, 1, 1, (void *)number_union_return_handler);
        ok(status == INFIX_SUCCESS, "Reverse trampoline created");
        if (rt)
            execute_number_union_return_callback((Number(*)(float))infix_reverse_get_code(rt), 3.14f);
        else
            skip(1, "Test skipped");
        infix_reverse_destroy(rt);
        infix_arena_destroy(arena);
    }
    subtest("Packed struct") {
        plan(5);
        infix_arena_t * arena = infix_arena_create(4096);
        infix_struct_member * members =
            infix_arena_alloc(arena, 2 * sizeof(infix_struct_member), _Alignof(infix_struct_member));
        members[0] = infix_type_create_member(
            "a", infix_type_create_primitive(INFIX_PRIMITIVE_SINT8), offsetof(PackedStruct, a));
        members[1] = infix_type_create_member(
            "b", infix_type_create_primitive(INFIX_PRIMITIVE_UINT64), offsetof(PackedStruct, b));
        infix_type * packed_type = nullptr;
        infix_status status = infix_type_create_packed_struct(
            arena, &packed_type, sizeof(PackedStruct), _Alignof(PackedStruct), members, 2);
        if (!ok(status == INFIX_SUCCESS, "Packed struct infix_type created")) {
            skip(4, "Test skipped");
            infix_arena_destroy(arena);
            return;
        }
        ok(packed_type->size == 9, "Packed struct size should be 9 bytes.");
        ok(packed_type->alignment == 1, "Packed struct alignment should be 1 byte.");
        infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
        infix_forward_t * trampoline = nullptr;
        status = infix_forward_create_unbound_manual(&trampoline, ret_type, &packed_type, 1, 1);
        ok(status == INFIX_SUCCESS, "Successfully generated trampoline for packed struct.");
        infix_unbound_cif_func cif_func = infix_forward_get_unbound_code(trampoline);
        PackedStruct arg_struct = {'X', 0xDEADBEEFCAFEBABE};
        int result = 0;
        void * args[] = {&arg_struct};
        cif_func((void *)process_packed_struct, &result, args);
        ok(result == 42, "Packed struct was passed and processed correctly.");
        infix_forward_destroy(trampoline);
        infix_arena_destroy(arena);
    }
}
