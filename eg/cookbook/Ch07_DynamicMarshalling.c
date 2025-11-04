/**
 * @file Ch07_DynamicMarshalling.c
 * @brief Cookbook Chapter 7: Dynamic Struct Marshalling
 *
 * This example demonstrates a powerful use of the introspection API: dynamically
 * packing data from an arbitrary source into a C-compatible struct layout at
 * runtime. This is a core task for any language binding or data serialization layer.
 *
 * The `infix_type_from_signature` function is used to parse a signature string
 * into a detailed `infix_type` graph. This graph contains all the `size`,
 * `alignment`, and member `offset` information needed to correctly write data
 * into a C-compatible memory buffer.
 */
#include <infix/infix.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// The target C struct we want to populate dynamically.
typedef struct {
    int32_t user_id;
    double score;
    const char * name;
} UserProfile;

/**
 * @brief A generic marshalling function that packs data into a struct.
 * @param dest A pointer to the destination C struct buffer.
 * @param sig The `infix` signature of the destination struct.
 * @param src An array of `void*` pointers, where each pointer points to the
 *            source data for the corresponding member, in order.
 */
static void marshal_ordered_data(void * dest, const char * sig, void ** src) {
    // 1. Parse the signature to get the struct's layout information.
    infix_type * type = NULL;
    infix_arena_t * arena = NULL;
    if (infix_type_from_signature(&type, &arena, sig, NULL) != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to parse signature for marshalling.\n");
        return;
    }

    if (infix_type_get_category(type) != INFIX_TYPE_STRUCT) {
        fprintf(stderr, "Signature is not a struct.\n");
        infix_arena_destroy(arena);
        return;
    }

    printf("Marshalling data into struct of size %zu, alignment %zu.\n",
           infix_type_get_size(type),
           infix_type_get_alignment(type));

    // 2. Iterate through the struct's members.
    for (size_t i = 0; i < infix_type_get_member_count(type); ++i) {
        const infix_struct_member * member = infix_type_get_member(type, i);

        // 3. Use the `offset` and `size` from the introspected type to
        //    copy the data into the correct location in the destination buffer.
        printf("  - Writing member '%s' (size %zu) to offset %zu\n",
               member->name,
               infix_type_get_size(member->type),
               member->offset);

        memcpy((char *)dest + member->offset, src[i], infix_type_get_size(member->type));
    }

    infix_arena_destroy(arena);
}

int main() {
    printf("--- Cookbook Chapter 7: Dynamic Struct Marshalling ---\n");

    // Our source data, coming from some dynamic source.
    int32_t id = 123;
    double score = 98.6;
    const char * name = "Sanko";
    void * my_data[] = {&id, &score, &name};

    // The signature of the target struct. Note the named fields.
    const char * profile_sig = "{id:int32, score:double, name:*char}";

    // The destination C struct buffer, initially zeroed.
    UserProfile profile_buffer = {0};

    // Marshal the data.
    marshal_ordered_data(&profile_buffer, profile_sig, my_data);

    printf("\nResulting C struct contents:\n");
    printf("  user_id: %d (Expected: 123)\n", profile_buffer.user_id);
    printf("  score:   %.1f (Expected: 98.6)\n", profile_buffer.score);
    printf("  name:    \"%s\" (Expected: \"Sanko\")\n", profile_buffer.name);

    return 0;
}
