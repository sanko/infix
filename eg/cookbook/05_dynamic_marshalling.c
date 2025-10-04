/**
 * @file 05_dynamic_marshalling.c
 * @brief Recipe: Dynamic Struct Marshalling with the Signature Parser.
 * @see
 * https://github.com/sanko/infix/blob/master/docs/cookbook.md#recipe-dynamic-struct-marshalling-with-the-signature-parser
 */
#include <infix/infix.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// The C struct we want to pack data into.
typedef struct {
    int32_t user_id;
    double score;
    const char * name;
} UserProfile;

// This function takes a destination buffer, a signature describing the layout,
// and an array of pointers to the source data. It dynamically packs the data
// into the buffer according to the layout described by the signature.
void marshal_ordered_data(void * dest_buffer, const char * signature, void ** source_values) {
    infix_type * struct_type = NULL;
    infix_arena_t * arena = NULL;

    // 1. Parse the signature to get the type layout information.
    if (infix_type_from_signature(&struct_type, &arena, signature) != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to parse signature.\n");
        return;
    }

    // 2. Zero the destination buffer for safety.
    memset(dest_buffer, 0, infix_type_get_size(struct_type));

    // 3. Iterate through the members described by the parsed type.
    for (size_t i = 0; i < infix_type_get_member_count(struct_type); ++i) {
        const infix_struct_member * member = infix_type_get_member(struct_type, i);
        printf("Marshalling member %zu ('%s') to offset %zu (size %zu)\n",
               i,
               member->name,
               member->offset,
               infix_type_get_size(member->type));

        // 4. Copy the source data to the correct offset in the destination buffer.
        memcpy((char *)dest_buffer + member->offset, source_values[i], infix_type_get_size(member->type));
    }

    // 5. Clean up the parser's temporary memory.
    infix_arena_destroy(arena);
}

int main() {
    // Our source data from some dynamic language or system.
    int32_t id_val = 123;
    double score_val = 98.6;
    const char * name_val = "Sanko";
    void * my_data[] = {&id_val, &score_val, &name_val};

    // A signature matching the UserProfile C struct, with named fields.
    const char * profile_sig = "{id:int32, score:double, name:*char}";

    // The destination C struct buffer.
    UserProfile profile_buffer;
    marshal_ordered_data(&profile_buffer, profile_sig, my_data);

    printf("\nResulting C struct:\n  user_id: %d\n  score:   %f\n  name:    %s\n",
           profile_buffer.user_id,
           profile_buffer.score,
           profile_buffer.name);

    // Verify offsets match what the compiler decided.
    if (offsetof(UserProfile, user_id) == 0 && offsetof(UserProfile, score) == 8 && offsetof(UserProfile, name) == 16)
        printf("Offsets match compiler layout.\n");
    else
        printf("Warning: Offsets do not match expected compiler layout.\n");

    return 0;
}
