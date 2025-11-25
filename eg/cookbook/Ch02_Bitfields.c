/**
 * @file Ch02_Bitfields.c
 * @brief Cookbook Chapter 2: Working with Structs that Contain Bitfields
 *
 * This example demonstrates how to interface with C structs that use bitfields
 * (e.g., `uint8_t flags : 3`) to pack data tightly.
 */
#include <infix/infix.h>
#include <stdint.h>
#include <stdio.h>

// A packed struct with bitfields (simulating a hardware register or network flag byte)
// Note: We use uint8_t base types to ensure consistent byte-aligned packing for this example.
#pragma pack(push, 1)
typedef struct {
    uint8_t enable : 1;   // 1 bit
    uint8_t mode : 3;     // 3 bits
    uint8_t error : 2;    // 2 bits
    uint8_t padding : 2;  // 2 bits (pad to 8)
} StatusRegister;
#pragma pack(pop)

// The native C function we want to call.
void print_status(StatusRegister reg) {
    printf("Status Register: [Enable: %d] [Mode: %d] [Error: %d]\n", reg.enable, reg.mode, reg.error);
}

int main() {
    printf("--- Cookbook Chapter 2: Working with Bitfields ---\n");

    // Signature syntax: "name : type : width"
    // We use !{} for packed struct to match the C definition.
    const char * status_sig =
        "(!{"
        "  enable : uint8 : 1,"
        "  mode   : uint8 : 3,"
        "  error  : uint8 : 2,"
        "  pad    : uint8 : 2"
        "}) -> void";

    infix_forward_t * t_status = NULL;
    infix_forward_create(&t_status, status_sig, (void *)print_status, NULL);

    // Manually construct the bitfield value in a raw byte container.
    // Target: Enable=1, Mode=5 (101), Error=0.
    // Binary layout (assuming LSB first packing):
    // Bits: [ 7 6 | 5 4 | 3 2 1 | 0 ]
    // Data: [ 0 0 | 0 0 | 1 0 1 | 1 ] = 00001011 = 0x0B

    uint8_t raw_byte = 0;
    raw_byte |= (1 & 0x1);       // Enable (bit 0)
    raw_byte |= (5 & 0x7) << 1;  // Mode   (bits 1-3)
    raw_byte |= (0 & 0x3) << 4;  // Error  (bits 4-5)

    // Pass the raw data. The JIT handles the width logic during layout,
    // but since it packs into a single byte here, we pass the pointer to that byte.
    void * args[] = {&raw_byte};

    infix_cif_func cif_status = infix_forward_get_code(t_status);
    cif_status(NULL, args);

    infix_forward_destroy(t_status);

    return 0;
}
