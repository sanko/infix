#include <stdbool.h>
#include <stdio.h>

#if defined(_MSC_VER)
#include <intrin.h>
#elif defined(__GNUC__) || defined(__clang__)
#include <cpuid.h>
#endif

// A standalone function to check for AVX2 using CPUID
static bool check_avx2(void) {
#if defined(_MSC_VER)
    int cpuInfo[4];
    __cpuidex(cpuInfo, 7, 0);
    return (cpuInfo[1] & (1 << 5)) != 0;
#elif defined(__GNUC__) || defined(__clang__)
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid_max(0, NULL) >= 7) {
        __cpuid_count(7, 0, eax, ebx, ecx, edx);
        return (ebx & (1 << 5)) != 0;
    }
    return false;
#else
    return false;
#endif
}

// A standalone function to check for AVX-512F using CPUID
static bool check_avx512f(void) {
#if defined(_MSC_VER)
    int cpuInfo[4];
    __cpuidex(cpuInfo, 7, 0);
    return (cpuInfo[1] & (1 << 16)) != 0;
#elif defined(__GNUC__) || defined(__clang__)
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid_max(0, NULL) >= 7) {
        __cpuid_count(7, 0, eax, ebx, ecx, edx);
        return (ebx & (1 << 16)) != 0;
    }
    return false;
#else
    return false;
#endif
}

int main(void) {
    printf("Checking CPU features...\n");
    printf("AVX2 Supported:      %s\n", check_avx2() ? "Yes" : "No");
    printf("AVX-512F Supported:  %s\n", check_avx512f() ? "Yes" : "No");
    return 0;
}
