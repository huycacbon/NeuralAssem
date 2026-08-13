/*
 * BENIGN TEST FIXTURE - simple.c
 *
 * Built twice, into 01_simple_debug.exe (/Od) and 02_simple_release.exe (/O2),
 * so you can compare how optimisation reshapes the recovered CFG for the same
 * source. There is no malicious behaviour here at all - it is arithmetic and a
 * printf. It exists to give the analyzer a tiny, predictable call graph:
 *
 *     main -> calculate -> { add, multiply }
 *     main -> printf
 */

#include <stdio.h>

#pragma comment(lib, "kernel32.lib")

static int add(int a, int b) {
    return a + b;
}

static int multiply(int a, int b) {
    return a * b;
}

static int calculate(int value) {
    if (value > 10) {
        return multiply(value, 2);
    }
    return add(value, 5);
}

int main(int argc, char **argv) {
    int seed = argc; /* runtime value so the optimiser cannot fold everything */
    int result = calculate(seed + 11);
    printf("simple fixture result=%d argv0=%s\n", result, argv[0]);
    return result & 0x7f;
}
