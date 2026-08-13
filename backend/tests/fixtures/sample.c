/*
 * Benign test fixture for Binary Graph Analyzer.
 *
 * Its only purpose is to produce a small PE with a predictable call graph:
 *
 *     main -> calculate -> multiply
 *                       -> add
 *     main -> printf   (imported API)
 *
 * There is deliberately NO malicious behaviour here - no networking, no
 * process manipulation, no filesystem writes, no persistence. Do not add any.
 *
 * Compile (either toolchain produces a usable PE):
 *
 *   MinGW-w64:
 *     gcc -O0 -o sample.exe sample.c
 *
 *   Visual Studio (from a "Developer Command Prompt"):
 *     cl /Od /Fe:sample.exe sample.c
 *
 * Then run the integration test:
 *     set BGA_TEST_PE=<path to sample.exe>
 *     pytest tests/test_integration_angr.py -v
 */

#include <stdio.h>

int add(int a, int b) {
    return a + b;
}

int multiply(int a, int b) {
    return a * b;
}

int calculate(int value) {
    if (value > 10) {
        return multiply(value, 2);
    }

    return add(value, 5);
}

int main(void) {
    int result = calculate(12);
    printf("%d\n", result);
    return 0;
}
