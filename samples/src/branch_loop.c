/*
 * BENIGN TEST FIXTURE - branch_loop.c  ->  03_branch_loop.exe
 *
 * Deliberately dense control flow: nested loops, a big switch, and short-circuit
 * conditionals. The point is to produce a function whose CFG has many basic
 * blocks and every edge kind the viewer can label (TRUE / FALSE / JUMP /
 * FALLTHROUGH / loop back-edges). No suspicious behaviour - pure computation.
 */

#include <stdio.h>

#pragma comment(lib, "kernel32.lib")

/* A classifier with many branches so the switch lowers to a jump table or a
   chain of compares - either way, lots of blocks. */
static int classify(int n) {
    switch (n % 7) {
        case 0: return n * 2;
        case 1: return n + 3;
        case 2: return (n > 100) ? n - 50 : n + 50;
        case 3: return n ^ 0x5a;
        case 4: return (n & 1) ? n / 3 : n / 2;
        case 5: return n << 1;
        default: return n - 1;
    }
}

/* Nested loops with early continue/break, giving back-edges and multiple exits. */
static long crunch(int rounds) {
    long acc = 0;
    for (int i = 0; i < rounds; ++i) {
        for (int j = 0; j < rounds; ++j) {
            if ((i ^ j) == 0) {
                continue;
            }
            int c = classify(i * j);
            if (c < 0) {
                acc -= c;
                if (acc > 1000000L) {
                    break; /* bounded so the program always terminates */
                }
            } else {
                acc += (c & 0x3ff);
            }
        }
        if (i > 3 && (acc % 13) == 0) {
            acc += classify(i);
        }
    }
    return acc;
}

int main(int argc, char **argv) {
    int rounds = 20 + (argc & 7); /* runtime-derived, small and bounded */
    long total = 0;
    for (int k = 0; k < rounds; ++k) {
        total += crunch(k);
        total ^= (total << 1) | 1;
    }
    printf("branch_loop total=%ld rounds=%d\n", total, rounds);
    return (int)(total & 0x7f);
}
