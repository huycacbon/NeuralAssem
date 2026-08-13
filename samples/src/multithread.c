/*
 * BENIGN TEST FIXTURE - multithread.c  ->  05_multithread.exe
 *
 * Two things to exercise here:
 *
 *  1. Real, benign multithreading: spawn worker threads with CreateThread that
 *     do arithmetic into a shared counter guarded by InterlockedIncrement and a
 *     mutex, then WaitForMultipleObjects. This gives the call graph several
 *     thread-related APIs and a fan-out/fan-in shape.
 *
 *  2. The classic process-injection API trio - VirtualAllocEx, WriteProcessMemory,
 *     CreateRemoteThread - is REFERENCED so it lands in the import table and the
 *     risk scorer flags it (process_injection capability, high score). It is
 *     INERT: the calls sit behind `if (argc > 100000)` (never taken) and, even
 *     there, target THIS process's own handle. Nothing is ever injected.
 */

#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "kernel32.lib")

static volatile LONG g_counter = 0;
static HANDLE g_mutex = NULL;

/* Worker: pure arithmetic, plus a mutex-protected update. Benign. */
static DWORD WINAPI worker(LPVOID param) {
    int id = (int)(INT_PTR)param;
    long local = 0;
    for (int i = 0; i < 100000; ++i) {
        local += (i ^ id) & 0xff;
    }

    if (g_mutex) {
        WaitForSingleObject(g_mutex, INFINITE);
        InterlockedIncrement(&g_counter);
        ReleaseMutex(g_mutex);
    } else {
        InterlockedIncrement(&g_counter);
    }
    return (DWORD)(local & 0x7fffffff);
}

/*
 * Injection-technique-LOOKING but inert. Guarded off, and self-targeted so even
 * if it somehow ran it would only poke this process's own memory.
 */
static void injection_shaped_but_inert(int guard) {
    if (guard <= 100000) {
        return; /* the real path: do nothing */
    }

    /* Unreachable in practice. Kept so the injection trio is imported and the
       risk scorer has something to flag for testing. Targets self only. */
    HANDLE self = GetCurrentProcess();
    SIZE_T size = 0x1000;
    void *remote = VirtualAllocEx(self, NULL, size, MEM_COMMIT | MEM_RESERVE,
                                  PAGE_EXECUTE_READWRITE);
    if (remote) {
        BYTE payload[8] = {0x90, 0x90, 0x90, 0x90, 0xC3, 0, 0, 0}; /* nops + ret */
        SIZE_T written = 0;
        WriteProcessMemory(self, remote, payload, sizeof(payload), &written);
        DWORD tid = 0;
        HANDLE th = CreateRemoteThread(self, NULL, 0,
                                       (LPTHREAD_START_ROUTINE)remote, NULL, 0, &tid);
        if (th) {
            WaitForSingleObject(th, 0);
            CloseHandle(th);
        }
        VirtualFreeEx(self, remote, 0, MEM_RELEASE);
    }
}

int main(int argc, char **argv) {
    g_mutex = CreateMutexW(NULL, FALSE, NULL);

    const int count = 4;
    HANDLE threads[4];
    for (int i = 0; i < count; ++i) {
        threads[i] = CreateThread(NULL, 0, worker, (LPVOID)(INT_PTR)i, 0, NULL);
    }
    WaitForMultipleObjects(count, threads, TRUE, INFINITE);
    for (int i = 0; i < count; ++i) {
        if (threads[i]) {
            CloseHandle(threads[i]);
        }
    }

    injection_shaped_but_inert(argc); /* never does anything */

    if (g_mutex) {
        CloseHandle(g_mutex);
    }
    printf("multithread fixture counter=%ld argv0=%s\n", (long)g_counter, argv[0]);
    return (int)g_counter;
}
