/*
 * BENIGN TEST FIXTURE - imports.c  ->  04_imports.exe
 *
 * Purpose: exercise the import extractor, the API graph and the API-based risk
 * scorer by pulling a broad, "malware-looking" set of Win32 APIs into the import
 * table across several capability buckets:
 *
 *     filesystem      CreateFileW / ReadFile / WriteFile
 *     memory          VirtualAlloc / VirtualProtect / LoadLibraryW / GetProcAddress
 *     persistence     RegOpenKeyExW / RegSetValueExW  (registry Run-key territory)
 *     anti_analysis   IsDebuggerPresent / CheckRemoteDebuggerPresent
 *     discovery       CreateToolhelp32Snapshot / Process32NextW
 *     crypto          CryptAcquireContextW / CryptEncrypt
 *     network         InternetOpenW / InternetOpenUrlW
 *
 * IMPORTANT - this program is INERT. Every genuinely side-effectful or
 * dangerous call is placed behind `if (argc > 100000)`, a branch that never
 * runs in practice but that the optimiser cannot fold away (argc is a runtime
 * value), so the APIs stay in the import table for STATIC analysis while nothing
 * ever executes. Where a call would still touch something, it targets only this
 * process / a read-only handle. No injection, no network traffic, no registry
 * writes, no persistence are ever performed.
 */

#include <windows.h>
#include <wininet.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <stdio.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wininet.lib")

/* Touch filesystem + memory APIs. Reads only; allocations are on self. */
static void filesystem_and_memory(int guard) {
    /* Benign, real: allocate and protect our own memory, then free it. */
    void *mem = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (mem) {
        DWORD old = 0;
        VirtualProtect(mem, 0x1000, PAGE_READONLY, &old);
        VirtualFree(mem, 0, MEM_RELEASE);
    }

    HMODULE k32 = LoadLibraryW(L"kernel32.dll");
    if (k32) {
        /* Reference-only: resolve a pointer we never invoke. */
        FARPROC p = GetProcAddress(k32, "GetSystemDirectoryW");
        (void)p;
    }

    if (guard > 100000) { /* never taken */
        HANDLE h = CreateFileW(L"nul", GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            char buf[16];
            DWORD n = 0;
            ReadFile(h, buf, sizeof(buf), &n, NULL);
            WriteFile(h, buf, n, &n, NULL);
            CloseHandle(h);
        }
    }
}

/* Reference persistence + discovery + crypto APIs; the writes never run. */
static void persistence_discovery_crypto(int guard) {
    HKEY key = NULL;
    /* Open (read) is harmless; the value write below is guarded off. */
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
                      L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_READ, &key) == ERROR_SUCCESS) {
        if (guard > 100000) { /* never taken: no persistence is written */
            const wchar_t *v = L"C:\\benign\\fixture.exe";
            RegSetValueExW(key, L"FixtureOnly", 0, REG_SZ,
                           (const BYTE *)v, (DWORD)((wcslen(v) + 1) * sizeof(wchar_t)));
        }
        RegCloseKey(key);
    }

    if (guard > 100000) { /* never taken */
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(pe);
            Process32NextW(snap, &pe);
            CloseHandle(snap);
        }
    }

    HCRYPTPROV prov = 0;
    if (CryptAcquireContextW(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (guard > 100000) { /* never taken */
            BYTE block[16] = {0};
            DWORD len = 0;
            CryptEncrypt(0, 0, TRUE, 0, block, &len, sizeof(block));
        }
        CryptReleaseContext(prov, 0);
    }
}

/* Reference network APIs. No handle is ever opened to a URL. */
static void network(int guard) {
    if (guard > 100000) { /* never taken: no network traffic occurs */
        HINTERNET net = InternetOpenW(L"fixture/1.0", INTERNET_OPEN_TYPE_DIRECT,
                                      NULL, NULL, 0);
        if (net) {
            HINTERNET url = InternetOpenUrlW(net, L"http://example.invalid/beacon",
                                             NULL, 0, INTERNET_FLAG_NO_UI, 0);
            if (url) {
                InternetCloseHandle(url);
            }
            InternetCloseHandle(net);
        }
    }
}

/* Anti-analysis checks are benign to call - they only read our own state. */
static int anti_analysis(void) {
    BOOL remote = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);
    return (IsDebuggerPresent() ? 1 : 0) | (remote ? 2 : 0);
}

int main(int argc, char **argv) {
    int flags = anti_analysis();
    filesystem_and_memory(argc);
    persistence_discovery_crypto(argc);
    network(argc);
    printf("imports fixture flags=%d argc=%d argv0=%s\n", flags, argc, argv[0]);
    return flags;
}
