/*
 * BENIGN TEST FIXTURE - strings_fixture.c  ->  07_strings_sysinternals.exe
 *
 * A "strings" test fixture. Its data segment is packed with benign but
 * suspicious-LOOKING string literals - exactly the patterns the string-based
 * risk scorer and the string extractor look for. The program never acts on any
 * of them; it just keeps them referenced so the linker cannot discard them, and
 * prints one chosen by argc.
 *
 * NOTE: this is NOT the Sysinternals `strings` utility (which is not installed
 * and is not downloaded by this project - a malware-analysis tool must not fetch
 * external binaries). It is a synthetic fixture named to match that slot. All
 * strings below point at invalid/example hosts and fictional paths.
 */

#include <stdio.h>

#pragma comment(lib, "kernel32.lib")

/* Patterns the risk scorer weights (all inert, all fictional). */
static const char *const g_indicators[] = {
    "http://example.invalid/gate.php",
    "https://cdn.example.invalid/stage2.bin",
    "cmd.exe /c whoami > %TEMP%\\o.txt",
    "powershell -nop -w hidden -enc AAAABBBBCCCC",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "\\\\.\\PhysicalDrive0",
    "http://abcdefabcdef1234.onion/checkin",
    "SELECT * FROM logins",           /* looks like credential theft, does nothing */
    "-----BEGIN PUBLIC KEY-----",
    "User-Agent: Mozilla/5.0 (Fixture)",
    "%APPDATA%\\Fixture\\config.dat",
    "schtasks /create /tn Fixture /tr calc.exe",
    "wmic process call create",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAA==",  /* fake base64 blob */
    "192.0.2.10:4444",                /* TEST-NET-1 address, non-routable */
    "This is a benign static-analysis test fixture. It performs no actions.",
};

static const wchar_t *const g_wide_indicators[] = {
    L"https://telemetry.example.invalid/report",
    L"\\Device\\PhysicalMemory",
    L"C:\\Windows\\Temp\\fixture.log",
};

int main(int argc, char **argv) {
    int total = (int)(sizeof(g_indicators) / sizeof(g_indicators[0]));
    int wtotal = (int)(sizeof(g_wide_indicators) / sizeof(g_wide_indicators[0]));

    /* Pick one by argc so nothing is constant-folded away, and so every entry
       stays referenced (and therefore present in the binary). */
    int pick = argc % total;
    int wpick = argc % wtotal;

    printf("strings fixture: %d ascii, %d wide indicators\n", total, wtotal);
    printf("sample[%d] = %s\n", pick, g_indicators[pick]);
    printf("wsample[%d] = %ls\n", wpick, g_wide_indicators[wpick]);

    /* Keep the rest reachable so the optimiser retains them. */
    long checksum = 0;
    for (int i = 0; i < total; ++i) {
        checksum += g_indicators[i][0];
    }
    return (int)(checksum & 0x7f);
}
