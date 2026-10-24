#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN64
#define ADDR_FMT    "0x%llX"
#define ADDR_FMTW   "0x%016llX"
#define ADDR_CAST(x) (unsigned long long)(x)
#else
#define ADDR_FMT    "0x%08X"
#define ADDR_FMTW   "0x%08X"
#define ADDR_CAST(x) (unsigned)(x)
#endif

#define MAX_SECTIONS        32
#define POLL_INTERVAL_MS    50
#define MAX_MONITOR_SEC     300
#define FINGERPRINT_SIZE    64
#define MAX_STR_LEN         1024
#define MIN_STR_LEN         4
#define MAX_IMPORTS         65536
#define MAX_IAT_SLOTS       8192
#define OEP_SCAN_SIZE       4096

#define MAX_DYNAMIC_REGIONS      256
#define REGION_FP_SIZE           64
#define HARVEST_SNAP_INTERVAL    10
#define HARVEST_BEHAV_INTERVAL   40
#define HARVEST_REGION_THRESHOLD 3
#define HARVEST_SETTLE_MS        3000
#define PESIEVE_TIMEOUT_MS       60000

typedef struct {
    char    name[16];
    DWORD   rva;
    DWORD   vsize;
    DWORD   raw_size;
    DWORD   characteristics;
    BYTE    fingerprint[FINGERPRINT_SIZE];
    int     changed;
    int     was_zeroed;
    int     nz_bytes;
} SectionInfo;

typedef struct {
    char    module[128];
    char    function[256];
    DWORD64 resolved_addr;
} ImportEntry;

typedef struct {
    DWORD   slot_rva;
    int     import_idx;
} IATSlotEntry;

typedef struct {
    DWORD64   base_addr;
    SIZE_T    size;
    DWORD     protect;
    BYTE      fingerprint[REGION_FP_SIZE];
    int       snapshot_first;
    int       snapshot_last;
    int       fp_changed;
    int       dumped;
} DynamicRegion;

typedef struct {
    DynamicRegion regions[MAX_DYNAMIC_REGIONS];
    int           count;
    int           index;
    DWORD         tick_ms;
} RegionSnapshot;

typedef struct {
    RegionSnapshot current;
    RegionSnapshot previous;

    DynamicRegion  all_seen[MAX_DYNAMIC_REGIONS * 2];
    int            all_seen_count;

    int  new_this_cycle;
    int  disappeared;
    int  fp_changes;

    int  behavioral_trigger;
    int  new_file_count;

    char timeline[64][256];
    int  timeline_count;

    int  pesieve_ran;
    int  pesieve_exit_code;
    int  pesieve_file_count;
    char pesieve_path[MAX_PATH];
} HarvestState;

static SectionInfo  g_sections[MAX_SECTIONS];
static int          g_num_sections = 0;
static DWORD64      g_image_base = 0;
static DWORD        g_size_of_image = 0;
static WORD         g_machine = 0;
static char         g_output_dir[MAX_PATH] = ".";
static char         g_dll_export[256] = "";
static int          g_is_dll = 0;
static int          g_is_service_dll = 0;
static int          g_no_pause = 0;
static char         g_wait_for_process[MAX_PATH] = "";
static int          g_force_direct = 0;
static int          g_force_dropper = 0;
static int          g_dropper_timeout = 60;

static ImportEntry  g_imports[MAX_IMPORTS];
static volatile LONG g_import_count = 0;

static IATSlotEntry g_iat_slots[MAX_IAT_SLOTS];
static int          g_iat_slot_count = 0;

static DWORD        g_oep_rva = 0;
static int          g_oep_captured = 0;
static DWORD        g_oep_thread_rva = 0;
static DWORD        g_oep_crt_rva = 0;

static HarvestState g_harvest;
static int          g_harvest_enabled = 1;
#define MAX_WATCH_DIRS_FWD  16
static char     g_harvest_watch_dirs[MAX_WATCH_DIRS_FWD][MAX_PATH];
static int      g_harvest_watch_count = 0;

static BYTE g_gpa_orig[16];
static BYTE g_lla_orig[16];
static BYTE g_llw_orig[16];
static DWORD64 g_gpa_addr = 0;
static DWORD64 g_lla_addr = 0;
static DWORD64 g_llw_addr = 0;

#define PE32_MAGIC          0x10b
#define PE32PLUS_MAGIC      0x20b

#define ProcessBasicInformation     0
#define ProcessWow64Information     26

typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _MY_PROCESS_BASIC_INFORMATION {
    NTSTATUS  ExitStatus;
    PVOID     PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG      BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} MY_PROCESS_BASIC_INFORMATION;

typedef NTSTATUS (NTAPI *pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG  ProcessInformationClass,
    PVOID  ProcessInformation,
    ULONG  ProcessInformationLength,
    PULONG ReturnLength
);

static pfnNtQueryInformationProcess g_NtQueryInformationProcess = NULL;

static int detect_target_architecture_vmp(HANDLE hProcess, DWORD64 *out_image_base)
{
    SIZE_T nread;

    if (!g_NtQueryInformationProcess) {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll) {
            g_NtQueryInformationProcess = (pfnNtQueryInformationProcess)
                GetProcAddress(hNtdll, "NtQueryInformationProcess");
        }
    }
    if (!g_NtQueryInformationProcess) return 0;

#ifdef _WIN64
    ULONG_PTR wow64_peb = 0;
    g_NtQueryInformationProcess(hProcess, ProcessWow64Information,
                                &wow64_peb, sizeof(wow64_peb), NULL);

    if (wow64_peb != 0) {
        printf("[*] Target architecture: x86 (32-bit, WOW64)\n");

        DWORD base32 = 0;
        if (ReadProcessMemory(hProcess, (LPCVOID)(wow64_peb + 0x08),
                              &base32, sizeof(base32), &nread) && nread == 4) {
            *out_image_base = (DWORD64)base32;
            printf("[+] ImageBase: 0x%08X\n", base32);
            return 1;
        }

        BYTE probe[2];
        if (ReadProcessMemory(hProcess, (LPCVOID)(ULONG_PTR)0x400000,
                              probe, 2, &nread) && probe[0] == 'M' && probe[1] == 'Z') {
            *out_image_base = 0x400000;
            printf("[+] ImageBase (fallback): 0x00400000\n");
            return 1;
        }
        return 0;
    }

    printf("[*] Target architecture: x64 (64-bit, native)\n");

    MY_PROCESS_BASIC_INFORMATION pbi;
    memset(&pbi, 0, sizeof(pbi));
    NTSTATUS status = g_NtQueryInformationProcess(hProcess, ProcessBasicInformation,
                                                   &pbi, sizeof(pbi), NULL);

    if (NT_SUCCESS(status) && pbi.PebBaseAddress != NULL) {
        ULONG_PTR peb_addr = (ULONG_PTR)pbi.PebBaseAddress;
        ULONGLONG base64 = 0;
        if (ReadProcessMemory(hProcess, (LPCVOID)(peb_addr + 0x10),
                              &base64, sizeof(base64), &nread) && nread == 8) {
            *out_image_base = (DWORD64)base64;
            printf("[+] ImageBase: 0x%llX\n", (unsigned long long)base64);
            return 1;
        }
    }

    BYTE probe[2];
    if (ReadProcessMemory(hProcess, (LPCVOID)(ULONG_PTR)0x140000000ULL,
                          probe, 2, &nread) && probe[0] == 'M' && probe[1] == 'Z') {
        *out_image_base = 0x140000000ULL;
        printf("[+] ImageBase (fallback): 0x0000000140000000\n");
        return 1;
    }
    if (ReadProcessMemory(hProcess, (LPCVOID)(ULONG_PTR)0x400000,
                          probe, 2, &nread) && probe[0] == 'M' && probe[1] == 'Z') {
        *out_image_base = 0x400000;
        printf("[+] ImageBase (fallback): 0x00400000\n");
        return 1;
    }
    return 0;

#else
    printf("[*] Target architecture: x86 (32-bit)\n");

    MY_PROCESS_BASIC_INFORMATION pbi;
    memset(&pbi, 0, sizeof(pbi));
    NTSTATUS status = g_NtQueryInformationProcess(hProcess, ProcessBasicInformation,
                                                   &pbi, sizeof(pbi), NULL);

    if (NT_SUCCESS(status) && pbi.PebBaseAddress != NULL) {
        ULONG_PTR peb_addr = (ULONG_PTR)pbi.PebBaseAddress;
        DWORD base32 = 0;
        if (ReadProcessMemory(hProcess, (LPCVOID)(peb_addr + 0x08),
                              &base32, sizeof(base32), &nread) && nread == 4) {
            *out_image_base = (DWORD64)base32;
            printf("[+] ImageBase: 0x%08X\n", base32);
            return 1;
        }
    }

    BYTE probe[2];
    if (ReadProcessMemory(hProcess, (LPCVOID)(ULONG_PTR)0x400000,
                          probe, 2, &nread) && probe[0] == 'M' && probe[1] == 'Z') {
        *out_image_base = 0x400000;
        printf("[+] ImageBase (fallback): 0x00400000\n");
        return 1;
    }
    return 0;
#endif
}

static int is_btc_address(const char *s)
{
    int len = (int)strlen(s);
    if (len < 26 || len > 62) return 0;
    if (s[0] == '1' || s[0] == '3' || (s[0] == 'b' && s[1] == 'c' && s[2] == '1'))
        return 1;
    return 0;
}

static int is_onion_url(const char *s)
{
    return strstr(s, ".onion") != NULL;
}

static int is_url(const char *s)
{
    return strstr(s, "http://") != NULL || strstr(s, "https://") != NULL ||
           strstr(s, "t.me/") != NULL || strstr(s, "ftp://") != NULL;
}

static int is_email(const char *s)
{
    const char *at = strchr(s, '@');
    if (!at) return 0;
    return strchr(at, '.') != NULL;
}

static int is_extension(const char *s)
{
    if (s[0] != '.') return 0;
    int len = (int)strlen(s);
    if (len < 3 || len > 12) return 0;
    for (int i = 1; i < len; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')))
            return 0;
    }
    return 1;
}

static int is_ransom_indicator(const char *s)
{
    return strstr(s, "README") != NULL || strstr(s, "readme") != NULL ||
           strstr(s, "DECRYPT") != NULL || strstr(s, "decrypt") != NULL ||
           strstr(s, "RESTORE") != NULL || strstr(s, "restore") != NULL ||
           strstr(s, "RECOVER") != NULL || strstr(s, "recover") != NULL ||
           strstr(s, "RANSOM") != NULL || strstr(s, "ransom") != NULL ||
           strstr(s, "Your files") != NULL || strstr(s, "your files") != NULL ||
           strstr(s, "YOUR FILES") != NULL || strstr(s, "encrypted") != NULL ||
           strstr(s, "Bitcoin") != NULL || strstr(s, "bitcoin") != NULL ||
           strstr(s, "Telegram") != NULL || strstr(s, "telegram") != NULL ||
           strstr(s, "payment") != NULL || strstr(s, "wallet") != NULL;
}

static const char* categorize_string(const char *s)
{
    if (is_btc_address(s)) return "btc_wallet";
    if (is_onion_url(s)) return "onion_url";
    if (is_url(s)) return "url";
    if (is_email(s)) return "email";
    if (is_ransom_indicator(s)) return "ransom";
    if (is_extension(s)) return "extension";
    if (strstr(s, ":\\") || strstr(s, "C:\\") || strstr(s, "\\Windows")) return "path";
    if (strstr(s, ".exe") || strstr(s, ".dll") || strstr(s, ".sys")) return "file";
    if (strstr(s, "mutex") || strstr(s, "Mutex") || strstr(s, "Global\\")) return "mutex";
    if (strstr(s, "SELECT") || strstr(s, "FROM") || strstr(s, "Win32_")) return "wmi";
    if (strstr(s, "bcdedit") || strstr(s, "wbadmin") || strstr(s, "vssadmin") ||
        strstr(s, "wevtutil") || strstr(s, "powershell")) return "command";
    if (strstr(s, "HKEY_") || strstr(s, "SOFTWARE\\") || strstr(s, "CurrentVersion")) return "registry";
    return NULL;
}

static int read_pe_sections(HANDLE hProc, DWORD64 base)
{
    BYTE hdr[4096];
    SIZE_T nread;

    if (!ReadProcessMemory(hProc, (LPCVOID)base, hdr, sizeof(hdr), &nread) || nread < 256)
        return 0;

    if (hdr[0] != 'M' || hdr[1] != 'Z') return 0;

    DWORD pe_off = *(DWORD*)(hdr + 0x3C);
    if (pe_off + 256 > sizeof(hdr)) return 0;

    BYTE *pe = hdr + pe_off;
    if (*(DWORD*)pe != 0x00004550) return 0;

    WORD machine = *(WORD*)(pe + 4);
    WORD num_secs = *(WORD*)(pe + 6);
    WORD opt_size = *(WORD*)(pe + 20);
    BYTE *sec_tbl = pe + 24 + opt_size;

    g_machine = machine;

    if (machine == 0x8664) {
        g_size_of_image = *(DWORD*)(pe + 24 + 56);
    } else {
        g_size_of_image = *(DWORD*)(pe + 24 + 56);
    }

    printf("[*] Machine: 0x%04X (%s)\n", machine,
           machine == 0x8664 ? "AMD64" : machine == 0x14C ? "i386" : "unknown");

    if (num_secs > MAX_SECTIONS) num_secs = MAX_SECTIONS;
    g_num_sections = 0;

    int zeroed_count = 0;
    int packed_count = 0;

    printf("[*] Sections (%d):\n", num_secs);
    for (int i = 0; i < num_secs; i++) {
        BYTE *s = sec_tbl + i * 40;
        SectionInfo *si = &g_sections[g_num_sections];
        memset(si, 0, sizeof(*si));
        memcpy(si->name, s, 8);
        si->name[8] = '\0';
        si->vsize           = *(DWORD*)(s + 8);
        si->rva             = *(DWORD*)(s + 12);
        si->raw_size        = *(DWORD*)(s + 16);
        si->characteristics = *(DWORD*)(s + 36);
        si->changed  = 0;

        si->was_zeroed = (si->vsize > 0 && si->raw_size == 0) ? 1 : 0;
        if (si->was_zeroed) zeroed_count++;
        if (si->raw_size > 0 && si->vsize > 0x100000) packed_count++;

        memset(si->fingerprint, 0, FINGERPRINT_SIZE);
        if (si->vsize > 0) {
            ReadProcessMemory(hProc, (LPCVOID)(base + si->rva),
                             si->fingerprint, FINGERPRINT_SIZE, &nread);
        }

        char dname[16];
        strncpy(dname, si->name, 15); dname[15] = '\0';
        for (int j = (int)strlen(dname) - 1; j >= 0 && (unsigned char)dname[j] <= ' '; j--)
            dname[j] = '\0';
        if (dname[0] == '\0') sprintf(dname, "sec_%d", i);

        int nz = 0;
        for (int j = 0; j < FINGERPRINT_SIZE; j++)
            if (si->fingerprint[j] != 0) nz++;

        const char *tag = si->was_zeroed ? " [ZEROED]" : "";
        printf("    %-12s RVA=0x%08X VS=0x%08X RS=0x%08X fp_nz=%d%s\n",
               dname, si->rva, si->vsize, si->raw_size, nz, tag);
        g_num_sections++;
    }

    if (zeroed_count > 0) {
        printf("[*] VMProtect signature: %d sections with FileSize=0 (original code zeroed)\n",
               zeroed_count);
    }
    if (packed_count > 0) {
        printf("[*] VMProtect payload: %d large packed section(s) detected\n", packed_count);
    }

    return g_num_sections;
}

static int check_changes(HANDLE hProc, DWORD64 base)
{
    int total = 0;
    SIZE_T nread;
    for (int i = 0; i < g_num_sections; i++) {
        SectionInfo *si = &g_sections[i];
        if (si->changed || si->vsize == 0) continue;

        BYTE current[FINGERPRINT_SIZE];
        memset(current, 0, FINGERPRINT_SIZE);
        if (!ReadProcessMemory(hProc, (LPCVOID)(base + si->rva),
                              current, FINGERPRINT_SIZE, &nread))
            continue;

        if (memcmp(current, si->fingerprint, FINGERPRINT_SIZE) != 0) {
            si->changed = 1;
            total++;

            const char *what = si->was_zeroed ? "POPULATED" : "MODIFIED";
            printf("[!] %s: section '%s' at 0x%llX\n", what, si->name,
                   (unsigned long long)(base + si->rva));
            printf("    Before: %02X %02X %02X %02X %02X %02X %02X %02X\n",
                   si->fingerprint[0], si->fingerprint[1], si->fingerprint[2], si->fingerprint[3],
                   si->fingerprint[4], si->fingerprint[5], si->fingerprint[6], si->fingerprint[7]);
            printf("    After:  %02X %02X %02X %02X %02X %02X %02X %02X\n",
                   current[0], current[1], current[2], current[3],
                   current[4], current[5], current[6], current[7]);
        }
    }
    return total;
}

#define OEP_MAX_SCAN  (256 * 1024)

static DWORD scan_crt_pattern(HANDLE hProc, DWORD64 base)
{
    SIZE_T nread;
    DWORD pass1 = 0, pass2 = 0, pass3 = 0, pass4 = 0;

    for (int i = 0; i < g_num_sections; i++) {
        SectionInfo *si = &g_sections[i];

        if (!si->was_zeroed || !si->changed) continue;

        if (!(si->characteristics & 0x20000000)) continue;
        if (si->vsize == 0) continue;

        DWORD scan_len = si->vsize;
        if (scan_len > OEP_MAX_SCAN) scan_len = OEP_MAX_SCAN;

        BYTE *buf = (BYTE*)malloc(scan_len);
        if (!buf) continue;
        memset(buf, 0, scan_len);
        if (!ReadProcessMemory(hProc, (LPCVOID)(base + si->rva),
                              buf, scan_len, &nread) || nread < 16) {
            free(buf);
            continue;
        }

        for (DWORD off = 0; off + 16 <= scan_len; off++) {

            if (g_machine == 0x8664) {

                if (pass3 == 0 &&
                    buf[off] == 0x48 && buf[off+1] == 0x83 &&
                    buf[off+2] == 0xEC && buf[off+3] == 0x28) {
                    for (DWORD j = 4; j < 20 && off + j < scan_len; j++) {
                        if (buf[off + j] == 0xE8) {
                            pass3 = si->rva + off;
                            printf("[+] CRT scan: x64 sub rsp,28h + call at RVA=0x%08lX\n",
                                   (unsigned long)pass3);
                            break;
                        }
                    }
                }
            } else {

                if (pass1 == 0 && off + 13 <= scan_len &&
                    buf[off]   == 0x6A && buf[off+1] == 0xFF &&
                    buf[off+2] == 0x68 &&
                    buf[off+7] == 0x64 && buf[off+8] == 0xA1 &&
                    buf[off+9] == 0x00 && buf[off+10] == 0x00 &&
                    buf[off+11] == 0x00 && buf[off+12] == 0x00) {
                    pass1 = si->rva + off;
                    printf("[+] CRT scan: SEH setup (6A FF 68 .. 64 A1) at RVA=0x%08lX\n",
                           (unsigned long)pass1);
                }

                if (pass2 == 0 && off + 10 <= scan_len &&
                    (off & 0xFFF) == 0 &&
                    buf[off] == 0xE8 && buf[off+5] == 0xE9) {
                    pass2 = si->rva + off;
                    printf("[+] CRT scan: call+jmp (security_init_cookie) at RVA=0x%08lX\n",
                           (unsigned long)pass2);
                }

                if (pass2 == 0 && off + 10 <= scan_len &&
                    buf[off] == 0xE8 && buf[off+5] == 0xE9) {

                    INT32 call_rel = *(INT32*)(buf + off + 1);
                    DWORD call_target = si->rva + off + 5 + call_rel;
                    if (call_target >= si->rva && call_target < si->rva + si->vsize) {
                        pass2 = si->rva + off;
                        printf("[+] CRT scan: call+jmp trampoline at RVA=0x%08lX\n",
                               (unsigned long)pass2);
                    }
                }

                if (pass4 == 0 && off == 0 && off + 6 <= scan_len &&
                    buf[0] == 0x55 && buf[1] == 0x8B && buf[2] == 0xEC &&
                    (buf[3] == 0x83 || buf[3] == 0x81) && buf[4] == 0xEC) {
                    pass4 = si->rva;
                    printf("[+] CRT scan: push ebp prologue at section start RVA=0x%08lX\n",
                           (unsigned long)pass4);
                }
            }
        }
        free(buf);

        if (pass1 != 0) break;
    }

    if (pass1 != 0) {
        printf("[+] OEP selected: SEH setup (pass 1) RVA=0x%08lX\n", (unsigned long)pass1);
        return pass1;
    }
    if (pass2 != 0) {
        printf("[+] OEP selected: cookie trampoline (pass 2) RVA=0x%08lX\n", (unsigned long)pass2);
        return pass2;
    }
    if (pass3 != 0) {
        printf("[+] OEP selected: x64 CRT (pass 3) RVA=0x%08lX\n", (unsigned long)pass3);
        return pass3;
    }
    if (pass4 != 0) {
        printf("[+] OEP selected: section-start prologue (pass 4) RVA=0x%08lX\n", (unsigned long)pass4);
        return pass4;
    }
    printf("[!] No CRT pattern found in any unpacked section\n");
    return 0;
}

static void capture_oep(HANDLE hProc, HANDLE hThread, DWORD64 base, DWORD soi)
{
    DWORD thread_rva = 0;
    DWORD crt_rva = 0;

    printf("\n[*] Capturing OEP...\n");

    if (hThread) {
        CONTEXT ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_CONTROL;
        if (GetThreadContext(hThread, &ctx)) {
            DWORD64 ip;
#ifdef _WIN64
            ip = ctx.Rip;
#else
            ip = ctx.Eip;
#endif
            if (ip >= base && ip < base + soi) {
                thread_rva = (DWORD)(ip - base);
                printf("[+] Thread IP at suspend: RVA=0x%08X (VA=0x%llX)\n",
                       thread_rva, (unsigned long long)ip);
            } else {
                printf("[!] Thread IP 0x%llX is outside image range\n",
                       (unsigned long long)ip);
            }
        } else {
            printf("[!] GetThreadContext failed (error %u)\n", (unsigned)GetLastError());
        }
    }

    crt_rva = scan_crt_pattern(hProc, base);

    g_oep_thread_rva = thread_rva;
    g_oep_crt_rva = crt_rva;

    if (crt_rva != 0) {
        g_oep_rva = crt_rva;
        g_oep_captured = 1;
        if (thread_rva != 0) {
            int delta = (int)thread_rva - (int)crt_rva;
            if (delta < 0) delta = -delta;
            printf("[+] OEP selected: CRT pattern RVA=0x%08X (thread IP delta=%d bytes)\n",
                   g_oep_rva, delta);
        } else {
            printf("[+] OEP selected: CRT pattern RVA=0x%08X\n", g_oep_rva);
        }
    } else if (thread_rva != 0) {
        g_oep_rva = thread_rva;
        g_oep_captured = 1;
        printf("[+] OEP selected: thread IP RVA=0x%08X (no CRT pattern found)\n", g_oep_rva);
    } else {
        g_oep_rva = 0;
        g_oep_captured = 0;
        printf("[!] OEP not captured (no thread IP, no CRT pattern)\n");
    }
}

static int dump_section(HANDLE hProc, DWORD64 base, SectionInfo *si, int idx)
{
    if (si->vsize == 0) return 0;

    char sname[16];
    strncpy(sname, si->name, 15); sname[15] = '\0';
    for (int i = 0; sname[i]; i++) {
        char c = sname[i];
        if (c == '.' || c == '/' || c == '\\' || c == ':' || c == '*' ||
            c == '?' || c == '<' || c == '>' || c == '|' || (unsigned char)c <= ' ' ||
            c == '~' || c == '[' || c == ',')
            sname[i] = '_';
    }
    if (sname[0] == '\0') sprintf(sname, "sec%d", idx);

    char fname[MAX_PATH];
    snprintf(fname, sizeof(fname), "%s\\%s_0x%llX.bin",
             g_output_dir, sname, (unsigned long long)(base + si->rva));

    DWORD dump_size = si->vsize;
    if (dump_size > 32 * 1024 * 1024) dump_size = 32 * 1024 * 1024;

    BYTE *buf = (BYTE*)malloc(dump_size);
    if (!buf) return 0;
    memset(buf, 0, dump_size);

    SIZE_T nread;
    DWORD chunk = 0x10000;
    for (DWORD off = 0; off < dump_size; off += chunk) {
        DWORD sz = (dump_size - off < chunk) ? (dump_size - off) : chunk;
        ReadProcessMemory(hProc, (LPCVOID)(base + si->rva + off),
                         buf + off, sz, &nread);
    }

    int nz = 0;
    DWORD check = (dump_size < 4096) ? dump_size : 4096;
    for (DWORD j = 0; j < check; j++)
        if (buf[j] != 0 && buf[j] != 0xFF && buf[j] != 0xCC) nz++;

    FILE *f = fopen(fname, "wb");
    if (!f) { free(buf); return 0; }
    fwrite(buf, 1, dump_size, f);
    fclose(f);

    si->nz_bytes = nz;
    const char *status = (nz > 50) ? "content" : (nz > 0) ? "sparse" : "empty";
    printf("[+] %-12s %8u bytes -> %s  [%s, nz=%d]\n",
           si->name, dump_size, fname, status, nz);
    free(buf);
    return 1;
}

static void dump_full_image(HANDLE hProc, DWORD64 base, const char *target_name)
{
    BYTE hdr[4096];
    SIZE_T nr;
    if (!ReadProcessMemory(hProc, (LPCVOID)base, hdr, sizeof(hdr), &nr) || nr < 256)
        return;

    DWORD pe_off = *(DWORD*)(hdr + 0x3C);
    WORD machine = *(WORD*)(hdr + pe_off + 4);
    DWORD soi;

    if (machine == 0x8664) {
        soi = *(DWORD*)(hdr + pe_off + 24 + 56);
    } else {
        soi = *(DWORD*)(hdr + pe_off + 24 + 56);
    }

    if (soi == 0 || soi > 128 * 1024 * 1024) {
        printf("[-] SizeOfImage invalid: 0x%X\n", soi);
        return;
    }

    g_size_of_image = soi;

    const char *bname = strrchr(target_name, '\\');
    if (!bname) bname = strrchr(target_name, '/');
    if (bname) bname++; else bname = target_name;

    BYTE *buf = (BYTE*)malloc(soi);
    if (!buf) return;
    memset(buf, 0, soi);

    DWORD chunk = 0x10000;
    for (DWORD off = 0; off < soi; off += chunk) {
        DWORD sz = (soi - off < chunk) ? (soi - off) : chunk;
        ReadProcessMemory(hProc, (LPCVOID)(base + off), buf + off, sz, &nr);
    }

    pe_off = *(DWORD*)(buf + 0x3C);
    if (pe_off + 256 < soi) {
        BYTE *pe = buf + pe_off;

        if (machine == 0x8664) {
            *(DWORD64*)(pe + 24 + 24) = base;
        } else {
            *(DWORD*)(pe + 24 + 28) = (DWORD)base;
        }

        WORD ns = *(WORD*)(pe + 6);
        WORD os = *(WORD*)(pe + 20);
        BYTE *st = pe + 24 + os;

        for (int i = 0; i < ns && i < MAX_SECTIONS; i++) {
            BYTE *s = st + i * 40;
            DWORD vs  = *(DWORD*)(s + 8);
            DWORD rva = *(DWORD*)(s + 12);
            *(DWORD*)(s + 16) = vs;
            *(DWORD*)(s + 20) = rva;
        }

        printf("\n[*] Repairing PE headers...\n");

        DWORD orig_ep = *(DWORD*)(pe + 24 + 16);
        if (g_oep_rva != 0 && g_oep_rva != orig_ep) {
            *(DWORD*)(pe + 24 + 16) = g_oep_rva;
            printf("[+] EntryPoint fixed: 0x%08X -> 0x%08X (OEP)\n", orig_ep, g_oep_rva);
        } else if (g_oep_rva == 0) {
            printf("[!] OEP not captured, EntryPoint unchanged: 0x%08X\n", orig_ep);
        }

        DWORD sec_align  = *(DWORD*)(pe + 24 + 32);
        DWORD file_align = *(DWORD*)(pe + 24 + 36);
        if (file_align != sec_align) {
            *(DWORD*)(pe + 24 + 36) = sec_align;
            printf("[+] FileAlignment fixed: 0x%X -> 0x%X (self-mapping)\n",
                   file_align, sec_align);
        }

        DWORD soh = *(DWORD*)(pe + 24 + 60);
        DWORD aligned_soh = (soh + sec_align - 1) & ~(sec_align - 1);
        if (aligned_soh != soh) {
            *(DWORD*)(pe + 24 + 60) = aligned_soh;
            printf("[+] SizeOfHeaders fixed: 0x%X -> 0x%X\n", soh, aligned_soh);
        }

        *(DWORD*)(pe + 24 + 64) = 0;

        int has_reloc = 0;
        for (int i = 0; i < ns && i < MAX_SECTIONS; i++) {
            BYTE *s = st + i * 40;
            if (strncmp((char*)s, ".reloc", 6) == 0 && *(DWORD*)(s + 8) > 0) {
                has_reloc = 1;
                break;
            }
        }
        if (!has_reloc) {
            WORD chars = *(WORD*)(pe + 22);
            if (!(chars & 0x0001)) {
                *(WORD*)(pe + 22) = chars | 0x0001;
                printf("[+] No .reloc section -- RELOCS_STRIPPED set, base pinned at 0x%llX\n",
                       (unsigned long long)base);
            }
            int reloc_dd_off = (machine == 0x8664) ? (24 + 152) : (24 + 136);
            *(DWORD*)(pe + reloc_dd_off) = 0;
            *(DWORD*)(pe + reloc_dd_off + 4) = 0;
        }

        int dllchars_off = (machine == 0x8664) ? (24 + 70) : (24 + 70);
        WORD dllchars = *(WORD*)(pe + dllchars_off);
        if (dllchars & 0x0040) {
            *(WORD*)(pe + dllchars_off) = dllchars & ~0x0040;
            printf("[+] ASLR (DYNAMIC_BASE) disabled for fixed-base execution\n");
        }

        printf("[+] PE repair complete\n");
    }

    char fname[MAX_PATH];
    snprintf(fname, sizeof(fname), "%s\\%s_dumped.bin", g_output_dir, bname);
    FILE *f = fopen(fname, "wb");
    if (f) { fwrite(buf, 1, soi, f); fclose(f); }
    printf("[+] Full PE dump: %s (%u bytes, %.1f MB)\n", fname, soi, soi / (1024.0 * 1024.0));
    free(buf);
}

static void log_import(const char *module, const char *function, DWORD64 addr)
{
    LONG idx = InterlockedIncrement(&g_import_count) - 1;
    if (idx >= MAX_IMPORTS) return;

    ImportEntry *e = &g_imports[idx];
    strncpy(e->module, module, sizeof(e->module) - 1);
    e->module[sizeof(e->module) - 1] = '\0';
    strncpy(e->function, function, sizeof(e->function) - 1);
    e->function[sizeof(e->function) - 1] = '\0';
    e->resolved_addr = addr;
}

static void reconstruct_iat(HANDLE hProc, DWORD64 base);
static const char* get_basename(const char *path);

#include <ctype.h>
#ifndef QWORD
typedef unsigned long long QWORD;
#endif

#define HOOK_RING_MAX       8192
#define HOOK_ENTRY_SIZE     32
#define HOOK_HDR_SIZE       0x100
#define HOOK_RING_OFF       0x100
#define HOOK_RING_BYTES     (HOOK_RING_MAX * HOOK_ENTRY_SIZE)
#define HOOK_TRAMP_OFF      (HOOK_RING_OFF + HOOK_RING_BYTES)       
#define HOOK_TRAMP_SIZE     256
#define HOOK_BODY_OFF       (HOOK_TRAMP_OFF + 3 * HOOK_TRAMP_SIZE)  
#define HOOK_BODY_SIZE      256
#define HOOK_SLOTS_OFF      (HOOK_BODY_OFF + 3 * HOOK_BODY_SIZE)    
#define HOOK_PARAM_OFF      (HOOK_SLOTS_OFF + 64)                   
#define HOOK_STUB_OFF       (HOOK_PARAM_OFF + 128)                  
#define HOOK_TOTAL_SIZE     (HOOK_STUB_OFF + 256)

#define HOOK_TAG_GPA 0
#define HOOK_TAG_LLA 1
#define HOOK_TAG_LLW 2

static int   g_no_hook = 0;
static int   g_no_antidebug = 0;
static DWORD64 g_hook_cave = 0;
static DWORD64 g_hook_gpa_addr = 0;
static DWORD64 g_hook_lla_addr = 0;
static DWORD64 g_hook_llw_addr = 0;
static int   g_hook_installed_count = 0;
static char  g_target_image_name[128] = "";

typedef struct {
    char dll[64];
    char func[256];
    WORD hint;
} OrigImport;

#define MAX_ORIG_IMPORTS 16384
static OrigImport g_orig_imports[MAX_ORIG_IMPORTS];
static int        g_orig_import_count = 0;

typedef struct {
    DWORD64 slot_rva;
    DWORD64 resolved_addr;
    char    module[64];
    char    function[256];
    int     status;
} VidFixEntry;

#define MAX_VID_FIXES 8192
static VidFixEntry g_vid_fixes[MAX_VID_FIXES];
static int         g_vid_fix_count = 0;

static int lde64_len(const BYTE *p, int max_len);
static int lde32_len(const BYTE *p, int max_len);
static int patch_iat_slots_for_hooks(HANDLE hProc);
static void launch_remote_patch_stub(HANDLE hProc, DWORD64 cave_remote,
                                     DWORD64 gpa, DWORD64 lla, DWORD64 llw,
                                     DWORD64 hook_gpa, DWORD64 hook_lla,
                                     DWORD64 hook_llw);

static int is_wine_host(void)
{
    HMODULE hN = GetModuleHandleA("ntdll.dll");
    if (!hN) return 0;
    return GetProcAddress(hN, "wine_get_version") != NULL;
}
static void launch_remote_patch_stub(HANDLE hProc, DWORD64 cave_remote,
                                     DWORD64 gpa, DWORD64 lla, DWORD64 llw,
                                     DWORD64 hook_gpa, DWORD64 hook_lla,
                                     DWORD64 hook_llw);

static int lde_sib_extra64(BYTE modrm, BYTE sib)
{
    BYTE mod = modrm >> 6;
    BYTE rm  = modrm & 7;
    int extra = 0;

    if (mod == 3) return 0;
    if (rm == 4) {
        BYTE base = sib & 7;
        extra += 1;                        
        if (mod == 0 && base == 5) extra += 4;
    } else {
        if (mod == 0 && rm == 5) extra += 4;
    }
    if (mod == 1) extra += 1;
    else if (mod == 2) extra += 4;
    return extra;
}

static int lde_modrm_extra64(BYTE modrm)
{
    BYTE mod = (BYTE)(modrm >> 6);
    BYTE rm  = (BYTE)(modrm & 7);
    int len = 0;
    if (mod != 3 && rm == 4) len += 1;
    if (mod == 1) len += 1;
    else if (mod == 2) len += 4;
    else if (mod == 0 && rm == 5) len += 4;
    return len;
}

static int lde_modrm_extra32(BYTE modrm, int addr16)
{
    BYTE mod = (BYTE)(modrm >> 6);
    BYTE rm  = (BYTE)(modrm & 7);
    int len = 0;
    if (addr16) {
        if (mod == 0 && rm == 6) len += 2;
        else if (mod == 1) len += 1;
        else if (mod == 2) len += 2;
    } else {
        if (mod != 3 && rm == 4) len += 1;
        if (mod == 1) len += 1;
        else if (mod == 2) len += 4;
        else if (mod == 0 && rm == 5) len += 4;
    }
    return len;
}

static int lde64_len(const BYTE *p, int max_len)
{
    int n = 0;
    BYTE rex = 0;
    int opsz16 = 0;

    int f2f3 = 0;
    for (;;) {
        BYTE b;
        if (n >= max_len) return -1;
        b = p[n];
        if (b == 0x66) { opsz16 = 1; n++; continue; }
        if (b == 0x67 || b == 0x2E || b == 0x3E || b == 0x26 ||
            b == 0x36 || b == 0x64 || b == 0x65) { n++; continue; }
        if (b == 0xF2 || b == 0xF3) { f2f3 = 1; n++; continue; }
        if (b == 0xF0) { n++; continue; }
        if ((b & 0xF0) == 0x40) { rex = b; n++; continue; }
        break;
    }
    if (n >= max_len) return -1;

    BYTE op = p[n];

    if (op == 0x0F) {
        if (n + 1 >= max_len) return -1;
        BYTE op2 = p[n + 1];
        if (op2 == 0x1E && f2f3) return n + 3;    
        if (op2 == 0x38) {
            if (n + 2 >= max_len) return -1;
            return n + 4 + lde_sib_extra64(p[n + 2], p[n + 3]);
        }
        if (op2 == 0x3A) {
            if (n + 2 >= max_len) return -1;
            return n + 4 + lde_sib_extra64(p[n + 2], p[n + 3]) + 1;
        }
        if (op2 >= 0x80 && op2 <= 0x8F) return n + 2 + 4;
        if (op2 == 0x0B || op2 == 0x05 || op2 == 0x06 || op2 == 0x07 ||
            op2 == 0x08 || op2 == 0x09 || op2 == 0x0A || op2 == 0x30 ||
            op2 == 0x31 || op2 == 0x32 || op2 == 0x33 || op2 == 0x34 ||
            op2 == 0x35 || op2 == 0x77 || op2 == 0xA0 || op2 == 0xA1 ||
            op2 == 0xA2 || op2 == 0xA8 || op2 == 0xA9 || op2 == 0xAA)
            return n + 2;
        if (op2 == 0xA4 || op2 == 0xAC || op2 == 0xBA || op2 == 0xC2 ||
            op2 == 0xC4 || op2 == 0xC6)
            return n + 3 + lde_sib_extra64(p[n + 2], p[n + 3]) + 1;
        return n + 3 + lde_sib_extra64(p[n + 2], p[n + 3]);
    }

    switch (op) {
    case 0xE8: case 0xE9:
        return n + 1 + 4;
    case 0xEB:
        return n + 1 + 1;
    case 0x70: case 0x71: case 0x72: case 0x73:
    case 0x74: case 0x75: case 0x76: case 0x77:
    case 0x78: case 0x79: case 0x7A: case 0x7B:
    case 0x7C: case 0x7D: case 0x7E: case 0x7F:    
        return n + 2;
    case 0x68:
        return n + 1 + (opsz16 ? 2 : 4);
    case 0x6A:
        return n + 1 + 1;
    case 0xA8:
        return n + 1 + 1;
    case 0xA9:
        return n + 1 + (opsz16 ? 2 : 4);
    case 0xA0: case 0xA1: case 0xA2: case 0xA3:
        return -1;
    case 0xC2: case 0xCA:
        return n + 1 + 2;
    case 0xC8:
        return n + 1 + 3;
    case 0xCD:
        return n + 1 + 1;
    case 0x50: case 0x51: case 0x52: case 0x53:
    case 0x54: case 0x55: case 0x56: case 0x57:    
    case 0x58: case 0x59: case 0x5A: case 0x5B:
    case 0x5C: case 0x5D: case 0x5E: case 0x5F:    
    case 0x90:                                     
    case 0x98: case 0x99:                          
    case 0x9B:                                     
    case 0x9C: case 0x9D:                          
    case 0xF5:                                     
    case 0xF8: case 0xF9:                          
    case 0xFC: case 0xFD:                          
    case 0xC3:                                     
    case 0xC9:                                     
        return n + 1;
    case 0xB0: case 0xB1: case 0xB2: case 0xB3:
    case 0xB4: case 0xB5: case 0xB6: case 0xB7:
        return n + 1 + 1;
    case 0xB8: case 0xB9: case 0xBA: case 0xBB:
    case 0xBC: case 0xBD: case 0xBE: case 0xBF:
        if (rex & 0x08) return n + 1 + 8;
        return n + 1 + (opsz16 ? 2 : 4);
    case 0x80: case 0xC0: case 0xC1: case 0xC6: case 0x6B: case 0x83:
        if (n + 1 >= max_len) return -1;
        return n + 2 + 1 + lde_sib_extra64(p[n + 1], p[n + 2]);    
    case 0x81:
        if (n + 1 >= max_len) return -1;
        return n + 2 + (opsz16 ? 2 : 4) + lde_sib_extra64(p[n + 1], p[n + 2]);
    case 0x69:
        if (n + 1 >= max_len) return -1;
        return n + 2 + 4 + lde_sib_extra64(p[n + 1], p[n + 2]);
    case 0xC7:
        if (n + 1 >= max_len) return -1;
        return n + 2 + (opsz16 ? 2 : 4) + lde_sib_extra64(p[n + 1], p[n + 2]);
    case 0xF6:
        if (n + 1 >= max_len) return -1;
        {
            BYTE reg = (BYTE)((p[n + 1] >> 3) & 7);
            return n + 1 + 1 + lde_sib_extra64(p[n + 1], p[n + 2]) +
                   ((reg == 0 || reg == 1) ? 1 : 0);
        }
    case 0xF7:
        if (n + 1 >= max_len) return -1;
        {
            BYTE reg = (BYTE)((p[n + 1] >> 3) & 7);
            return n + 2 + (opsz16 ? 2 : 4) + lde_sib_extra64(p[n + 1], p[n + 2]) +
                   ((reg == 0 || reg == 1) ? (opsz16 ? 2 : 4) : 0);
        }
    default:
        break;
    }

    if (op <= 0x3F && (op & 0x07) == 0x04) return n + 2;    
    if (op <= 0x3F && (op & 0x07) == 0x05)
        return n + 1 + (opsz16 ? 2 : 4);                    

    if (op >= 0xD8 && op <= 0xDF) {
        if (n + 1 >= max_len) return -1;
        return n + 2 + lde_sib_extra64(p[n + 1], p[n + 2]);
    }

    if (op == 0xF4 || op == 0xF1 || op == 0xC4 || op == 0xC5 ||
        (op >= 0x06 && op <= 0x07) || (op >= 0x0E && op <= 0x0F) ||
        (op >= 0x16 && op <= 0x17) || (op >= 0x1E && op <= 0x1F) ||
        (op >= 0x27 && op <= 0x27) || (op >= 0x2F && op <= 0x2F) ||
        (op >= 0x37 && op <= 0x37) || (op >= 0x3F && op <= 0x3F) ||
        op == 0x60 || op == 0x61 || op == 0x62 || op == 0x82 ||
        op == 0xD4 || op == 0xD5 || op == 0xD6 || op == 0xD7 ||
        (op >= 0xE0 && op <= 0xE3) || (op >= 0xE4 && op <= 0xE7) ||
        (op >= 0xEA && op <= 0xEF))
        return -1;

    {
        static const BYTE modrm_ranges[][2] = {
            {0x00, 0x03}, {0x08, 0x0B}, {0x10, 0x13}, {0x18, 0x1B},
            {0x20, 0x23}, {0x28, 0x2B}, {0x30, 0x33}, {0x38, 0x3B},
            {0x63, 0x63}, {0x84, 0x8F}, {0xD0, 0xD3}, {0xFE, 0xFF}
        };
        int in_range = 0;
        for (int t = 0; t < (int)(sizeof(modrm_ranges) / sizeof(modrm_ranges[0])); t++) {
            if (op >= modrm_ranges[t][0] && op <= modrm_ranges[t][1]) { in_range = 1; break; }
        }
        if (in_range) {
            if (n + 1 >= max_len) return -1;
            return n + 2 + lde_sib_extra64(p[n + 1], p[n + 2]);
        }
    }

    return -1;
}

static int lde32_len(const BYTE *p, int max_len)
{
    int n = 0;
    int opsz16 = 0;
    int addr16 = 0;

    for (;;) {
        BYTE b;
        if (n >= max_len) return -1;
        b = p[n];
        if (b == 0x66) { opsz16 = 1; n++; continue; }
        if (b == 0x67) { addr16 = 1; n++; continue; }
        if (b == 0x2E || b == 0x3E || b == 0x26 || b == 0x36 ||
            b == 0x64 || b == 0x65 || b == 0xF2 || b == 0xF3 || b == 0xF0) { n++; continue; }
        break;
    }
    if (n >= max_len) return -1;

    BYTE op = p[n];

    switch (op) {
    case 0xE8: case 0xE9:
        return n + 1 + 4;
    case 0xEB:
        return n + 1 + 1;
    case 0x68:
        return n + 1 + (opsz16 ? 2 : 4);
    case 0x6A:
        return n + 1 + 1;
    case 0xA8:
        return n + 1 + 1;
    case 0xA9:
        return n + 1 + (opsz16 ? 2 : 4);
    case 0xC2: case 0xCA:
        return n + 1 + 2;
    case 0xC8:
        return n + 1 + 3;
    case 0xCD:
        return n + 1 + 1;
    case 0xB0: case 0xB1: case 0xB2: case 0xB3:
    case 0xB4: case 0xB5: case 0xB6: case 0xB7:
        return n + 1 + 1;
    case 0xB8: case 0xB9: case 0xBA: case 0xBB:
    case 0xBC: case 0xBD: case 0xBE: case 0xBF:
        return n + 1 + (opsz16 ? 2 : 4);
    case 0x80: case 0xC0: case 0xC1: case 0xC6: case 0x6B: case 0x83:
        if (n + 1 >= max_len) return -1;
        return n + 1 + 1 + lde_modrm_extra32(p[n + 1], addr16);
    case 0x81:
        if (n + 1 >= max_len) return -1;
        return n + 1 + (opsz16 ? 2 : 4) + lde_modrm_extra32(p[n + 1], addr16);
    case 0x69:
        if (n + 1 >= max_len) return -1;
        return n + 1 + 4 + lde_modrm_extra32(p[n + 1], addr16);
    case 0xC7:
        if (n + 1 >= max_len) return -1;
        return n + 1 + (opsz16 ? 2 : 4) + lde_modrm_extra32(p[n + 1], addr16);
    default:
        break;
    }

    {
        static const BYTE modrm_ranges[][2] = {
            {0x00, 0x03}, {0x08, 0x0B}, {0x10, 0x13}, {0x18, 0x1B},
            {0x20, 0x23}, {0x28, 0x2B}, {0x30, 0x33}, {0x38, 0x3B},
            {0x62, 0x63}, {0x69, 0x6F}, {0x84, 0x8F}, {0xD0, 0xD3},
            {0xD8, 0xDF}, {0xFE, 0xFF}
        };
        int in_range = 0;
        for (int t = 0; t < (int)(sizeof(modrm_ranges) / sizeof(modrm_ranges[0])); t++) {
            if (op >= modrm_ranges[t][0] && op <= modrm_ranges[t][1]) { in_range = 1; break; }
        }
        if (in_range) {
            if (n + 1 >= max_len) return -1;
            return n + 1 + lde_modrm_extra32(p[n + 1], addr16);
        }
        if (op >= 0x04 && op <= 0x05) return n + 1;
        if (op >= 0x0C && op <= 0x0D) return n + 1;
        if (op >= 0x14 && op <= 0x15) return n + 1;
        if (op >= 0x1C && op <= 0x1D) return n + 1;
        if (op >= 0x24 && op <= 0x25) return n + 1;
        if (op >= 0x2C && op <= 0x2D) return n + 1;
        if (op >= 0x34 && op <= 0x35) return n + 1;
        if (op >= 0x3C && op <= 0x3D) return n + 1;
        if (op == 0xA0 || op == 0xA1 || op == 0xA2 || op == 0xA3) {
            return n + 1 + (addr16 ? 2 : 4);
        }
        if (op >= 0x70 && op <= 0x7F) return n + 1 + 1;
        if (op >= 0x40 && op <= 0x5F) return n + 1;
        if (op >= 0x90 && op <= 0x9F) return n + 1;
        if (op >= 0xA4 && op <= 0xAF) return n + 1;
        if (op >= 0xF8 && op <= 0xFD) return n + 1;
        if (op == 0xF6) {
            if (n + 1 >= max_len) return -1;
            BYTE reg = (BYTE)((p[n + 1] >> 3) & 7);
            return n + 1 + 1 + lde_modrm_extra32(p[n + 1], addr16) +
                   ((reg == 0 || reg == 1) ? 1 : 0);
        }
        if (op == 0xF7) {
            if (n + 1 >= max_len) return -1;
            BYTE reg = (BYTE)((p[n + 1] >> 3) & 7);
            return n + 1 + (opsz16 ? 2 : 4) + lde_modrm_extra32(p[n + 1], addr16) +
                   ((reg == 0 || reg == 1) ? (opsz16 ? 2 : 4) : 0);
        }
    }

    return -1;
}

static DWORD64 hook_find_export_in_target(HANDLE hProc, DWORD64 mod_base,
                                          const char *func_name)
{
    BYTE hdr[4096];
    SIZE_T nread;

    if (!ReadProcessMemory(hProc, (LPCVOID)mod_base, hdr, sizeof(hdr), &nread) ||
        nread < 256)
        return 0;
    if (hdr[0] != 'M' || hdr[1] != 'Z') return 0;

    DWORD pe_off = *(DWORD*)(hdr + 0x3C);
    if (pe_off + 256 > sizeof(hdr)) return 0;
    BYTE *pe = hdr + pe_off;
    if (*(DWORD*)pe != 0x00004550) return 0;

    WORD machine = *(WORD*)(pe + 4);
    DWORD export_rva, export_size;
    if (machine == 0x8664) {
        export_rva  = *(DWORD*)(pe + 24 + 112);
        export_size = *(DWORD*)(pe + 24 + 116);
    } else {
        export_rva  = *(DWORD*)(pe + 24 + 96);
        export_size = *(DWORD*)(pe + 24 + 100);
    }
    if (export_rva == 0 || export_size == 0) return 0;

    BYTE *eb = (BYTE*)malloc(export_size);
    if (!eb) return 0;
    if (!ReadProcessMemory(hProc, (LPCVOID)(mod_base + export_rva), eb,
                           export_size, &nread)) {
        free(eb);
        return 0;
    }

    DWORD num_funcs = *(DWORD*)(eb + 20);
    DWORD num_names = *(DWORD*)(eb + 24);
    DWORD funcs_rva = *(DWORD*)(eb + 28);
    DWORD names_rva = *(DWORD*)(eb + 32);
    DWORD ords_rva  = *(DWORD*)(eb + 36);

    DWORD64 result = 0;
    if (num_names > 0 && num_names < 100000 &&
        funcs_rva >= export_rva && funcs_rva < export_rva + export_size &&
        names_rva >= export_rva && names_rva < export_rva + export_size &&
        ords_rva  >= export_rva && ords_rva  < export_rva + export_size)
    {
        DWORD *func_addrs = (DWORD*)(eb + (funcs_rva - export_rva));
        DWORD *name_ptrs  = (DWORD*)(eb + (names_rva - export_rva));
        WORD  *ordinals   = (WORD*) (eb + (ords_rva  - export_rva));

        for (DWORD i = 0; i < num_names; i++) {
            char name[256] = {0};
            DWORD np = name_ptrs[i];
            if (np >= export_rva && np < export_rva + export_size) {
                strncpy(name, (char*)(eb + (np - export_rva)), sizeof(name) - 1);
            } else {
                ReadProcessMemory(hProc, (LPCVOID)(mod_base + np),
                                  name, sizeof(name) - 1, &nread);
            }
            if (_stricmp(name, func_name) == 0) {
                WORD ord = ordinals[i];
                if (ord < num_funcs) {
                    DWORD frva = func_addrs[ord];
                    if (frva != 0 &&
                        !(frva >= export_rva && frva < export_rva + export_size))
                        result = mod_base + frva;
                }
                break;
            }
        }
    }
    free(eb);
    return result;
}

static DWORD64 hook_get_target_module(HANDLE hProc, const char *mod_name)
{
    DWORD pid = GetProcessId(hProc);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    DWORD64 found = 0;

    if (Module32FirstW(snap, &me)) {
        do {
            char mname[MAX_PATH];
            WideCharToMultiByte(CP_ACP, 0, me.szModule, -1, mname, MAX_PATH, NULL, NULL);
            if (_stricmp(mname, mod_name) == 0) {
                found = (DWORD64)me.modBaseAddr;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

static const BYTE HOOK_BODY_GPA[] = {
    0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x50,
    0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,
    0x50,
    0x48, 0x8B, 0x54, 0x24, 0x30,
    0x48, 0x8B, 0x4C, 0x24, 0x38,
    0xB8, 0x01, 0x00, 0x00, 0x00,
    0xF0, 0x48, 0x0F, 0xC1, 0x05, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x3D, 0x00, 0x20, 0x00, 0x00,
    0x73, 0x28,
    0x4C, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
    0x4C, 0x8B, 0xD0,
    0x49, 0xC1, 0xE2, 0x05,
    0x4D, 0x01, 0xD1,
    0x49, 0x89, 0x11,
    0x4C, 0x8B, 0x14, 0x24,
    0x49, 0x89, 0x51, 0x08,
    0x49, 0x89, 0x49, 0x10,
    0x49, 0xC7, 0x41, 0x18, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x8B, 0x04, 0x24,
    0x48, 0x83, 0xC4, 0x08,
    0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58,
    0x5A, 0x59,
    0xC3
};

static const BYTE HOOK_BODY_LLA[] = {
    0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x50,
    0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,
    0x50,
    0x48, 0x8B, 0x54, 0x24, 0x38,
    0xB8, 0x01, 0x00, 0x00, 0x00,
    0xF0, 0x48, 0x0F, 0xC1, 0x05, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x3D, 0x00, 0x20, 0x00, 0x00,
    0x73, 0x2C,
    0x4C, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
    0x4C, 0x8B, 0xD0,
    0x49, 0xC1, 0xE2, 0x05,
    0x4D, 0x01, 0xD1,
    0x49, 0x89, 0x11,
    0x4C, 0x8B, 0x14, 0x24,
    0x49, 0x89, 0x51, 0x08,
    0x49, 0xC7, 0x41, 0x10, 0x00, 0x00, 0x00, 0x00,
    0x49, 0xC7, 0x41, 0x18, 0x01, 0x00, 0x00, 0x00,
    0x48, 0x8B, 0x04, 0x24,
    0x48, 0x83, 0xC4, 0x08,
    0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58,
    0x5A, 0x59,
    0xC3
};

static const BYTE HOOK_BODY_LLW[] = {
    0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x50,
    0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,
    0x50,
    0x48, 0x8B, 0x54, 0x24, 0x38,
    0xB8, 0x01, 0x00, 0x00, 0x00,
    0xF0, 0x48, 0x0F, 0xC1, 0x05, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x3D, 0x00, 0x20, 0x00, 0x00,
    0x73, 0x2C,
    0x4C, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
    0x4C, 0x8B, 0xD0,
    0x49, 0xC1, 0xE2, 0x05,
    0x4D, 0x01, 0xD1,
    0x49, 0x89, 0x11,
    0x4C, 0x8B, 0x14, 0x24,
    0x49, 0x89, 0x51, 0x08,
    0x49, 0xC7, 0x41, 0x10, 0x00, 0x00, 0x00, 0x00,
    0x49, 0xC7, 0x41, 0x18, 0x02, 0x00, 0x00, 0x00,
    0x48, 0x8B, 0x04, 0x24,
    0x48, 0x83, 0xC4, 0x08,
    0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58,
    0x5A, 0x59,
    0xC3
};

typedef struct {
    BYTE *buf;
    int   len;
    int   cap;
} CodeBuf;

static void cb_put8(CodeBuf *c, BYTE v)
{
    if (c->len < c->cap) c->buf[c->len++] = v;
}
static void cb_put16(CodeBuf *c, WORD v)
{
    cb_put8(c, (BYTE)(v & 0xFF));
    cb_put8(c, (BYTE)(v >> 8));
}
static void cb_put32(CodeBuf *c, DWORD v)
{
    cb_put8(c, (BYTE)(v & 0xFF));
    cb_put8(c, (BYTE)((v >> 8) & 0xFF));
    cb_put8(c, (BYTE)((v >> 16) & 0xFF));
    cb_put8(c, (BYTE)((v >> 24) & 0xFF));
}
static void cb_put64(CodeBuf *c, DWORD64 v)
{
    for (int i = 0; i < 8; i++) cb_put8(c, (BYTE)((v >> (8 * i)) & 0xFF));
}

static void cb_patch32(CodeBuf *c, int at, DWORD v)
{
    if (at + 4 <= c->cap) {
        c->buf[at]     = (BYTE)(v & 0xFF);
        c->buf[at + 1] = (BYTE)((v >> 8) & 0xFF);
        c->buf[at + 2] = (BYTE)((v >> 16) & 0xFF);
        c->buf[at + 3] = (BYTE)((v >> 24) & 0xFF);
    }
}

static int hook_build_trampoline(HANDLE hProc, DWORD64 orig_addr, DWORD64 tramp_addr,
                                 BYTE *tramp_buf, int *out_prolog_len)
{
    BYTE orig[32];
    SIZE_T nread;
    if (!ReadProcessMemory(hProc, (LPCVOID)orig_addr, orig, sizeof(orig), &nread) ||
        nread < 16)
        return 0;

    int total = 0;
    int rip_refs[8];
    int rip_ref_at[8];
    int n_rip = 0;

    while (total < 12) {
        int ilen = lde64_len(orig + total, 16 - total);
        if (ilen <= 0) {
            static int lde_fails = 0;
            if (++lde_fails <= 2 || lde_fails % 100 == 0)
                printf("    [-] LDE: unsupported instruction at +%d (%02X %02X), hook aborted (fail %d)\n",
                       total, orig[total], (total + 1 < 16) ? orig[total + 1] : 0, lde_fails);
            return 0;
        }
        BYTE op = orig[total];
        int is_riprel = 0;
        int rip_disp_at = -1;

        if (op == 0x0F && total + 1 < 16) {
            BYTE op2 = orig[total + 1];
            int pre = total;
            while (pre > 0) {
                BYTE pb = orig[pre - 1];
                if (pb == 0x66 || pb == 0x67 || pb == 0xF2 || pb == 0xF3 ||
                    pb == 0xF0 || (pb & 0xF0) == 0x40 ||
                    pb == 0x2E || pb == 0x3E || pb == 0x26 || pb == 0x36 ||
                    pb == 0x64 || pb == 0x65) pre--;
                else break;
            }
            (void)pre;
            if (op2 >= 0x80 && op2 <= 0x8F) {
                is_riprel = 1;
            } else {
                int mplen = lde_modrm_extra64(orig[total + 2]);
                if (total + 2 < 16) {
                    BYTE modrm = orig[total + 2];
                    if ((modrm >> 6) == 0 && (modrm & 7) == 5) is_riprel = 1;
                }
                (void)mplen;
            }
        } else if (op == 0xE8 || op == 0xE9) {
            is_riprel = 1;
        } else if (op == 0xFF || op == 0x8B || op == 0x89 || op == 0x8D ||
                   op == 0xC7 || op == 0xC6 || op == 0x3B || op == 0x39 ||
                   op == 0x85 || op == 0x63 || op == 0x48 || op == 0x4C)
        {
            int plen = total;
            while (plen < 16) {
                BYTE pb = orig[plen];
                if ((pb & 0xF0) == 0x40 || pb == 0x66 || pb == 0x67 ||
                    pb == 0xF2 || pb == 0xF3 || pb == 0xF0 ||
                    pb == 0x2E || pb == 0x3E || pb == 0x26 || pb == 0x36 ||
                    pb == 0x64 || pb == 0x65) plen++;
                else break;
            }
            if (plen < 16) {
                BYTE mop = orig[plen];
                (void)mop;
                if (total + 1 < 16) {
                    BYTE modrm = orig[total + 1];
                    if ((modrm >> 6) == 0 && (modrm & 7) == 5) is_riprel = 1;
                }
            }
        }

        if (is_riprel && n_rip < 8) {
            int disp_off = total + 1;
            if (op == 0x0F) disp_off = total + 2;
            else {
                int plen = total;
                while (plen < 16) {
                    BYTE pb = orig[plen];
                    if ((pb & 0xF0) == 0x40 || pb == 0x66 || pb == 0x67 ||
                        pb == 0xF2 || pb == 0xF3 || pb == 0xF0 ||
                        pb == 0x2E || pb == 0x3E || pb == 0x26 || pb == 0x36 ||
                        pb == 0x64 || pb == 0x65) plen++;
                    else break;
                }
                disp_off = plen + 1;
            }
            rip_refs[n_rip] = op;
            rip_ref_at[n_rip] = disp_off;
            n_rip++;
        }

        total += ilen;
    }

    for (int i = 0; i < total; i++) tramp_buf[i] = orig[i];

    for (int i = 0; i < n_rip; i++) {
        int at = rip_ref_at[i];
        if (at + 4 <= total) {
            INT32 disp = *(INT32*)(tramp_buf + at);
            INT32 new_disp = disp - (INT32)(tramp_addr - orig_addr);
            *(INT32*)(tramp_buf + at) = new_disp;
        }
    }

    DWORD64 jmp_back_at = tramp_addr + total;
    INT32 rel = (INT32)((orig_addr + total) - (jmp_back_at + 5));

    CodeBuf cb = { tramp_buf, total, HOOK_TRAMP_SIZE };
    cb_put8(&cb, 0xE9);
    cb_put32(&cb, (DWORD)rel);
    *out_prolog_len = total;

    if (n_rip > 0)
        printf("    [*] Trampoline: %d bytes prologue, %d rip-relative reloc\n",
               total, n_rip);

    return 1;
}

static int hook_patch_entry(HANDLE hProc, DWORD64 orig_addr, DWORD64 hook_addr,
                            BYTE *orig_saved, int *out_patched_len)
{
    BYTE orig[32];
    SIZE_T nread;

    if (!ReadProcessMemory(hProc, (LPCVOID)orig_addr, orig, sizeof(orig), &nread) ||
        nread < 16)
        return 0;

    int total = 0;
    while (total < 12) {
        int ilen = lde64_len(orig + total, 16 - total);
        if (ilen <= 0) return 0;
        total += ilen;
        if (total >= 6 && total >= 5) {
            if (total >= 12) break;
        }
    }
    if (total < 5) return 0;

    BYTE patch[16];
    int plen = 0;

    if (total >= 12) {
        patch[0] = 0x48; patch[1] = 0xB8;
        memcpy(patch + 2, &hook_addr, 8);
        patch[10] = 0xFF; patch[11] = 0xE0;
        plen = 12;
    } else {
        DWORD64 tail = orig_addr + 6;
        patch[0] = 0xFF; patch[1] = 0x25;
        *(DWORD*)(patch + 2) = 0;
        memcpy(patch + 6, &hook_addr, 8);
        plen = 14;
        (void)tail;
    }

    if (orig_saved) memcpy(orig_saved, orig, 16);
    if (out_patched_len) *out_patched_len = plen;

    DWORD old_prot = 0;
    if (!VirtualProtectEx(hProc, (LPVOID)(ULONG_PTR)orig_addr, 16, PAGE_EXECUTE_READWRITE, &old_prot))
        return 0;

    BOOL ok = WriteProcessMemory(hProc, (LPVOID)(ULONG_PTR)orig_addr, patch, plen, NULL);
    VirtualProtectEx(hProc, (LPVOID)(ULONG_PTR)orig_addr, 16, old_prot, &old_prot);
    FlushInstructionCache(hProc, (LPCVOID)(ULONG_PTR)orig_addr, plen);
    return ok ? 1 : 0;
}

static void install_gpa_hook(HANDLE hProc)
{
#ifdef _WIN64
    if (g_hook_cave != 0) return;

    if (g_target_image_name[0] == '\0') {
        DWORD pid = GetProcessId(hProc);
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
        if (snap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me;
            me.dwSize = sizeof(me);
            if (Module32FirstW(snap, &me))
                WideCharToMultiByte(CP_ACP, 0, me.szModule, -1,
                                    g_target_image_name,
                                    (int)sizeof(g_target_image_name), NULL, NULL);
            CloseHandle(snap);
        }
    }

    DWORD64 k32 = hook_get_target_module(hProc, "kernel32.dll");
    if (!k32) {
        static int warned = 0;
        if (!warned) {
            printf("[-] GPA hook: kernel32.dll not found in target (will retry)\n");
            warned = 1;
        }
        return;
    }

    DWORD64 gpa = hook_find_export_in_target(hProc, k32, "GetProcAddress");
    DWORD64 lla = hook_find_export_in_target(hProc, k32, "LoadLibraryA");
    DWORD64 llw = hook_find_export_in_target(hProc, k32, "LoadLibraryW");

    if (!gpa) { printf("[-] GPA hook: GetProcAddress not resolved\n"); return; }
    printf("[*] GPA hook targets: GPA=0x%llX LLA=0x%llX LLW=0x%llX\n",
           (unsigned long long)gpa,
           (unsigned long long)lla, (unsigned long long)llw);

    BYTE *cave_local = (BYTE*)VirtualAlloc(NULL, HOOK_TOTAL_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!cave_local) { printf("[-] GPA hook: local alloc failed\n"); return; }
    memset(cave_local, 0, HOOK_TOTAL_SIZE);

    DWORD64 cave_remote = (DWORD64)VirtualAllocEx(hProc, NULL, HOOK_TOTAL_SIZE,
                                                  MEM_RESERVE | MEM_COMMIT,
                                                  PAGE_EXECUTE_READWRITE);
    if (!cave_remote) {
        printf("[-] GPA hook: VirtualAllocEx failed (error %u)\n", (unsigned)GetLastError());
        VirtualFree(cave_local, 0, MEM_RELEASE);
        return;
    }

    memcpy(cave_local + 0x000, "VMPH", 4);

    BYTE *tramps = cave_local + HOOK_TRAMP_OFF;
    DWORD64 tramp_r[3];
    tramp_r[0] = cave_remote + HOOK_TRAMP_OFF;
    tramp_r[1] = cave_remote + HOOK_TRAMP_OFF + HOOK_TRAMP_SIZE;
    tramp_r[2] = cave_remote + HOOK_TRAMP_OFF + 2 * HOOK_TRAMP_SIZE;

    int prolog_len = 0;
    if (!hook_build_trampoline(hProc, gpa, tramp_r[0], tramps, &prolog_len)) {
        static int hook_fails = 0;
        if (++hook_fails <= 2 || hook_fails % 100 == 0)
            printf("[-] GPA hook: GetProcAddress prologue not hookable (attempt %d)\n",
                   hook_fails);
        VirtualFreeEx(hProc, (LPVOID)(ULONG_PTR)cave_remote, 0, MEM_RELEASE);
        VirtualFree(cave_local, 0, MEM_RELEASE);
        return;
    }

    if (lla && !hook_build_trampoline(hProc, lla, tramp_r[1],
                                      tramps + HOOK_TRAMP_SIZE, &prolog_len)) {
        printf("[!] LLA prologue not hookable, skipping LLA\n");
        lla = 0;
    }
    if (llw && !hook_build_trampoline(hProc, llw, tramp_r[2],
                                      tramps + 2 * HOOK_TRAMP_SIZE, &prolog_len)) {
        printf("[!] LLW prologue not hookable, skipping LLW\n");
        llw = 0;
    }

    DWORD64 orig_gpa_slot = tramp_r[0];
    DWORD64 orig_lla_slot = lla ? tramp_r[1] : 0;
    DWORD64 orig_llw_slot = llw ? tramp_r[2] : 0;

    BYTE *body = cave_local + HOOK_BODY_OFF;
    BYTE *slots = cave_local + HOOK_SLOTS_OFF;

    int body_len = (int)sizeof(HOOK_BODY_GPA);
    memcpy(body, HOOK_BODY_GPA, body_len);
    {
        BYTE *b = body;
        INT32 disp;
         
        disp = (INT32)((cave_remote + HOOK_SLOTS_OFF + 0) - ((cave_remote + HOOK_BODY_OFF) + 17));
        *(INT32*)(b + 13) = disp;
         
        disp = (INT32)((cave_remote + 8) - ((cave_remote + HOOK_BODY_OFF) + 42));
        *(INT32*)(b + 38) = disp;
         
        disp = (INT32)((cave_remote + HOOK_RING_OFF) - ((cave_remote + HOOK_BODY_OFF) + 57));
        *(INT32*)(b + 53) = disp;
    }

    if (lla) {
        BYTE *b2 = body + HOOK_BODY_SIZE;
        memcpy(b2, HOOK_BODY_LLA, (int)sizeof(HOOK_BODY_LLA));
        INT32 disp;
        disp = (INT32)((cave_remote + HOOK_SLOTS_OFF + 8) - ((cave_remote + HOOK_BODY_OFF + HOOK_BODY_SIZE) + 17));
        *(INT32*)(b2 + 13) = disp;
        disp = (INT32)((cave_remote + 8) - ((cave_remote + HOOK_BODY_OFF + HOOK_BODY_SIZE) + 37));
        *(INT32*)(b2 + 33) = disp;
        disp = (INT32)((cave_remote + HOOK_RING_OFF) - ((cave_remote + HOOK_BODY_OFF + HOOK_BODY_SIZE) + 52));
        *(INT32*)(b2 + 48) = disp;
    }

    if (llw) {
        BYTE *b3 = body + 2 * HOOK_BODY_SIZE;
        memcpy(b3, HOOK_BODY_LLW, (int)sizeof(HOOK_BODY_LLW));
        INT32 disp;
        disp = (INT32)((cave_remote + HOOK_SLOTS_OFF + 16) - ((cave_remote + HOOK_BODY_OFF + 2 * HOOK_BODY_SIZE) + 17));
        *(INT32*)(b3 + 13) = disp;
        disp = (INT32)((cave_remote + 8) - ((cave_remote + HOOK_BODY_OFF + 2 * HOOK_BODY_SIZE) + 37));
        *(INT32*)(b3 + 33) = disp;
        disp = (INT32)((cave_remote + HOOK_RING_OFF) - ((cave_remote + HOOK_BODY_OFF + 2 * HOOK_BODY_SIZE) + 52));
        *(INT32*)(b3 + 48) = disp;
    }

    memcpy(slots + 0,  &orig_gpa_slot, 8);
    memcpy(slots + 8,  &orig_lla_slot, 8);
    memcpy(slots + 16, &orig_llw_slot, 8);
    {
        QWORD maxe = HOOK_RING_MAX;
        memcpy(cave_local + 0x18, &maxe, 8);
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, (LPVOID)(ULONG_PTR)cave_remote, cave_local,
                            HOOK_TOTAL_SIZE, &written) || written != HOOK_TOTAL_SIZE) {
        printf("[-] GPA hook: WriteProcessMemory failed (error %u)\n", (unsigned)GetLastError());
        VirtualFreeEx(hProc, (LPVOID)(ULONG_PTR)cave_remote, 0, MEM_RELEASE);
        VirtualFree(cave_local, 0, MEM_RELEASE);
        return;
    }
    FlushInstructionCache(hProc, (LPCVOID)(ULONG_PTR)cave_remote, HOOK_TOTAL_SIZE);

    {
        BYTE check[64];
        SIZE_T cnr;
        if (ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)(cave_remote + HOOK_BODY_OFF),
                              check, 48, &cnr) && cnr >= 48) {
            INT32 d_call = *(INT32*)(check + 13);
            INT32 d_xadd = *(INT32*)(check + 38);
            INT32 d_lea  = *(INT32*)(check + 53);
            DWORD64 t_call = cave_remote + HOOK_BODY_OFF + 17 + (DWORD64)d_call;
            DWORD64 t_xadd = cave_remote + HOOK_BODY_OFF + 42 + (DWORD64)d_xadd;
            DWORD64 t_lea  = cave_remote + HOOK_BODY_OFF + 57 + (DWORD64)d_lea;
            printf("[*] Hook self-check: call->0x%llX (slots 0x%llX) xadd->0x%llX (want 0x%llX) lea->0x%llX (ring 0x%llX)\n",
                   (unsigned long long)t_call, (unsigned long long)(cave_remote + HOOK_SLOTS_OFF),
                   (unsigned long long)t_xadd, (unsigned long long)(cave_remote + 8),
                   (unsigned long long)t_lea, (unsigned long long)(cave_remote + HOOK_RING_OFF));
        }
    }

    DWORD64 hook_gpa = cave_remote + HOOK_BODY_OFF;
    DWORD64 hook_lla = cave_remote + HOOK_BODY_OFF + HOOK_BODY_SIZE;
    DWORD64 hook_llw = cave_remote + HOOK_BODY_OFF + 2 * HOOK_BODY_SIZE;

    static BYTE orig_saved_gpa[16];
    static BYTE orig_saved_lla[16];
    static BYTE orig_saved_llw[16];
    int patched_len = 0;

    if (is_wine_host()) {
        printf("[*] wine host: cross-process code/IAT patches are not honored by\n"
               "    wine shared mappings - skipping inline hooks.\n"
               "    Read-based IAT rebuild (catalog + address matching) stays active.\n");
        g_hook_cave = cave_remote;
        g_hook_gpa_addr = gpa;
        g_hook_lla_addr = lla;
        g_hook_llw_addr = llw;
        return;
    }

    if (!hook_patch_entry(hProc, gpa, hook_gpa, orig_saved_gpa, &patched_len)) {
        printf("[-] GPA hook: entry patch failed\n");
        VirtualFreeEx(hProc, (LPVOID)(ULONG_PTR)cave_remote, 0, MEM_RELEASE);
        VirtualFree(cave_local, 0, MEM_RELEASE);
        return;
    }
    g_hook_installed_count++;
    printf("[+] GetProcAddress hooked (patch=%d bytes, cave=0x%llX)\n",
           patched_len, (unsigned long long)cave_remote);
    {
        BYTE verify[16];
        SIZE_T vn;
        if (ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)gpa, verify, 16, &vn) && vn == 16) {
            printf("[*] GPA entry NOW: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n",
                   verify[0],verify[1],verify[2],verify[3],verify[4],verify[5],
                   verify[6],verify[7],verify[8],verify[9],verify[10],verify[11]);
        }
    }

    if (lla && hook_patch_entry(hProc, lla, hook_lla, orig_saved_lla, &patched_len)) {
        g_hook_installed_count++;
        printf("[+] LoadLibraryA hooked (patch=%d bytes)\n", patched_len);
    }
    if (llw && hook_patch_entry(hProc, llw, hook_llw, orig_saved_llw, &patched_len)) {
        g_hook_installed_count++;
        printf("[+] LoadLibraryW hooked (patch=%d bytes)\n", patched_len);
    }

    launch_remote_patch_stub(hProc, cave_remote, gpa, lla, llw,
                             cave_remote + HOOK_BODY_OFF,
                             cave_remote + HOOK_BODY_OFF + HOOK_BODY_SIZE,
                             cave_remote + HOOK_BODY_OFF + 2 * HOOK_BODY_SIZE);

    {
        int iat_slots = patch_iat_slots_for_hooks(hProc);
        printf("[+] IAT-slot hooking: %d slots redirected to cave\n", iat_slots);
    }

    g_hook_cave = cave_remote;
    g_hook_gpa_addr = gpa;
    g_hook_lla_addr = lla;
    g_hook_llw_addr = llw;
    free_saved_prologues: ;
#else
    printf("[*] GPA hook: x86 target, inline hooks skipped (order-based IAT rebuild will be used)\n");
#endif
}

static int patch_iat_slots_for_hooks(HANDLE hProc)
{
    if (g_hook_cave == 0) return 0;

    static int g_hook_dbg = 0;
    int dbg_now = 0;
    if (g_hook_dbg < 3) { g_hook_dbg++; dbg_now = 1; }
    DWORD64 hook_gpa = g_hook_cave + HOOK_BODY_OFF;
    DWORD64 hook_lla = g_hook_cave + HOOK_BODY_OFF + HOOK_BODY_SIZE;
    DWORD64 hook_llw = g_hook_cave + HOOK_BODY_OFF + 2 * HOOK_BODY_SIZE;

    DWORD pid = GetProcessId(hProc);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    int total = 0;

    if (Module32FirstW(snap, &me)) {
        do {
            DWORD64 base = (DWORD64)me.modBaseAddr;
            BYTE hdr[4096];
            SIZE_T nr;
            if (!ReadProcessMemory(hProc, (LPCVOID)base, hdr, sizeof(hdr), &nr) ||
                nr < 1024) continue;
            if (hdr[0] != 'M' || hdr[1] != 'Z') continue;

            DWORD pe_off = *(DWORD*)(hdr + 0x3C);
            if (pe_off + 264 > sizeof(hdr)) continue;
            BYTE *pe = hdr + pe_off;
            if (*(DWORD*)pe != 0x00004550) continue;

            WORD machine = *(WORD*)(pe + 4);
            int dd_base  = (machine == 0x8664) ? (24 + 112) : (24 + 96);
            int ptr_size = (machine == 0x8664) ? 8 : 4;
            int ord_shift = (ptr_size * 8) - 1;

            DWORD imp_rva = *(DWORD*)(pe + dd_base + 8);
            DWORD imp_sz  = *(DWORD*)(pe + dd_base + 12);
            if (imp_rva == 0 || imp_sz == 0 || imp_sz > 0x100000) continue;

            BYTE *ib = (BYTE*)malloc(imp_sz + 32);
            if (!ib) continue;
            if (!ReadProcessMemory(hProc, (LPCVOID)(base + imp_rva), ib, imp_sz, &nr)) {
                free(ib);
                continue;
            }

            if (dbg_now)
                printf("[iatdbg] mod %ls imp_rva=0x%X imp_sz=0x%X\n", me.szModule, imp_rva, imp_sz);

            for (DWORD d = 0; d + 20 <= imp_sz; d += 20) {
                DWORD oft = *(DWORD*)(ib + d);
                DWORD ft  = *(DWORD*)(ib + d + 16);
                if (oft == 0 && ft == 0) break;
                if (ft == 0 || oft == 0) continue;    

                for (int s = 0; s < 16384; s++) {
                    DWORD slot_addr = base + ft + (DWORD)(s * ptr_size);
                    DWORD64 thunk_val = 0;
                    if (!ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)slot_addr,
                                           &thunk_val, ptr_size, &nr) || thunk_val == 0)
                        break;

                    DWORD int_addr = base + oft + (DWORD)(s * ptr_size);
                    DWORD64 int_val = 0;
                    if (!ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)int_addr,
                                           &int_val, ptr_size, &nr) || int_val == 0)
                        break;
                    if ((int_val >> ord_shift) & 1) continue;    

                    DWORD name_rva = (DWORD)(int_val & 0xFFFFFFFF);
                    char fname[64] = {0};
                    if (!ReadProcessMemory(hProc,
                            (LPCVOID)(base + name_rva + 2),
                            fname, sizeof(fname) - 1, &nr))
                        continue;

                    DWORD64 target_hook = 0;
                    if (strcmp(fname, "GetProcAddress") == 0)
                        target_hook = hook_gpa;
                    else if (strcmp(fname, "LoadLibraryA") == 0)
                        target_hook = hook_lla;
                    else if (strcmp(fname, "LoadLibraryW") == 0)
                        target_hook = hook_llw;
                    if (target_hook == 0) {
                        if (dbg_now && (!strcmp(fname, "GetProcAddress") ||
                                           !strcmp(fname, "LoadLibraryA")))
                            printf("[iatdbg]   slot s=%d %s matched-name but... target_hook=0?\n", s, fname);
                        continue;
                    }
                    if (dbg_now)
                        printf("[iatdbg]   HOOKABLE slot s=%d %s thunk=0x%llX\n",
                               s, fname, (unsigned long long)thunk_val);

                    if (thunk_val >= g_hook_cave &&
                        thunk_val < g_hook_cave + HOOK_TOTAL_SIZE)
                        continue;    

                    DWORD oldp = 0;
                    if (VirtualProtectEx(hProc, (LPVOID)(ULONG_PTR)slot_addr,
                                         ptr_size, PAGE_READWRITE, &oldp)) {
                        if (WriteProcessMemory(hProc, (LPVOID)(ULONG_PTR)slot_addr,
                                               &target_hook, ptr_size, &nr)) {
                            total++;
                            FlushInstructionCache(hProc,
                                (LPCVOID)(ULONG_PTR)slot_addr, ptr_size);
                        }
                        VirtualProtectEx(hProc, (LPVOID)(ULONG_PTR)slot_addr,
                                         ptr_size, oldp, &oldp);
                    }
                }
            }
            free(ib);
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return total;
}

static const BYTE HOOK_STUB_X64[] = {
    0x53,                                    
    0x48, 0x89, 0xCB,                        
    0x48, 0x89, 0xDF,                        
    0x48, 0x8B, 0x47, 0x38,                  
    0x48, 0x83, 0xEC, 0x30,                  
    0x4C, 0x8D, 0x4C, 0x24, 0x20,            
    0x48, 0xC7, 0x47, 0x40, 0x01, 0x00, 0x00, 0x00,    
    0x48, 0x8B, 0x0F,                        
    0xBA, 0x10, 0x00, 0x00, 0x00,            
    0x41, 0xB8, 0x40, 0x00, 0x00, 0x00,      
    0xFF, 0xD0,                              
    0x48, 0xC7, 0x47, 0x48, 0x01, 0x00, 0x00, 0x00,    
    0x48, 0x8B, 0x0F,                        
    0x48, 0x8B, 0x47, 0x18,                  
    0xC6, 0x01, 0x48,                        
    0xC6, 0x41, 0x01, 0xB8,                  
    0x48, 0x89, 0x41, 0x02,                  
    0x66, 0xC7, 0x41, 0x0A, 0xE0, 0xFF,      
    0x48, 0x8B, 0x4F, 0x08,                  
    0x48, 0x85, 0xC9,                        
    0x74, 0x15,                              
    0x48, 0x8B, 0x47, 0x20,                  
    0xC6, 0x01, 0x48,                        
    0xC6, 0x41, 0x01, 0xB8,                  
    0x48, 0x89, 0x41, 0x02,                  
    0x66, 0xC7, 0x41, 0x0A, 0xE0, 0xFF,      
    0x48, 0x8B, 0x4F, 0x10,                  
    0x48, 0x85, 0xC9,                        
    0x74, 0x15,                              
    0x48, 0x8B, 0x47, 0x28,                  
    0xC6, 0x01, 0x48,                        
    0xC6, 0x41, 0x01, 0xB8,                  
    0x48, 0x89, 0x41, 0x02,                  
    0x66, 0xC7, 0x41, 0x0A, 0xE0, 0xFF,      
    0x48, 0xC7, 0x47, 0x50, 0x01, 0x00, 0x00, 0x00,    
    0x48, 0x83, 0xC4, 0x30,                  
    0x5B,                                    
    0x31, 0xC0,                              
    0xC3                                     
};

static void launch_remote_patch_stub(HANDLE hProc, DWORD64 cave_remote,
                                     DWORD64 gpa, DWORD64 lla, DWORD64 llw,
                                     DWORD64 hook_gpa, DWORD64 hook_lla,
                                     DWORD64 hook_llw)
{
    typedef NTSTATUS (NTAPI *pfnNCTE)(PHANDLE, ACCESS_MASK, void *, HANDLE,
                                      LPTHREAD_START_ROUTINE, LPVOID, ULONG,
                                      SIZE_T, SIZE_T, SIZE_T, LPVOID);
    static pfnNCTE fn = NULL;
    if (!fn) {
        HMODULE hN = GetModuleHandleA("ntdll.dll");
        if (hN) fn = (pfnNCTE)(ULONG_PTR)GetProcAddress(hN, "NtCreateThreadEx");
    }

    DWORD64 k32 = hook_get_target_module(hProc, "kernel32.dll");
    DWORD64 vp = k32 ? hook_find_export_in_target(hProc, k32, "VirtualProtect") : 0;
    if (!vp) {
        printf("[!] CRT stub: VirtualProtect not resolved, skipping\n");
        return;
    }

    {
        SIZE_T swr = 0;
        if (!WriteProcessMemory(hProc, (LPVOID)(ULONG_PTR)(cave_remote + HOOK_STUB_OFF),
                                HOOK_STUB_X64, sizeof(HOOK_STUB_X64), &swr)) {
            printf("[!] CRT stub: stub write failed (err %u)\n", (unsigned)GetLastError());
            return;
        }
        FlushInstructionCache(hProc, (LPCVOID)(ULONG_PTR)(cave_remote + HOOK_STUB_OFF),
                              sizeof(HOOK_STUB_X64));
    }

    BYTE params[128];
    memset(params, 0, sizeof(params));
    memcpy(params + 0,  &gpa, 8);
    memcpy(params + 8,  &lla, 8);
    memcpy(params + 16, &llw, 8);
    memcpy(params + 24, &hook_gpa, 8);
    memcpy(params + 32, &hook_lla, 8);
    memcpy(params + 40, &hook_llw, 8);
    memcpy(params + 56, &vp, 8);

    SIZE_T wr = 0;
    if (!WriteProcessMemory(hProc, (LPVOID)(ULONG_PTR)(cave_remote + HOOK_PARAM_OFF),
                            params, sizeof(params), &wr)) {
        printf("[!] CRT stub: param write failed (err %u)\n", (unsigned)GetLastError());
        return;
    }

    HANDLE th = NULL;
    NTSTATUS st = -1;
    if (fn) {
        st = fn(&th, 0x1FFFFF, NULL, hProc,
                (LPTHREAD_START_ROUTINE)(ULONG_PTR)(cave_remote + HOOK_STUB_OFF),
                (LPVOID)(ULONG_PTR)(cave_remote + HOOK_PARAM_OFF),
                0, 0, 0, 0, NULL);
        printf("[*] NtCreateThreadEx status=0x%08lX th=%p\n",
               (unsigned long)st, (void*)th);
    }
    if (st < 0) {
        th = CreateRemoteThread(hProc, NULL, 0,
                                (LPTHREAD_START_ROUTINE)(ULONG_PTR)(cave_remote + HOOK_STUB_OFF),
                                (LPVOID)(ULONG_PTR)(cave_remote + HOOK_PARAM_OFF), 0, NULL);
        if (!th)
            printf("[!] CreateRemoteThread failed (err %u)\n", (unsigned)GetLastError());
    }
    if (th) CloseHandle(th);

    LONGLONG last1 = -1, last2 = -1;
    for (int i = 0; i < 20; i++) {
        Sleep(50);
        BYTE hdr[88];
        SIZE_T nr;
        if (ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)(cave_remote + HOOK_PARAM_OFF),
                              hdr, 88, &nr) && nr == 88) {
            LONGLONG s1 = *(LONGLONG*)(hdr + 64);
            LONGLONG s2 = *(LONGLONG*)(hdr + 72);
            LONGLONG s3 = *(LONGLONG*)(hdr + 80);
            if (s3 == 1) {
                printf("[+] Remote stub COMPLETED (entries patched in-process)\n");
                return;
            }
            last1 = s1; last2 = s2;
        }
    }
    printf("[!] Remote stub incomplete in 1s: stage1=%lld stage2=%lld\n",
           (long long)last1, (long long)last2);
    if (last1 == 1 && last2 == 1)
        printf("[!] Environment blocks writes to system-DLL code pages (wine shared\n"
               "    mappings). Inline hooks disabled here; read-based IAT rebuild\n"
               "    (catalog + address matching) remains fully functional.\n"
               "    On native Windows the inline hooks operate normally.\n");
}

static void poll_gpa_log(HANDLE hProc)
{
#ifdef _WIN64
    if (g_hook_cave == 0 || !hProc) return;

    BYTE hdr[0x20];
    SIZE_T nread;
    if (!ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)g_hook_cave, hdr,
                           sizeof(hdr), &nread))
        return;

    LONGLONG count = *(LONGLONG*)(hdr + 8);
    {
        static int dbg_n = 0;
        if (++dbg_n % 20 == 1)
            printf("[dbg] cave hdr: %02X %02X %02X %02X | count=%lld\n",
                   hdr[0], hdr[1], hdr[2], hdr[3], (long long)count);
    }
    if (count <= 0) return;
    if (count > HOOK_RING_MAX) count = HOOK_RING_MAX;

    static LONGLONG consumed = 0;
    LONGLONG start = consumed;
    if (start >= count) return;

    static DWORD64 mod_bases[512];
    static DWORD64 mod_ends[512];
    static char    mod_names[512][64];
    static int     mod_count = 0;
    static int     mod_cached = 0;

    if (!mod_cached) {
        DWORD pid = GetProcessId(hProc);
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me;
            me.dwSize = sizeof(me);
            if (Module32FirstW(snap, &me)) {
                do {
                    if (mod_count >= 512) break;
                    mod_bases[mod_count] = (DWORD64)me.modBaseAddr;
                    mod_ends[mod_count] = mod_bases[mod_count] + me.modBaseSize;
                    WideCharToMultiByte(CP_ACP, 0, me.szModule, -1,
                                        mod_names[mod_count], 64, NULL, NULL);
                    mod_count++;
                } while (Module32NextW(snap, &me));
            }
            CloseHandle(snap);
        }
        mod_cached = 1;
    }

    int new_logged = 0;

    for (LONGLONG i = start; i < count; i++) {
        BYTE ent[HOOK_ENTRY_SIZE];
        if (!ReadProcessMemory(hProc,
                (LPCVOID)(ULONG_PTR)(g_hook_cave + HOOK_RING_OFF + i * HOOK_ENTRY_SIZE),
                ent, sizeof(ent), &nread))
            break;

        DWORD64 name_ptr = *(DWORD64*)(ent + 0);
        DWORD64 resolved = *(DWORD64*)(ent + 8);
        DWORD64 hmod     = *(DWORD64*)(ent + 16);
        DWORD64 tag      = *(DWORD64*)(ent + 24);

        if (tag > 2) continue;

        char func_name[256] = {0};
        int have_name = 0;

        if (tag == HOOK_TAG_GPA) {
            if (name_ptr != 0 && name_ptr < 0x10000) {
                sprintf(func_name, "#%lu", (unsigned long)name_ptr);
                have_name = 1;
            } else if (name_ptr != 0) {
                char tmp[256] = {0};
                if (ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)name_ptr,
                                      tmp, sizeof(tmp) - 1, &nread) && nread > 0) {
                    tmp[sizeof(tmp) - 1] = '\0';
                    tmp[255] = '\0';
                    if (tmp[0] != '\0') {
                        strncpy(func_name, tmp, sizeof(func_name) - 1);
                        have_name = 1;
                    }
                }
            }
        } else if (tag == HOOK_TAG_LLA) {
            if (name_ptr != 0) {
                char tmp[256] = {0};
                if (ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)name_ptr,
                                      tmp, sizeof(tmp) - 1, &nread) && nread > 0) {
                    tmp[sizeof(tmp) - 1] = '\0';
                    if (tmp[0] != '\0') {
                        strncpy(func_name, tmp, sizeof(func_name) - 1);
                        have_name = 1;
                    }
                }
            }
        } else if (tag == HOOK_TAG_LLW) {
            if (name_ptr != 0) {
                WCHAR wtmp[128] = {0};
                if (ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)name_ptr,
                                      wtmp, sizeof(wtmp) - 2, &nread) && nread > 0) {
                    char tmp[256] = {0};
                    WideCharToMultiByte(CP_ACP, 0, wtmp, -1, tmp, sizeof(tmp), NULL, NULL);
                    if (tmp[0] != '\0') {
                        strncpy(func_name, tmp, sizeof(func_name) - 1);
                        have_name = 1;
                    }
                }
            }
        }

        const char *mod_name = NULL;
        if (tag == HOOK_TAG_GPA) {
            if (hmod == 0) {
                mod_name = g_target_image_name[0] ? g_target_image_name : NULL;
            } else {
                for (int m = 0; m < mod_count; m++) {
                    if (hmod >= mod_bases[m] && hmod < mod_ends[m]) {
                        mod_name = mod_names[m];
                        break;
                    }
                }
            }
        } else {
            for (int m = 0; m < mod_count; m++) {
                if (hmod != 0 && hmod == mod_bases[m]) {
                    mod_name = mod_names[m];
                    break;
                }
            }
        }

        if (!have_name && resolved == 0) continue;
        if (!mod_name) mod_name = "unknown.dll";

        log_import(mod_name, have_name ? func_name : "(ordinal)", resolved);
        new_logged++;
    }

    consumed = count;
    if (new_logged > 0)
        printf("[+] GPA hook log: +%d calls captured (total ring %lld)\n",
               new_logged, (long long)count);
#endif
}

static void neutralize_antidebug(HANDLE hProc)
{
    SIZE_T nread;
    ULONG_PTR peb = 0;

    typedef NTSTATUS (NTAPI *pfnNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static pfnNtQIP fn = NULL;
    if (!fn) {
        HMODULE hN = GetModuleHandleA("ntdll.dll");
        if (hN) fn = (pfnNtQIP)GetProcAddress(hN, "NtQueryInformationProcess");
    }
    if (!fn) return;

#ifdef _WIN64
    ULONG_PTR wow64 = 0;
    fn(hProc, ProcessWow64Information, &wow64, sizeof(wow64), NULL);
    if (wow64 != 0) {
        BYTE peb32_buf[8];
        if (ReadProcessMemory(hProc, (LPCVOID)wow64, peb32_buf, 4, &nread)) {
            DWORD peb32 = *(DWORD*)peb32_buf;
            BYTE zero = 0;
            DWORD flag = 0;
            WriteProcessMemory(hProc, (LPVOID)(ULONG_PTR)(peb32 + 2), &zero, 1, &nread);
            WriteProcessMemory(hProc, (LPVOID)(ULONG_PTR)(peb32 + 0x68), &flag, 4, &nread);
            printf("[+] Anti-debug: WOW64 PEB.BeingDebugged=0, NtGlobalFlag=0\n");
        }
        return;
    }
#endif

    MY_PROCESS_BASIC_INFORMATION pbi;
    memset(&pbi, 0, sizeof(pbi));
    NTSTATUS st = fn(hProc, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
    if (!NT_SUCCESS(st) || !pbi.PebBaseAddress) return;

    peb = (ULONG_PTR)pbi.PebBaseAddress;
    BYTE zero = 0;
    DWORD flag = 0;
    WriteProcessMemory(hProc, (LPVOID)(peb + 2), &zero, 1, &nread);
#ifdef _WIN64
    WriteProcessMemory(hProc, (LPVOID)(peb + 0xBC), &flag, 4, &nread);
#else
    WriteProcessMemory(hProc, (LPVOID)(peb + 0x68), &flag, 4, &nread);
#endif
    printf("[+] Anti-debug: PEB.BeingDebugged=0, NtGlobalFlag=0 (PEB=0x%llX)\n",
           (unsigned long long)peb);
}

static int read_original_imports(const char *pe_path)
{
    FILE *f = fopen(pe_path, "rb");
    if (!f) return 0;

    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    if (fsz < 1024 || fsz > 1024 * 1024 * 1024) { fclose(f); return 0; }
    fseek(f, 0, SEEK_SET);

    BYTE *buf = (BYTE*)malloc(fsz);
    if (!buf) { fclose(f); return 0; }
    size_t rd = fread(buf, 1, fsz, f);
    fclose(f);
    if (rd < 1024) { free(buf); return 0; }

    if (buf[0] != 'M' || buf[1] != 'Z') { free(buf); return 0; }
    DWORD pe_off = *(DWORD*)(buf + 0x3C);
    if (pe_off + 264 > (DWORD)rd) { free(buf); return 0; }
    BYTE *pe = buf + pe_off;
    if (*(DWORD*)pe != 0x00004550) { free(buf); return 0; }

    WORD machine = *(WORD*)(pe + 4);
    int dd_base = (machine == 0x8664) ? (24 + 112) : (24 + 96);
    DWORD imp_rva  = *(DWORD*)(pe + dd_base + 8 * 1);
    DWORD imp_size = *(DWORD*)(pe + dd_base + 8 * 1 + 4);

    if (imp_rva == 0 || imp_size == 0) {
        printf("[!] Original file has no import directory\n");
        free(buf);
        return 0;
    }

    DWORD img_base = *(DWORD*)(pe + 24 + 24);
    if (machine == 0x8664)
        img_base = (DWORD)*(DWORD64*)(pe + 24 + 24);

    int ptr_size = (machine == 0x8664) ? 8 : 4;

    g_orig_import_count = 0;

    DWORD off = imp_rva;
    while (off + 20 <= (DWORD)rd && g_orig_import_count < MAX_ORIG_IMPORTS) {
        DWORD oft = *(DWORD*)(buf + off + 0);
        DWORD ts  = *(DWORD*)(buf + off + 4);
        DWORD name_rva = *(DWORD*)(buf + off + 12);
        DWORD ft  = *(DWORD*)(buf + off + 16);
        if (oft == 0 && ft == 0 && name_rva == 0) break;
        (void)ts;

        char dll[64] = {0};
        if (name_rva && (size_t)name_rva + 64 < rd) {
            strncpy(dll, (char*)(buf + name_rva), sizeof(dll) - 1);
            for (int k = (int)strlen(dll) - 1; k >= 0; k--)
                if (dll[k] == ' ') dll[k] = '\0';
        }

        DWORD thunk_rva = oft ? oft : ft;
        if (thunk_rva == 0 || (size_t)thunk_rva + 16 > rd) break;
        DWORD t = thunk_rva;
        int per_desc = 0;
        while ((size_t)t + (size_t)ptr_size <= rd && g_orig_import_count < MAX_ORIG_IMPORTS) {
            QWORD val64 = 0;
            DWORD val32 = 0;
            if (ptr_size == 8) val64 = *(DWORD64*)(buf + t);
            else val32 = *(DWORD*)(buf + t);

            int is_ord;
            DWORD name_field;
            if (ptr_size == 8) {
                is_ord = (val64 >> 63) != 0;
                name_field = (DWORD)(val64 & 0xFFFFFFFF);
            } else {
                is_ord = (val32 >> 31) != 0;
                name_field = val32 & 0x7FFFFFFF;
            }

            if ((ptr_size == 8 && val64 == 0) || (ptr_size == 4 && val32 == 0)) break;
            if (!is_ord && (name_field == 0 ||
                            (DWORD)(name_field + 2) >= (DWORD)rd)) break;

            OrigImport *oi = &g_orig_imports[g_orig_import_count];
            memset(oi, 0, sizeof(*oi));
            strncpy(oi->dll, dll, sizeof(oi->dll) - 1);

            if (is_ord) {
                sprintf(oi->func, "#%lu", (unsigned long)(name_field & 0xFFFF));
            } else {
                WORD hint = 0;
                if (name_field && name_field + 2 < (DWORD)rd) {
                    hint = *(WORD*)(buf + name_field);
                    strncpy(oi->func, (char*)(buf + name_field + 2), sizeof(oi->func) - 1);
                }
                oi->hint = hint;
            }
            g_orig_import_count++;
            per_desc++;
            t += ptr_size;
        }

        off += 20;
    }

    free(buf);
    printf("[+] Original imports parsed from disk: %d entries\n", g_orig_import_count);
    return g_orig_import_count;
}

static DWORD64 vid_resolve_via_catalog(const char *dll, const char *func)
{
    LONG imp_count = g_import_count;
    if (imp_count > MAX_IMPORTS) imp_count = MAX_IMPORTS;

    char dll_norm[64];
    strncpy(dll_norm, dll, sizeof(dll_norm) - 1);
    dll_norm[sizeof(dll_norm) - 1] = '\0';
    for (int i = 0; dll_norm[i]; i++) dll_norm[i] = (char)tolower((unsigned char)dll_norm[i]);

    for (LONG i = 0; i < imp_count; i++) {
        ImportEntry *e = &g_imports[i];
        if (e->module[0] == '\0') continue;

        char mod_norm[64];
        strncpy(mod_norm, e->module, sizeof(mod_norm) - 1);
        mod_norm[sizeof(mod_norm) - 1] = '\0';
        for (int k = 0; mod_norm[k]; k++) mod_norm[k] = (char)tolower((unsigned char)mod_norm[k]);

        const char *base = mod_norm;
        const char *sl = strrchr(base, '\\');
        if (sl) base = sl + 1;

        char mod_stem[64];
        strncpy(mod_stem, base, sizeof(mod_stem) - 1);
        char *dot = strrchr(mod_stem, '.');
        if (dot) *dot = '\0';

        char dll_stem[64];
        strncpy(dll_stem, dll_norm, sizeof(dll_stem) - 1);
        char *dot2 = strrchr(dll_stem, '.');
        if (dot2) *dot2 = '\0';

        if (strcmp(mod_stem, dll_stem) != 0) continue;
        if (strcmp(e->function, func) != 0) continue;

        return e->resolved_addr;
    }
    return 0;
}

static void rebuild_imports_vid(HANDLE hProc, DWORD64 base, const char *target_name)
{
    printf("\n[*] VID-style IAT rebuild: 5-step simulated GetProcAddress...\n");

    if (g_orig_import_count == 0) {
        const char *bn = get_basename(target_name);
        char orig_path[MAX_PATH];
        snprintf(orig_path, sizeof(orig_path), "%s", target_name);
        (void)bn;
        read_original_imports(orig_path);
    }
    if (g_orig_import_count == 0) {
        printf("[!] VID: no original imports available, skipping\n");
        return;
    }

    reconstruct_iat(hProc, base);

    printf("[*] VID step 2: simulated GetProcAddress catalog ready (%ld exports)\n",
           (long)g_import_count);

    BYTE hdr[4096];
    SIZE_T nr;
    if (!ReadProcessMemory(hProc, (LPCVOID)base, hdr, sizeof(hdr), &nr) || nr < 256) {
        printf("[-] VID: cannot read target PE header\n");
        return;
    }
    DWORD pe_off = *(DWORD*)(hdr + 0x3C);
    BYTE *pe = hdr + pe_off;
    WORD machine = *(WORD*)(pe + 4);
    int dd_base = (machine == 0x8664) ? (24 + 112) : (24 + 96);
    DWORD imp_rva  = *(DWORD*)(pe + dd_base + 8 * 1);
    DWORD imp_size = *(DWORD*)(pe + dd_base + 8 * 1 + 4);
    int ptr_size = (machine == 0x8664) ? 8 : 4;

    if (imp_rva == 0 || imp_size == 0) {
        printf("[!] VID: target has no import directory in memory\n");
        return;
    }

    BYTE *imp_buf = (BYTE*)malloc(imp_size + 4096);
    if (!imp_buf) return;
    if (!ReadProcessMemory(hProc, (LPCVOID)(base + imp_rva), imp_buf, imp_size, &nr)) {
        free(imp_buf);
        printf("[-] VID: cannot read import directory from target\n");
        return;
    }

    int orig_cursor = 0;
    int stubs_replaced = 0;
    int stubs_total = 0;
    int already_real = 0;

    printf("[*] VID step 3: scanning live import directory for VM stubs...\n");

    for (DWORD d = 0; d + 20 <= imp_size; d += 20) {
        DWORD oft = *(DWORD*)(imp_buf + d + 0);
        DWORD name_rva = *(DWORD*)(imp_buf + d + 12);
        DWORD ft  = *(DWORD*)(imp_buf + d + 16);
        if (oft == 0 && ft == 0) break;

        char dll[64] = {0};
        if (name_rva) {
            ReadProcessMemory(hProc, (LPCVOID)(base + name_rva), dll,
                              sizeof(dll) - 1, &nr);
            for (int k = (int)strlen(dll) - 1; k >= 0; k--)
                if (dll[k] == ' ') dll[k] = '\0';
        }

        DWORD thunk_rva = oft ? oft : ft;
        if (thunk_rva == 0) continue;

        for (int slot = 0; slot < 8192; slot++) {
            DWORD slot_addr = base + thunk_rva + (DWORD)(slot * ptr_size);
            DWORD64 val = 0;
            if (!ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)slot_addr, &val,
                                   ptr_size, &nr) || val == 0)
                break;

            stubs_total++;
            int in_image = (val >= base && val < base + g_size_of_image);

            OrigImport *oi = NULL;
            if (orig_cursor < g_orig_import_count)
                oi = &g_orig_imports[orig_cursor];

            if (oi) orig_cursor++;

            if (!in_image) {
                already_real++;
                continue;
            }

            if (!oi) break;

            DWORD64 resolved = vid_resolve_via_catalog(oi->dll, oi->func);
            if (resolved == 0) continue;

            DWORD old_prot = 0;
            if (VirtualProtectEx(hProc, (LPVOID)(ULONG_PTR)slot_addr, ptr_size,
                                 PAGE_READWRITE, &old_prot)) {
                if (WriteProcessMemory(hProc, (LPCVOID)(ULONG_PTR)slot_addr,
                                       &resolved, ptr_size, &nr)) {
                    stubs_replaced++;
                    FlushInstructionCache(hProc, (LPCVOID)(ULONG_PTR)slot_addr, ptr_size);

                    if (g_vid_fix_count < MAX_VID_FIXES) {
                        VidFixEntry *ve = &g_vid_fixes[g_vid_fix_count++];
                        ve->slot_rva = thunk_rva + (DWORD)(slot * ptr_size);
                        ve->resolved_addr = resolved;
                        strncpy(ve->module, oi->dll, sizeof(ve->module) - 1);
                        strncpy(ve->function, oi->func, sizeof(ve->function) - 1);
                        ve->status = 1;
                    }
                }
                VirtualProtectEx(hProc, (LPVOID)(ULONG_PTR)slot_addr, ptr_size,
                                 old_prot, &old_prot);
            }
        }
    }

    free(imp_buf);
    printf("[+] VID step 3 done: %d slots scanned, %d VM stubs replaced, %d already real\n",
           stubs_total, stubs_replaced, already_real);

    printf("[*] VID step 4: rebuilding fresh import directory in dump...\n");
    (void)target_name;
}

static void reconstruct_iat(HANDLE hProc, DWORD64 base)
{
    printf("\n[*] Reconstructing IAT from loaded modules...\n");

    HMODULE mods[512];
    DWORD cb_needed = 0;

    DWORD pid = GetProcessId(hProc);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot enumerate modules (error %u)\n", (unsigned)GetLastError());
        return;
    }

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);

    int mod_count = 0;
    if (Module32FirstW(snap, &me)) {
        do {
            if ((DWORD64)me.modBaseAddr == base) continue;

            BYTE mod_hdr[4096];
            SIZE_T nread;
            DWORD64 mod_base = (DWORD64)me.modBaseAddr;

            if (!ReadProcessMemory(hProc, (LPCVOID)mod_base, mod_hdr,
                                  sizeof(mod_hdr), &nread) || nread < 256)
                continue;

            if (mod_hdr[0] != 'M' || mod_hdr[1] != 'Z') continue;

            DWORD mod_pe_off = *(DWORD*)(mod_hdr + 0x3C);
            if (mod_pe_off + 256 > sizeof(mod_hdr)) continue;

            BYTE *pe = mod_hdr + mod_pe_off;
            if (*(DWORD*)pe != 0x00004550) continue;

            WORD mod_machine = *(WORD*)(pe + 4);
            DWORD export_rva, export_size;

            if (mod_machine == 0x8664) {
                export_rva  = *(DWORD*)(pe + 24 + 112);
                export_size = *(DWORD*)(pe + 24 + 116);
            } else {
                export_rva  = *(DWORD*)(pe + 24 + 96);
                export_size = *(DWORD*)(pe + 24 + 100);
            }

            if (export_rva == 0 || export_size == 0) continue;

            BYTE *export_buf = (BYTE*)malloc(export_size);
            if (!export_buf) continue;

            if (!ReadProcessMemory(hProc, (LPCVOID)(mod_base + export_rva),
                                  export_buf, export_size, &nread)) {
                free(export_buf);
                continue;
            }

            DWORD num_funcs = *(DWORD*)(export_buf + 20);
            DWORD num_names = *(DWORD*)(export_buf + 24);
            DWORD funcs_rva = *(DWORD*)(export_buf + 28);
            DWORD names_rva = *(DWORD*)(export_buf + 32);
            DWORD ords_rva  = *(DWORD*)(export_buf + 36);
            DWORD name_rva  = *(DWORD*)(export_buf + 12);

            char mod_name[128] = {0};
            if (name_rva >= export_rva && name_rva < export_rva + export_size) {
                strncpy(mod_name, (char*)(export_buf + (name_rva - export_rva)),
                        sizeof(mod_name) - 1);
            } else {
                ReadProcessMemory(hProc, (LPCVOID)(mod_base + name_rva),
                                 mod_name, sizeof(mod_name) - 1, &nread);
            }

            if (num_names > 0 && num_names < 20000 &&
                funcs_rva >= export_rva && funcs_rva < export_rva + export_size &&
                names_rva >= export_rva && names_rva < export_rva + export_size &&
                ords_rva  >= export_rva && ords_rva  < export_rva + export_size)
            {
                DWORD *func_addrs = (DWORD*)(export_buf + (funcs_rva - export_rva));
                DWORD *name_ptrs  = (DWORD*)(export_buf + (names_rva - export_rva));
                WORD  *ordinals   = (WORD*) (export_buf + (ords_rva  - export_rva));

                for (DWORD i = 0; i < num_names && i < 10000; i++) {
                    WORD ord = ordinals[i];
                    if (ord >= num_funcs) continue;

                    DWORD func_rva_val = func_addrs[ord];
                    if (func_rva_val == 0) continue;

                    if (func_rva_val >= export_rva &&
                        func_rva_val < export_rva + export_size)
                        continue;

                    DWORD64 func_addr = mod_base + func_rva_val;

                    char exp_name[256] = {0};
                    DWORD name_ptr = name_ptrs[i];
                    if (name_ptr >= export_rva && name_ptr < export_rva + export_size) {
                        strncpy(exp_name, (char*)(export_buf + (name_ptr - export_rva)),
                                sizeof(exp_name) - 1);
                    } else {
                        ReadProcessMemory(hProc, (LPCVOID)(mod_base + name_ptr),
                                         exp_name, sizeof(exp_name) - 1, &nread);
                    }

                    if (exp_name[0] != '\0') {
                        log_import(mod_name, exp_name, func_addr);
                    }
                }
                mod_count++;
            }

            free(export_buf);
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);

    printf("[+] Enumerated exports from %d modules (%ld total entries)\n",
           mod_count, (long)g_import_count);
}

static void scan_for_iat_entries(HANDLE hProc, DWORD64 base)
{
    if (g_import_count == 0) return;

    printf("[*] Scanning for IAT entries in process memory...\n");

    char report_path[MAX_PATH];
    snprintf(report_path, sizeof(report_path), "%s\\resolved_imports.txt", g_output_dir);
    FILE *report = fopen(report_path, "w");
    if (!report) return;

    fprintf(report, "=== VMProtect Dumper v4.0 - Resolved Imports ===\n");
    fprintf(report, "=== Scanned from loaded module export tables ===\n\n");

    int written = 0;
    LONG count = g_import_count;
    if (count > MAX_IMPORTS) count = MAX_IMPORTS;

    for (LONG i = 0; i < count; i++) {
        ImportEntry *e = &g_imports[i];
        if (e->function[0] == '\0') continue;

        DWORD slot_rva = 0;
        for (int s = 0; s < g_iat_slot_count; s++) {
            if (g_iat_slots[s].import_idx == (int)i) {
                slot_rva = g_iat_slots[s].slot_rva;
                break;
            }
        }

        if (slot_rva != 0) {
            fprintf(report, "%s!%s = 0x%016llX  @ RVA=0x%08X\n",
                    e->module, e->function,
                    (unsigned long long)e->resolved_addr, slot_rva);
        } else {
            fprintf(report, "%s!%s = 0x%016llX\n",
                    e->module, e->function,
                    (unsigned long long)e->resolved_addr);
        }
        written++;
    }

    fprintf(report, "\n=== Summary ===\n");
    fprintf(report, "Total resolved exports: %d\n", written);
    fprintf(report, "IAT slots mapped: %d\n", g_iat_slot_count);
    fclose(report);

    printf("[+] Import catalog: %d entries -> %s\n", written, report_path);
}

typedef struct {
    DWORD   iat_rva;
    DWORD64 thunk_addr;
    DWORD64 resolved_addr;
    int     import_idx;
    char    module[128];
    char    function[256];
} ResolvedIATEntry;

#define MAX_IAT_RESOLVED 512
static ResolvedIATEntry g_resolved_iat[MAX_IAT_RESOLVED];
static int g_resolved_iat_count = 0;

static DWORD64 follow_thunk_chain(HANDLE hProc, DWORD64 addr, DWORD64 img_base, DWORD img_size)
{
    BYTE code[16];
    SIZE_T nr;
    int max_hops = 16;

    for (int hop = 0; hop < max_hops; hop++) {

        if (addr < img_base || addr >= img_base + img_size)
            return addr;

        if (!ReadProcessMemory(hProc, (LPCVOID)addr, code, sizeof(code), &nr) || nr < 6)
            return 0;

        if (code[0] == 0xFF && code[1] == 0x25) {
            DWORD target_ptr;
#ifdef _WIN64

            DWORD disp = *(DWORD*)(code + 2);
            target_ptr = 0;
            DWORD64 ptr_addr = addr + 6 + (INT32)disp;
            DWORD64 final;
            if (!ReadProcessMemory(hProc, (LPCVOID)ptr_addr, &final, 8, &nr))
                return 0;
            addr = final;
#else

            DWORD ptr_addr = *(DWORD*)(code + 2);
            DWORD final;
            if (!ReadProcessMemory(hProc, (LPCVOID)(DWORD64)ptr_addr, &final, 4, &nr))
                return 0;
            addr = (DWORD64)final;
#endif
            continue;
        }

        if (code[0] == 0xE9) {
            INT32 rel = *(INT32*)(code + 1);
            addr = addr + 5 + rel;
            continue;
        }

        if (code[0] == 0xEB) {
            INT8 rel = (INT8)code[1];
            addr = addr + 2 + rel;
            continue;
        }

        if (code[0] == 0x68 && code[5] == 0xC3) {
            DWORD target = *(DWORD*)(code + 1);
            addr = (DWORD64)target;
            continue;
        }

        if (code[0] == 0xFF && (code[1] >= 0xE0 && code[1] <= 0xE7))
            return 0;

        return addr;
    }

    return 0;
}

static void resolve_iat_thunks(HANDLE hProc, DWORD64 base)
{
    BYTE hdr[4096];
    SIZE_T nr;
    if (!ReadProcessMemory(hProc, (LPCVOID)base, hdr, sizeof(hdr), &nr) || nr < 256)
        return;

    DWORD pe_off = *(DWORD*)(hdr + 0x3C);
    BYTE *pe = hdr + pe_off;
    WORD machine = *(WORD*)(pe + 4);

    int dd_base = (machine == 0x8664) ? (24 + 112) : (24 + 96);
    DWORD iat_rva  = *(DWORD*)(pe + dd_base + 8*12);
    DWORD iat_size = *(DWORD*)(pe + dd_base + 8*12 + 4);

    if (iat_rva == 0 || iat_size == 0) {
        printf("[!] No IAT data directory found\n");
        return;
    }

    int ptr_size = (machine == 0x8664) ? 8 : 4;
    int num_slots = (int)(iat_size / ptr_size);
    if (num_slots > MAX_IAT_RESOLVED) num_slots = MAX_IAT_RESOLVED;

    DWORD img_size = g_size_of_image;
    if (img_size == 0) img_size = 0x1000000;

    printf("\n[*] Resolving IAT thunks (IAT at RVA=0x%08X, %d slots)...\n",
           (unsigned)iat_rva, num_slots);

    BYTE *iat_buf = (BYTE*)malloc(iat_size);
    if (!iat_buf) return;
    if (!ReadProcessMemory(hProc, (LPCVOID)(base + iat_rva), iat_buf, iat_size, &nr)) {
        free(iat_buf);
        printf("[-] Cannot read IAT\n");
        return;
    }

    int resolved_count = 0;
    int thunk_count = 0;
    int direct_count = 0;
    LONG imp_count = g_import_count;
    if (imp_count > MAX_IMPORTS) imp_count = MAX_IMPORTS;

    for (int i = 0; i < num_slots; i++) {
        DWORD64 slot_val;
        if (ptr_size == 8)
            slot_val = *(DWORD64*)(iat_buf + i * ptr_size);
        else
            slot_val = *(DWORD*)(iat_buf + i * ptr_size);

        if (slot_val == 0) continue;

        DWORD slot_rva = iat_rva + i * ptr_size;
        int is_internal = (slot_val >= base && slot_val < base + img_size);

        DWORD64 final_addr = slot_val;
        if (is_internal) {

            final_addr = follow_thunk_chain(hProc, slot_val, base, img_size);
            if (final_addr != 0 && final_addr != slot_val)
                thunk_count++;
        } else {
            direct_count++;
        }

        if (final_addr == 0 || (final_addr >= base && final_addr < base + img_size))
            continue;

        int match_idx = -1;
        for (LONG j = 0; j < imp_count; j++) {
            if (g_imports[j].resolved_addr == final_addr) {
                match_idx = (int)j;
                break;
            }
        }

        if (g_resolved_iat_count < MAX_IAT_RESOLVED) {
            ResolvedIATEntry *re = &g_resolved_iat[g_resolved_iat_count];
            re->iat_rva = slot_rva;
            re->thunk_addr = slot_val;
            re->resolved_addr = final_addr;
            re->import_idx = match_idx;
            if (match_idx >= 0) {
                strncpy(re->module, g_imports[match_idx].module, sizeof(re->module) - 1);
                strncpy(re->function, g_imports[match_idx].function, sizeof(re->function) - 1);
            } else {
                re->module[0] = '\0';
                re->function[0] = '\0';
            }
            g_resolved_iat_count++;
            resolved_count++;
        }
    }

    free(iat_buf);
    printf("[+] IAT resolved: %d entries (%d via thunks, %d direct)\n",
           resolved_count, thunk_count, direct_count);
    if (resolved_count > 0) {
        int named = 0;
        for (int i = 0; i < g_resolved_iat_count; i++)
            if (g_resolved_iat[i].import_idx >= 0) named++;
        printf("[+] Named imports: %d of %d resolved entries\n", named, resolved_count);
    }
}

static void patch_dumped_iat(const char *target_name)
{
    if (g_resolved_iat_count == 0) return;

    const char *bname = strrchr(target_name, '\\');
    if (!bname) bname = strrchr(target_name, '/');
    if (bname) bname++; else bname = target_name;

    char fname[MAX_PATH];
    snprintf(fname, sizeof(fname), "%s\\%s_dumped.bin", g_output_dir, bname);

    FILE *f = fopen(fname, "r+b");
    if (!f) {
        printf("[-] Cannot open dump for IAT patching: %s\n", fname);
        return;
    }

    int ptr_size = (g_machine == 0x8664) ? 8 : 4;
    int patched = 0;

    for (int i = 0; i < g_resolved_iat_count; i++) {
        ResolvedIATEntry *re = &g_resolved_iat[i];

        if (re->resolved_addr == re->thunk_addr) continue;
        if (re->resolved_addr == 0) continue;

        if (fseek(f, (long)re->iat_rva, SEEK_SET) != 0) continue;

        if (ptr_size == 8) {
            DWORD64 val = re->resolved_addr;
            fwrite(&val, 8, 1, f);
        } else {
            DWORD val = (DWORD)re->resolved_addr;
            fwrite(&val, 4, 1, f);
        }
        patched++;
    }

    fclose(f);

    if (patched > 0)
        printf("[+] IAT patched: %d entries written to %s\n", patched, fname);
    else
        printf("[!] No IAT entries needed patching\n");
}

static void scan_iat_slots(HANDLE hProc, DWORD64 base)
{
    LONG imp_count = g_import_count;
    if (imp_count == 0 || imp_count > MAX_IMPORTS) return;

    printf("\n[*] Scanning PE sections for IAT pointer slots...\n");

    #define HASH_BUCKETS 65536
    BYTE *hash_set = (BYTE*)calloc(HASH_BUCKETS / 8, 1);
    if (!hash_set) return;

    for (LONG i = 0; i < imp_count; i++) {
        WORD h = (WORD)(g_imports[i].resolved_addr & 0xFFFF);
        hash_set[h / 8] |= (1 << (h & 7));
    }

    int ptr_size = (g_machine == 0x8664) ? 8 : 4;
    g_iat_slot_count = 0;

    for (int si = 0; si < g_num_sections; si++) {
        SectionInfo *sec = &g_sections[si];
        if (sec->vsize == 0) continue;

        DWORD scan_size = sec->vsize;
        if (scan_size > 4 * 1024 * 1024) scan_size = 4 * 1024 * 1024;

        BYTE *buf = (BYTE*)malloc(scan_size);
        if (!buf) continue;
        memset(buf, 0, scan_size);
        SIZE_T nread;
        ReadProcessMemory(hProc, (LPCVOID)(base + sec->rva), buf, scan_size, &nread);

        for (DWORD off = 0; off + ptr_size <= scan_size; off += ptr_size) {
            DWORD64 val;
            if (ptr_size == 8)
                val = *(DWORD64*)(buf + off);
            else
                val = *(DWORD*)(buf + off);

            if (val == 0) continue;

            WORD h = (WORD)(val & 0xFFFF);
            if (!(hash_set[h / 8] & (1 << (h & 7)))) continue;

            for (LONG j = 0; j < imp_count; j++) {
                if (g_imports[j].resolved_addr == val) {
                    if (g_iat_slot_count < MAX_IAT_SLOTS) {
                        g_iat_slots[g_iat_slot_count].slot_rva = sec->rva + off;
                        g_iat_slots[g_iat_slot_count].import_idx = (int)j;
                        g_iat_slot_count++;
                    }
                    break;
                }
            }
        }
        free(buf);
    }

    free(hash_set);
    printf("[+] IAT slots found: %d pointer entries in PE sections\n", g_iat_slot_count);
}

static void json_escape(FILE *f, const char *s)
{
    while (*s) {
        if (*s == '"') fprintf(f, "\\\"");
        else if (*s == '\\') fprintf(f, "\\\\");
        else fputc(*s, f);
        s++;
    }
}

static void write_dump_metadata(HANDLE hProc, DWORD64 base, const char *target_name)
{
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s\\dump_metadata.json", g_output_dir);
    FILE *f = fopen(path, "w");
    if (!f) return;

    BYTE hdr[4096];
    SIZE_T nr;
    DWORD dd_import_rva = 0, dd_import_size = 0;
    DWORD dd_iat_rva = 0, dd_iat_size = 0;
    DWORD dd_tls_rva = 0, dd_tls_size = 0;
    DWORD dd_reloc_rva = 0, dd_reloc_size = 0;
    DWORD dd_rsrc_rva = 0, dd_rsrc_size = 0;
    DWORD sec_align = 0x1000, file_align = 0x1000;
    DWORD entry_rva = 0;

    if (ReadProcessMemory(hProc, (LPCVOID)base, hdr, sizeof(hdr), &nr) && nr >= 256) {
        DWORD pe_off = *(DWORD*)(hdr + 0x3C);
        BYTE *pe = hdr + pe_off;
        entry_rva = *(DWORD*)(pe + 24 + 16);
        sec_align = *(DWORD*)(pe + 24 + 32);
        file_align = *(DWORD*)(pe + 24 + 36);

        int dd_base = (g_machine == 0x8664) ? (24 + 112) : (24 + 96);

        dd_import_rva  = *(DWORD*)(pe + dd_base + 8*1);
        dd_import_size = *(DWORD*)(pe + dd_base + 8*1 + 4);
        dd_rsrc_rva    = *(DWORD*)(pe + dd_base + 8*2);
        dd_rsrc_size   = *(DWORD*)(pe + dd_base + 8*2 + 4);
        dd_reloc_rva   = *(DWORD*)(pe + dd_base + 8*5);
        dd_reloc_size  = *(DWORD*)(pe + dd_base + 8*5 + 4);
        dd_tls_rva     = *(DWORD*)(pe + dd_base + 8*9);
        dd_tls_size    = *(DWORD*)(pe + dd_base + 8*9 + 4);
        dd_iat_rva     = *(DWORD*)(pe + dd_base + 8*12);
        dd_iat_size    = *(DWORD*)(pe + dd_base + 8*12 + 4);
    }

    fprintf(f, "{\n");
    fprintf(f, "  \"dumper_version\": \"4.0\",\n");
    fprintf(f, "  \"machine\": \"0x%04X\",\n", g_machine);
    fprintf(f, "  \"image_base\": \"0x%llX\",\n", (unsigned long long)base);
    fprintf(f, "  \"size_of_image\": \"0x%X\",\n", g_size_of_image);
    fprintf(f, "  \"original_entry_rva\": \"0x%08X\",\n", entry_rva);
    fprintf(f, "  \"oep_rva\": \"0x%08X\",\n", g_oep_rva);
    fprintf(f, "  \"oep_captured\": %s,\n", g_oep_captured ? "true" : "false");
    fprintf(f, "  \"oep_thread_rva\": \"0x%08X\",\n", g_oep_thread_rva);
    fprintf(f, "  \"oep_crt_rva\": \"0x%08X\",\n", g_oep_crt_rva);
    fprintf(f, "  \"section_alignment\": %u,\n", sec_align);
    fprintf(f, "  \"file_alignment\": %u,\n", sec_align);

    fprintf(f, "  \"sections\": [\n");
    for (int i = 0; i < g_num_sections; i++) {
        SectionInfo *si = &g_sections[i];
        fprintf(f, "    {\"name\": \"");
        json_escape(f, si->name);
        fprintf(f, "\", \"rva\": \"0x%08X\", \"virtual_size\": \"0x%08X\", "
                   "\"raw_size\": \"0x%08X\", \"characteristics\": \"0x%08X\", "
                   "\"was_zeroed\": %s, \"was_changed\": %s, \"nz_bytes\": %d}%s\n",
                si->rva, si->vsize, si->raw_size, si->characteristics,
                si->was_zeroed ? "true" : "false",
                si->changed ? "true" : "false",
                si->nz_bytes,
                (i < g_num_sections - 1) ? "," : "");
    }
    fprintf(f, "  ],\n");

    fprintf(f, "  \"data_directories\": {\n");
    fprintf(f, "    \"import\": {\"rva\": \"0x%08X\", \"size\": \"0x%08X\"},\n",
            dd_import_rva, dd_import_size);
    fprintf(f, "    \"iat\": {\"rva\": \"0x%08X\", \"size\": \"0x%08X\"},\n",
            dd_iat_rva, dd_iat_size);
    fprintf(f, "    \"tls\": {\"rva\": \"0x%08X\", \"size\": \"0x%08X\"},\n",
            dd_tls_rva, dd_tls_size);
    fprintf(f, "    \"reloc\": {\"rva\": \"0x%08X\", \"size\": \"0x%08X\"},\n",
            dd_reloc_rva, dd_reloc_size);
    fprintf(f, "    \"resource\": {\"rva\": \"0x%08X\", \"size\": \"0x%08X\"}\n",
            dd_rsrc_rva, dd_rsrc_size);
    fprintf(f, "  },\n");

    LONG imp_count = g_import_count;
    if (imp_count > MAX_IMPORTS) imp_count = MAX_IMPORTS;
    fprintf(f, "  \"imports_resolved\": %ld,\n", (long)imp_count);
    fprintf(f, "  \"iat_slots_found\": %d,\n", g_iat_slot_count);
    fprintf(f, "  \"iat_thunks_resolved\": %d,\n", g_resolved_iat_count);

    fprintf(f, "  \"resolved_iat\": [\n");
    for (int i = 0; i < g_resolved_iat_count; i++) {
        ResolvedIATEntry *re = &g_resolved_iat[i];
        fprintf(f, "    {\"iat_rva\": \"0x%08X\", \"thunk_addr\": \"0x%llX\", "
                   "\"resolved_addr\": \"0x%llX\"",
                re->iat_rva,
                (unsigned long long)re->thunk_addr,
                (unsigned long long)re->resolved_addr);
        if (re->import_idx >= 0) {
            fprintf(f, ", \"module\": \"");
            json_escape(f, re->module);
            fprintf(f, "\", \"function\": \"");
            json_escape(f, re->function);
            fprintf(f, "\"");
        }
        fprintf(f, "}%s\n", (i < g_resolved_iat_count - 1) ? "," : "");
    }
    fprintf(f, "  ],\n");

    fprintf(f, "  \"iat_slots\": [\n");
    for (int i = 0; i < g_iat_slot_count; i++) {
        IATSlotEntry *sl = &g_iat_slots[i];
        ImportEntry *imp = &g_imports[sl->import_idx];
        fprintf(f, "    {\"slot_rva\": \"0x%08X\", \"module\": \"", sl->slot_rva);
        json_escape(f, imp->module);
        fprintf(f, "\", \"function\": \"");
        json_escape(f, imp->function);
        fprintf(f, "\"}%s\n", (i < g_iat_slot_count - 1) ? "," : "");
    }
    fprintf(f, "  ]\n");

    fprintf(f, "}\n");
    fclose(f);
    printf("[+] Metadata: %s\n", path);
}

static void scan_process_strings(HANDLE hProc)
{
    printf("\n[*] Scanning process memory for config strings & IOCs...\n");

    char report_path[MAX_PATH];
    snprintf(report_path, sizeof(report_path), "%s\\extracted_strings.txt", g_output_dir);
    FILE *report = fopen(report_path, "w");
    if (!report) {
        printf("[-] Cannot create string report\n");
        return;
    }

    fprintf(report, "=== VMProtect Dumper v4.0 - Extracted Strings ===\n\n");

    MEMORY_BASIC_INFORMATION mbi;
    DWORD64 addr = 0x10000;
    int total_regions = 0;
    int total_strings = 0;
    int ioc_count = 0;

    BYTE *page_buf = (BYTE*)malloc(0x10000);
    if (!page_buf) { fclose(report); return; }

    while (addr < 0x7FFFFFFEFFFF) {
        if (!VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi)))
            break;

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
                           PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)))
        {
            DWORD64 region_base = (DWORD64)mbi.BaseAddress;
            SIZE_T region_size = mbi.RegionSize;

            if (region_size > 4 * 1024 * 1024)
                region_size = 4 * 1024 * 1024;

            total_regions++;

            for (SIZE_T off = 0; off < region_size; off += 0x10000) {
                SIZE_T read_sz = (region_size - off < 0x10000) ? (region_size - off) : 0x10000;
                SIZE_T nread = 0;
                if (!ReadProcessMemory(hProc, (LPCVOID)(region_base + off),
                                      page_buf, read_sz, &nread) || nread == 0)
                    continue;

                int str_start = -1;
                for (SIZE_T i = 0; i <= nread; i++) {
                    int printable = (i < nread) &&
                                   (page_buf[i] >= 0x20 && page_buf[i] < 0x7F);
                    if (printable && str_start < 0)
                        str_start = (int)i;
                    else if (!printable && str_start >= 0) {
                        int len = (int)i - str_start;
                        if (len >= MIN_STR_LEN && len < MAX_STR_LEN) {
                            char tmp[MAX_STR_LEN];
                            memcpy(tmp, page_buf + str_start, len);
                            tmp[len] = '\0';
                            const char *cat = categorize_string(tmp);
                            if (cat) {
                                DWORD64 saddr = region_base + off + str_start;
                                fprintf(report, "[%-12s] 0x%016llX: %s\n",
                                        cat, (unsigned long long)saddr, tmp);
                                ioc_count++;
                                if (strcmp(cat, "btc_wallet") == 0 ||
                                    strcmp(cat, "onion_url") == 0 ||
                                    strcmp(cat, "url") == 0 ||
                                    strcmp(cat, "email") == 0 ||
                                    strcmp(cat, "ransom") == 0 ||
                                    strcmp(cat, "mutex") == 0) {
                                    printf("    [%s] %s\n", cat, tmp);
                                }
                            }
                            total_strings++;
                        }
                        str_start = -1;
                    }
                }

                str_start = -1;
                for (SIZE_T i = 0; i + 1 <= nread; i += 2) {
                    int printable = (i + 1 < nread) &&
                                   (page_buf[i] >= 0x20 && page_buf[i] < 0x7F) &&
                                   (page_buf[i + 1] == 0);
                    if (printable && str_start < 0)
                        str_start = (int)i;
                    else if (!printable && str_start >= 0) {
                        int wlen = ((int)i - str_start) / 2;
                        if (wlen >= MIN_STR_LEN && wlen < MAX_STR_LEN) {
                            char tmp[MAX_STR_LEN];
                            for (int k = 0; k < wlen; k++)
                                tmp[k] = page_buf[str_start + k * 2];
                            tmp[wlen] = '\0';
                            const char *cat = categorize_string(tmp);
                            if (cat) {
                                DWORD64 saddr = region_base + off + str_start;
                                fprintf(report, "[%-12s] 0x%016llX W: %s\n",
                                        cat, (unsigned long long)saddr, tmp);
                                ioc_count++;
                                if (strcmp(cat, "btc_wallet") == 0 ||
                                    strcmp(cat, "onion_url") == 0 ||
                                    strcmp(cat, "url") == 0 ||
                                    strcmp(cat, "email") == 0 ||
                                    strcmp(cat, "ransom") == 0 ||
                                    strcmp(cat, "extension") == 0 ||
                                    strcmp(cat, "mutex") == 0) {
                                    printf("    [%s] W: %s\n", cat, tmp);
                                }
                            }
                            total_strings++;
                        }
                        str_start = -1;
                    }
                }
            }
        }

        DWORD64 next = (DWORD64)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }

    fprintf(report, "\n=== Summary ===\n");
    fprintf(report, "Regions scanned: %d\n", total_regions);
    fprintf(report, "Total categorized strings: %d\n", total_strings);
    fprintf(report, "IOCs found: %d\n", ioc_count);
    fclose(report);
    free(page_buf);

    printf("[+] String scan: %d regions, %d IOCs -> %s\n",
           total_regions, ioc_count, report_path);
}

static void capture_dropped_files(const char *target_dir)
{
    printf("\n[*] Scanning for dropped files (ransom notes)...\n");

    WIN32_FIND_DATAA fd;
    char search[MAX_PATH];
    snprintf(search, sizeof(search), "%s\\*", target_dir);

    HANDLE hFind = FindFirstFileA(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    int found = 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        const char *name = fd.cFileName;

        int is_note = 0;
        if (strstr(name, "README") || strstr(name, "readme") ||
            strstr(name, "DECRYPT") || strstr(name, "decrypt") ||
            strstr(name, "RESTORE") || strstr(name, "restore") ||
            strstr(name, "RECOVER") || strstr(name, "recover") ||
            strstr(name, "RANSOM") || strstr(name, "ransom") ||
            strstr(name, "HOW_TO") || strstr(name, "how_to") ||
            strstr(name, "HowTo") || strstr(name, "HELP") ||
            strstr(name, ".hta") || strstr(name, ".html"))
        {
            is_note = 1;
        }
        if (strstr(name, ".txt") || strstr(name, ".TXT"))
            is_note = 1;

        if (is_note) {

            const char *ext = strrchr(name, '.');
            if (ext && (_stricmp(ext, ".exe") == 0 || _stricmp(ext, ".dll") == 0 ||
                        _stricmp(ext, ".scr") == 0 || _stricmp(ext, ".com") == 0)) {
                printf("    Skipped PE: %s (not a ransom note)\n", name);
                continue;
            }

            char src[MAX_PATH], dst[MAX_PATH];
            snprintf(src, sizeof(src), "%s\\%s", target_dir, name);
            snprintf(dst, sizeof(dst), "%s\\%s", g_output_dir, name);

            if (CopyFileA(src, dst, FALSE)) {
                printf("[+] Captured: %s (%lu bytes)\n", name, fd.nFileSizeLow);
                found++;
            }
        }
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);

    if (found == 0) printf("    No ransom notes found in %s\n", target_dir);
}

static void kill_monitor_processes(int kill_vmtools)
{
    printf("[*] Killing monitor programs VMProtect detects...\n");

    const char *monitors[] = {
        "procmon.exe", "procmon64.exe", "Procmon.exe",
        "procexp.exe", "procexp64.exe",
        "wireshark.exe", "Wireshark.exe",
        "fiddler.exe", "Fiddler.exe",
        "tcpview.exe", "tcpview64.exe",
        "autoruns.exe", "autoruns64.exe",
        "filemon.exe", "regmon.exe",
        "ProcessHacker.exe", "processhacker.exe",
        "pestudio.exe", "PEStudio.exe",
        "x64dbg.exe", "x32dbg.exe", "ollydbg.exe",
        "idaq.exe", "idaq64.exe", "ida.exe", "ida64.exe",
        "dumpcap.exe", "rawshark.exe",
        "HookExplorer.exe", "ImportREC.exe",
        "SysInspector.exe", "SysAnalyzer.exe",
        "Sniff_hit.exe", "joeboxcontrol.exe", "joeboxserver.exe",
        "ResourceHacker.exe", "BehaviorDumper.exe",
        "idag.exe", "idag64.exe", "immunitydebugger.exe",
        "agent.exe", "analyzer.exe", "cuckoomon.exe",
        "python.exe", "pythonw.exe",
        "apimonitor.exe", "apimonitor-x86.exe", "apimonitor-x64.exe",
        "OLLYDBG.EXE", "windbg.exe", "dbgview.exe",
        "Dbgview.exe", "DebugView.exe",
        "regshot.exe", "Regshot-x86-Unicode.exe",
        "fakenet.exe", "netmon.exe",
        "petools.exe", "LordPE.exe",
        NULL
    };

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe)) {
            do {
                for (int i = 0; monitors[i]; i++) {
                    if (_stricmp(pe.szExeFile, monitors[i]) == 0) {
                        HANDLE hp = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                        if (hp) {
                            TerminateProcess(hp, 0);
                            CloseHandle(hp);
                            printf("    Killed: %s (PID %u)\n", pe.szExeFile, pe.th32ProcessID);
                        }
                        break;
                    }
                }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }

    if (kill_vmtools) {
        printf("[*] Killing VMware/VBox tools (--kill-vmtools enabled)...\n");
        printf("    WARNING: Shared folders and clipboard will stop working!\n");

        const char *vm_procs[] = {
            "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
            "vmacthlp.exe", "VBoxService.exe", "VBoxTray.exe",
            "VGAuthService.exe", NULL
        };
        HANDLE snap2 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap2 != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe2;
            pe2.dwSize = sizeof(pe2);
            if (Process32First(snap2, &pe2)) {
                do {
                    for (int i = 0; vm_procs[i]; i++) {
                        if (_stricmp(pe2.szExeFile, vm_procs[i]) == 0) {
                            HANDLE hp = OpenProcess(PROCESS_TERMINATE, FALSE, pe2.th32ProcessID);
                            if (hp) { TerminateProcess(hp, 0); CloseHandle(hp); }
                            printf("    Killed: %s\n", pe2.szExeFile);
                            break;
                        }
                    }
                } while (Process32Next(snap2, &pe2));
            }
            CloseHandle(snap2);
        }

        const char *vm_svcs[] = {
            "VMTools", "vm3dservice", "VGAuthService",
            "VMUSBArbService", "vmvss", "VBoxService", NULL
        };
        SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
        if (scm) {
            for (int i = 0; vm_svcs[i]; i++) {
                SC_HANDLE svc = OpenServiceA(scm, vm_svcs[i], SERVICE_STOP | SERVICE_QUERY_STATUS);
                if (svc) {
                    SERVICE_STATUS ss;
                    if (ControlService(svc, SERVICE_CONTROL_STOP, &ss))
                        printf("    Stopped service: %s\n", vm_svcs[i]);
                    CloseServiceHandle(svc);
                }
            }
            CloseServiceHandle(scm);
        }
    } else {
        printf("[*] VMware Tools: kept running (use --kill-vmtools to disable)\n");
    }
}

static void harvest_init(void)
{
    memset(&g_harvest, 0, sizeof(g_harvest));

    g_harvest_watch_count = 0;
    char buf[MAX_PATH];
    if (ExpandEnvironmentStringsA("%USERPROFILE%\\Desktop", buf, MAX_PATH))
        strncpy(g_harvest_watch_dirs[g_harvest_watch_count++], buf, MAX_PATH - 1);
    if (ExpandEnvironmentStringsA("%TEMP%", buf, MAX_PATH))
        strncpy(g_harvest_watch_dirs[g_harvest_watch_count++], buf, MAX_PATH - 1);
    if (ExpandEnvironmentStringsA("%APPDATA%", buf, MAX_PATH))
        strncpy(g_harvest_watch_dirs[g_harvest_watch_count++], buf, MAX_PATH - 1);
    if (ExpandEnvironmentStringsA("%LOCALAPPDATA%", buf, MAX_PATH))
        strncpy(g_harvest_watch_dirs[g_harvest_watch_count++], buf, MAX_PATH - 1);
    if (ExpandEnvironmentStringsA("%PROGRAMDATA%", buf, MAX_PATH))
        strncpy(g_harvest_watch_dirs[g_harvest_watch_count++], buf, MAX_PATH - 1);
}

static void harvest_log(const char *fmt, ...)
{
    if (g_harvest.timeline_count >= 64) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_harvest.timeline[g_harvest.timeline_count],
              sizeof(g_harvest.timeline[0]), fmt, ap);
    va_end(ap);
    g_harvest.timeline_count++;
}

static int is_module_region(HANDLE hProc, DWORD64 addr)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                           GetProcessId(hProc));
    if (snap == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32 me;
    me.dwSize = sizeof(me);
    int found = 0;

    if (Module32First(snap, &me)) {
        do {
            DWORD64 mod_base = (DWORD64)(ULONG_PTR)me.modBaseAddr;
            DWORD64 mod_end  = mod_base + me.modBaseSize;
            if (addr >= mod_base && addr < mod_end) {
                found = 1;
                break;
            }
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

static int take_region_snapshot(HANDLE hProc, DWORD64 image_base, DWORD soi)
{

    memcpy(&g_harvest.previous, &g_harvest.current, sizeof(RegionSnapshot));
    memset(&g_harvest.current, 0, sizeof(RegionSnapshot));
    g_harvest.current.index = g_harvest.previous.index + 1;
    g_harvest.current.tick_ms = GetTickCount();

    MEMORY_BASIC_INFORMATION mbi;
    DWORD64 addr = 0x10000;
    DWORD64 pe_end = image_base + soi;
    int count = 0;

#ifdef _WIN64
    DWORD64 max_addr = (g_machine == 0x14c) ? (DWORD64)0x7FFF0000ULL
                                              : (DWORD64)0x7FFFFFFFFFFFULL;
#else
    DWORD64 max_addr = (DWORD64)0x7FFF0000;
#endif

    while (addr < max_addr && count < MAX_DYNAMIC_REGIONS) {
        if (!VirtualQueryEx(hProc, (LPCVOID)(ULONG_PTR)addr, &mbi, sizeof(mbi)))
            break;

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        {
            DWORD64 rbase = (DWORD64)(ULONG_PTR)mbi.BaseAddress;
            SIZE_T  rsize = mbi.RegionSize;

            int inside_pe = (rbase >= image_base && rbase < pe_end);

            int is_mod = 0;
            if (!inside_pe) {
                is_mod = is_module_region(hProc, rbase);
            }

            int is_own_cave = (g_hook_cave != 0 && rbase >= g_hook_cave &&
                               rbase < g_hook_cave + HOOK_TOTAL_SIZE);

            if (!inside_pe && !is_mod && !is_own_cave) {
                DynamicRegion *dr = &g_harvest.current.regions[count];
                dr->base_addr = rbase;
                dr->size = rsize;
                dr->protect = mbi.Protect;
                dr->dumped = 0;
                dr->fp_changed = 0;

                SIZE_T nread = 0;
                ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)rbase,
                                  dr->fingerprint, REGION_FP_SIZE, &nread);

                int was_known = 0;
                for (int i = 0; i < g_harvest.previous.count; i++) {
                    if (g_harvest.previous.regions[i].base_addr == rbase) {
                        dr->snapshot_first = g_harvest.previous.regions[i].snapshot_first;
                        was_known = 1;

                        if (memcmp(dr->fingerprint,
                                   g_harvest.previous.regions[i].fingerprint,
                                   REGION_FP_SIZE) != 0) {
                            dr->fp_changed = 1;
                        }
                        break;
                    }
                }
                if (!was_known) {
                    dr->snapshot_first = g_harvest.current.index;
                }
                dr->snapshot_last = g_harvest.current.index;

                if (!was_known && g_harvest.all_seen_count < MAX_DYNAMIC_REGIONS * 2) {
                    memcpy(&g_harvest.all_seen[g_harvest.all_seen_count],
                           dr, sizeof(DynamicRegion));
                    g_harvest.all_seen_count++;
                }

                count++;
            }
        }

        DWORD64 next = (DWORD64)(ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }

    g_harvest.current.count = count;
    return count;
}

static int check_region_changes(void)
{
    int new_count = 0, disappeared = 0, fp_changes = 0;

    for (int i = 0; i < g_harvest.current.count; i++) {
        DynamicRegion *cr = &g_harvest.current.regions[i];
        int found = 0;
        for (int j = 0; j < g_harvest.previous.count; j++) {
            if (g_harvest.previous.regions[j].base_addr == cr->base_addr) {
                found = 1;
                break;
            }
        }
        if (!found) {
            new_count++;
            printf("[!] HARVEST: NEW exec region " ADDR_FMT " (%u bytes, prot=0x%X)\n",
                   ADDR_CAST(cr->base_addr), (unsigned)cr->size, cr->protect);
            harvest_log("[T+%.1fs] Snap #%d: NEW region " ADDR_FMT " (%u bytes)",
                        (float)g_harvest.current.tick_ms / 1000.0f,
                        g_harvest.current.index,
                        ADDR_CAST(cr->base_addr), (unsigned)cr->size);
        }
        if (cr->fp_changed) {
            fp_changes++;
            harvest_log("[T+%.1fs] Snap #%d: CHANGED fp at " ADDR_FMT,
                        (float)g_harvest.current.tick_ms / 1000.0f,
                        g_harvest.current.index,
                        ADDR_CAST(cr->base_addr));
        }
    }

    for (int j = 0; j < g_harvest.previous.count; j++) {
        int found = 0;
        for (int i = 0; i < g_harvest.current.count; i++) {
            if (g_harvest.current.regions[i].base_addr ==
                g_harvest.previous.regions[j].base_addr) {
                found = 1;
                break;
            }
        }
        if (!found) {
            disappeared++;
            harvest_log("[T+%.1fs] Snap #%d: DISAPPEARED region " ADDR_FMT,
                        (float)g_harvest.current.tick_ms / 1000.0f,
                        g_harvest.current.index,
                        ADDR_CAST(g_harvest.previous.regions[j].base_addr));
        }
    }

    g_harvest.new_this_cycle = new_count;
    g_harvest.disappeared += disappeared;
    g_harvest.fp_changes += fp_changes;
    return new_count + fp_changes;
}

static int dump_dynamic_regions(HANDLE hProc)
{
    int dumped = 0;

    for (int i = 0; i < g_harvest.all_seen_count; i++) {
        DynamicRegion *dr = &g_harvest.all_seen[i];
        if (dr->dumped) continue;

        char fname[MAX_PATH];
        snprintf(fname, sizeof(fname), "%s\\region_" ADDR_FMT "_%u.bin",
                 g_output_dir, ADDR_CAST(dr->base_addr), (unsigned)dr->size);

        DWORD dump_size = (DWORD)dr->size;
        if (dump_size > 64 * 1024 * 1024) dump_size = 64 * 1024 * 1024;

        BYTE *buf = (BYTE*)malloc(dump_size);
        if (!buf) continue;
        memset(buf, 0, dump_size);

        SIZE_T nread;
        DWORD chunk = 0x1000;
        int has_data = 0;
        for (DWORD off = 0; off < dump_size; off += chunk) {
            DWORD sz = (dump_size - off < chunk) ? (dump_size - off) : chunk;
            if (ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)(dr->base_addr + off),
                                  buf + off, sz, &nread) && nread > 0) {
                has_data = 1;
            }
        }

        if (has_data) {
            FILE *f = fopen(fname, "wb");
            if (f) {
                fwrite(buf, 1, dump_size, f);
                fclose(f);
                printf("[+] Region dump: " ADDR_FMT " (%u bytes) -> %s\n",
                       ADDR_CAST(dr->base_addr), dump_size, fname);
                dumped++;
            }
        }

        dr->dumped = 1;
        free(buf);
    }

    for (int i = 0; i < g_harvest.current.count; i++) {
        DynamicRegion *cr = &g_harvest.current.regions[i];

        int already = 0;
        for (int j = 0; j < g_harvest.all_seen_count; j++) {
            if (g_harvest.all_seen[j].base_addr == cr->base_addr &&
                g_harvest.all_seen[j].dumped) {
                already = 1;
                break;
            }
        }
        if (already) continue;

        char fname[MAX_PATH];
        snprintf(fname, sizeof(fname), "%s\\region_" ADDR_FMT "_%u.bin",
                 g_output_dir, ADDR_CAST(cr->base_addr), (unsigned)cr->size);

        DWORD dump_size = (DWORD)cr->size;
        if (dump_size > 64 * 1024 * 1024) dump_size = 64 * 1024 * 1024;

        BYTE *buf = (BYTE*)malloc(dump_size);
        if (!buf) continue;
        memset(buf, 0, dump_size);

        SIZE_T nread;
        DWORD chunk = 0x1000;
        int has_data = 0;
        for (DWORD off = 0; off < dump_size; off += chunk) {
            DWORD sz = (dump_size - off < chunk) ? (dump_size - off) : chunk;
            if (ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)(cr->base_addr + off),
                                  buf + off, sz, &nread) && nread > 0) {
                has_data = 1;
            }
        }

        if (has_data) {
            FILE *f = fopen(fname, "wb");
            if (f) {
                fwrite(buf, 1, dump_size, f);
                fclose(f);
                printf("[+] Region dump: " ADDR_FMT " (%u bytes) -> %s\n",
                       ADDR_CAST(cr->base_addr), dump_size, fname);
                dumped++;
            }
        }
        free(buf);
    }

    if (dumped > 0)
        printf("[+] Total dynamic regions dumped: %d\n", dumped);
    else
        printf("[*] No dynamic executable regions found outside PE image\n");

    return dumped;
}

static void detect_pesieve_path(void)
{
    if (g_harvest.pesieve_path[0] != '\0') return;

    const char *p64 = "C:\\Tools\\pe-sieve64.exe";
    const char *p32 = "C:\\Tools\\pe-sieve32.exe";
    const char *preferred = (g_machine == 0x14c) ? p32 : p64;
    const char *fallback  = (g_machine == 0x14c) ? p64 : p32;

    DWORD attr = GetFileAttributesA(preferred);
    if (attr != INVALID_FILE_ATTRIBUTES) {
        strncpy(g_harvest.pesieve_path, preferred, MAX_PATH - 1);
    } else {
        attr = GetFileAttributesA(fallback);
        if (attr != INVALID_FILE_ATTRIBUTES)
            strncpy(g_harvest.pesieve_path, fallback, MAX_PATH - 1);
    }

    if (g_harvest.pesieve_path[0] != '\0')
        printf("[+] PE-sieve found: %s\n", g_harvest.pesieve_path);
    else
        printf("[!] PE-sieve not found at C:\\Tools\\ (optional, skipping)\n");
}

static int run_pesieve(DWORD target_pid)
{
    if (g_harvest.pesieve_path[0] == '\0') return 0;

    char pesieve_outdir[MAX_PATH];
    snprintf(pesieve_outdir, sizeof(pesieve_outdir), "%s\\pesieve_out", g_output_dir);
    CreateDirectoryA(pesieve_outdir, NULL);

    char cmdline[MAX_PATH * 3];
    snprintf(cmdline, sizeof(cmdline),
             "\"%s\" /pid %u /dir \"%s\" /shellc /iat 3 /dmode 1 /quiet",
             g_harvest.pesieve_path, target_pid, pesieve_outdir);

    printf("\n[*] Running PE-sieve: pid=%u\n", target_pid);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                        0, NULL, NULL, &si, &pi)) {
        printf("[-] PE-sieve launch failed (error %u)\n", (unsigned)GetLastError());
        return 0;
    }

    DWORD wait = WaitForSingleObject(pi.hProcess, PESIEVE_TIMEOUT_MS);
    if (wait == WAIT_TIMEOUT) {
        printf("[!] PE-sieve timed out, terminating\n");
        TerminateProcess(pi.hProcess, 1);
    }

    DWORD ec = 0;
    GetExitCodeProcess(pi.hProcess, &ec);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    g_harvest.pesieve_ran = 1;
    g_harvest.pesieve_exit_code = (int)ec;

    char search[MAX_PATH];
    snprintf(search, sizeof(search), "%s\\*", pesieve_outdir);
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(search, &fd);
    int fc = 0;
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) fc++;
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
    g_harvest.pesieve_file_count = fc;
    printf("[+] PE-sieve done (exit=%u, %d files in pesieve_out)\n", (unsigned)ec, fc);
    return 1;
}

static int check_behavioral_trigger(void)
{
    int new_files = 0;
    for (int d = 0; d < g_harvest_watch_count; d++) {
        char search[MAX_PATH];
        snprintf(search, sizeof(search), "%s\\*", g_harvest_watch_dirs[d]);
        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA(search, &fd);
        if (hFind == INVALID_HANDLE_VALUE) continue;
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

            FILETIME ft = fd.ftCreationTime;
            ULARGE_INTEGER ul;
            ul.LowPart = ft.dwLowDateTime;
            ul.HighPart = ft.dwHighDateTime;

            FILETIME now_ft;
            GetSystemTimeAsFileTime(&now_ft);
            ULARGE_INTEGER now_ul;
            now_ul.LowPart = now_ft.dwLowDateTime;
            now_ul.HighPart = now_ft.dwHighDateTime;
            if (now_ul.QuadPart - ul.QuadPart < 300000000ULL) {
                new_files++;
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }

    if (new_files > 0 && !g_harvest.behavioral_trigger) {
        g_harvest.behavioral_trigger = 1;
        g_harvest.new_file_count = new_files;
        printf("[!] HARVEST: Behavioral trigger - %d new files in watched dirs\n", new_files);
        harvest_log("[T+%.1fs] BEHAVIORAL: %d new files detected",
                    (float)GetTickCount() / 1000.0f, new_files);
    }
    return new_files;
}

static void write_harvest_report(DWORD total_elapsed_ms)
{
    char rpath[MAX_PATH];
    snprintf(rpath, sizeof(rpath), "%s\\harvest_report.txt", g_output_dir);

    FILE *f = fopen(rpath, "w");
    if (!f) return;

    fprintf(f, "=== Clarity Memory Harvester v5.0 Report ===\n");
    fprintf(f, "Target architecture: %s\n", (g_machine == 0x14c) ? "x86" : "x64");
    fprintf(f, "Image base: 0x%llX\n", (unsigned long long)g_image_base);
    fprintf(f, "Size of image: 0x%08X\n", g_size_of_image);
    fprintf(f, "Total analysis time: %.1f seconds\n", (float)total_elapsed_ms / 1000.0f);
    fprintf(f, "Harvest mode: %s\n\n", g_harvest_enabled ? "enabled" : "disabled");

    fprintf(f, "=== Region Timeline ===\n");
    for (int i = 0; i < g_harvest.timeline_count; i++)
        fprintf(f, "%s\n", g_harvest.timeline[i]);
    if (g_harvest.timeline_count == 0)
        fprintf(f, "(no events recorded)\n");

    fprintf(f, "\n=== Dynamic Region Summary ===\n");
    fprintf(f, "Total unique regions tracked: %d\n", g_harvest.all_seen_count);
    fprintf(f, "Regions at final snapshot: %d\n", g_harvest.current.count);
    fprintf(f, "Disappeared regions: %d\n", g_harvest.disappeared);
    fprintf(f, "Fingerprint changes observed: %d\n", g_harvest.fp_changes);
    fprintf(f, "Behavioral trigger: %s (%d new files)\n",
            g_harvest.behavioral_trigger ? "yes" : "no", g_harvest.new_file_count);

    fprintf(f, "\n=== PE-sieve Results ===\n");
    if (g_harvest.pesieve_ran) {
        fprintf(f, "PE-sieve path: %s\n", g_harvest.pesieve_path);
        fprintf(f, "Exit code: %d\n", g_harvest.pesieve_exit_code);
        fprintf(f, "Output files: %d\n", g_harvest.pesieve_file_count);
    } else {
        fprintf(f, "PE-sieve: not executed\n");
    }

    fprintf(f, "\n=== Section Status ===\n");
    for (int i = 0; i < g_num_sections; i++) {
        SectionInfo *si = &g_sections[i];
        fprintf(f, "%-12s RVA=0x%08X  changed=%s\n",
                si->name, si->rva, si->changed ? "yes" : "no");
    }

    if (g_harvest.all_seen_count == 0 && !g_harvest.pesieve_ran) {
        fprintf(f, "\n=== Note ===\n");
        fprintf(f, "No dynamic executable regions found outside PE image.\n");
        fprintf(f, "If section fingerprints also didn't change, the sample may use\n");
        fprintf(f, "VMProtect code virtualization (VM bytecode, not decryptable).\n");
    }

    fclose(f);
    printf("[+] Harvest report: %s\n", rpath);
}

static void dump_all(HANDLE hProc, DWORD64 base, const char *target_name)
{
    printf("\n[*] Dumping all sections:\n");
    for (int i = 0; i < g_num_sections; i++)
        dump_section(hProc, base, &g_sections[i], i);

    dump_full_image(hProc, base, target_name);
    reconstruct_iat(hProc, base);
    rebuild_imports_vid(hProc, base, target_name);
    resolve_iat_thunks(hProc, base);
    patch_dumped_iat(target_name);
    scan_iat_slots(hProc, base);
    scan_for_iat_entries(hProc, base);
    write_dump_metadata(hProc, base, target_name);
    scan_process_strings(hProc);

    if (g_harvest_enabled) {
        printf("\n[*] Memory Harvester: dumping dynamic executable regions...\n");
        dump_dynamic_regions(hProc);
    }
}

static void enable_debug_privilege(void)
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return;
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid)) {
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        if (GetLastError() == ERROR_SUCCESS)
            printf("[+] SeDebugPrivilege enabled\n");
    }
    CloseHandle(hToken);
}

#define SVC_TEMP_NAME "VmpDumpTempSvc"

static HANDLE launch_service_dll(const char *dll_path, DWORD64 *out_dll_base, DWORD *out_pid)
{
    *out_dll_base = 0;
    *out_pid = 0;

    char abs_path[MAX_PATH];
    GetFullPathNameA(dll_path, MAX_PATH, abs_path, NULL);

    printf("[*] Service DLL mode: creating temporary service...\n");

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        printf("[-] OpenSCManager failed (error %u). Run as Administrator!\n",
               (unsigned)GetLastError());
        return NULL;
    }

    SC_HANDLE old_svc = OpenServiceA(scm, SVC_TEMP_NAME, SERVICE_ALL_ACCESS);
    if (old_svc) {
        SERVICE_STATUS ss;
        ControlService(old_svc, SERVICE_CONTROL_STOP, &ss);
        Sleep(500);
        DeleteService(old_svc);
        CloseServiceHandle(old_svc);
        Sleep(500);
    }

    char sys_dir[MAX_PATH];
    GetSystemDirectoryA(sys_dir, MAX_PATH);
    char svchost_cmd[MAX_PATH];
    snprintf(svchost_cmd, sizeof(svchost_cmd),
             "%s\\svchost.exe -k %s", sys_dir, SVC_TEMP_NAME);
    printf("[*] svchost cmd: %s\n", svchost_cmd);

    SC_HANDLE svc = CreateServiceA(
        scm, SVC_TEMP_NAME, SVC_TEMP_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_SHARE_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        svchost_cmd,
        NULL, NULL, NULL, NULL, NULL
    );

    if (!svc) {
        DWORD err = GetLastError();
        printf("[-] CreateService failed (error %u)\n", (unsigned)err);
        if (err == 1073) printf("    Service already exists. Delete it first: sc delete %s\n", SVC_TEMP_NAME);
        CloseServiceHandle(scm);
        return NULL;
    }
    printf("[+] Service created: %s (type=SHARE_PROCESS)\n", SVC_TEMP_NAME);

    char reg_path[MAX_PATH];
    snprintf(reg_path, sizeof(reg_path),
             "SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters", SVC_TEMP_NAME);

    HKEY hKey;
    LONG rc = RegCreateKeyExA(HKEY_LOCAL_MACHINE, reg_path, 0, NULL,
                              REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
    if (rc == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "ServiceDll", 0, REG_EXPAND_SZ,
                       (const BYTE*)abs_path, (DWORD)(strlen(abs_path) + 1));
        RegCloseKey(hKey);
        printf("[+] ServiceDll: %s\n", abs_path);
    } else {
        printf("[-] Cannot create Parameters key (error %ld)\n", rc);
    }

    HKEY hSvcHost;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost",
                      0, KEY_SET_VALUE, &hSvcHost) == ERROR_SUCCESS) {
        int name_len = (int)strlen(SVC_TEMP_NAME);
        char group_val[256];
        memset(group_val, 0, sizeof(group_val));
        memcpy(group_val, SVC_TEMP_NAME, name_len);
        RegSetValueExA(hSvcHost, SVC_TEMP_NAME, 0, REG_MULTI_SZ,
                       (const BYTE*)group_val, (DWORD)(name_len + 2));
        RegCloseKey(hSvcHost);
        printf("[+] Svchost group registered: %s\n", SVC_TEMP_NAME);
    } else {
        printf("[-] Cannot write Svchost group (error %u)\n", (unsigned)GetLastError());
    }

    printf("[*] Starting service (svchost will load the DLL)...\n");
    BOOL started = StartServiceA(svc, 0, NULL);
    if (!started) {
        DWORD err = GetLastError();
        printf("[*] StartService result: error %u", (unsigned)err);
        if (err == 1053) printf(" (timeout - normal for malware, DLL may still be loaded)");
        else if (err == 1056) printf(" (already running)");
        else if (err == 1067) printf(" (process terminated unexpectedly)");
        else if (err == 1058) printf(" (service disabled)");
        else if (err == 2)    printf(" (service not found - registry issue?)");
        printf("\n");
    } else {
        printf("[+] StartService succeeded\n");
    }

    Sleep(1000);

    SERVICE_STATUS_PROCESS ssp;
    DWORD needed = 0;
    DWORD service_pid = 0;
    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                             (LPBYTE)&ssp, sizeof(ssp), &needed)) {
        service_pid = ssp.dwProcessId;
        printf("[+] Service PID: %u  State: %u\n", service_pid, ssp.dwCurrentState);
    } else {
        printf("[!] QueryServiceStatusEx failed (error %u)\n", (unsigned)GetLastError());
    }

    HANDLE hProc = NULL;

    if (service_pid != 0) {
        hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, service_pid);
        if (!hProc) {
            printf("[-] OpenProcess PID=%u failed (error %u)\n",
                   service_pid, (unsigned)GetLastError());
        } else {
            printf("[+] Attached to svchost PID=%u\n", service_pid);

            const char *dll_basename = abs_path;
            const char *p;
            p = strrchr(dll_basename, '\\'); if (p) dll_basename = p + 1;
            p = strrchr(dll_basename, '/');  if (p) dll_basename = p + 1;

            HANDLE modSnap = CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, service_pid);
            if (modSnap != INVALID_HANDLE_VALUE) {
                MODULEENTRY32W me;
                me.dwSize = sizeof(me);
                if (Module32FirstW(modSnap, &me)) {
                    do {
                        char mod_path[MAX_PATH], mod_name[MAX_PATH];
                        WideCharToMultiByte(CP_ACP, 0, me.szExePath, -1,
                                           mod_path, MAX_PATH, NULL, NULL);
                        WideCharToMultiByte(CP_ACP, 0, me.szModule, -1,
                                           mod_name, MAX_PATH, NULL, NULL);

                        if (_stricmp(mod_path, abs_path) == 0 ||
                            _stricmp(mod_name, dll_basename) == 0) {
                            *out_dll_base = (DWORD64)me.modBaseAddr;
                            *out_pid = service_pid;
                            printf("[+] Found DLL at 0x%llX (size: %u)\n",
                                   (unsigned long long)*out_dll_base, me.modBaseSize);
                            printf("    Path: %s\n", mod_path);
                            break;
                        }
                    } while (Module32NextW(modSnap, &me));
                }
                CloseHandle(modSnap);
            } else {
                printf("[!] Module snapshot failed (error %u)\n", (unsigned)GetLastError());
            }

            if (*out_dll_base == 0) {
                printf("[!] DLL not found by name. Scanning for non-system modules...\n");
                modSnap = CreateToolhelp32Snapshot(
                    TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, service_pid);
                if (modSnap != INVALID_HANDLE_VALUE) {
                    MODULEENTRY32W me;
                    me.dwSize = sizeof(me);
                    if (Module32FirstW(modSnap, &me)) {
                        do {
                            char mod_path[MAX_PATH];
                            WideCharToMultiByte(CP_ACP, 0, me.szExePath, -1,
                                               mod_path, MAX_PATH, NULL, NULL);
                            if (_strnicmp(mod_path, sys_dir, strlen(sys_dir)) == 0) continue;
                            if (strstr(mod_path, "\\Windows\\") != NULL) continue;
                            *out_dll_base = (DWORD64)me.modBaseAddr;
                            *out_pid = service_pid;
                            printf("[+] Found non-system module at 0x%llX: %s\n",
                                   (unsigned long long)*out_dll_base, mod_path);
                            break;
                        } while (Module32NextW(modSnap, &me));
                    }
                    CloseHandle(modSnap);
                }
            }
        }
    }

    if (!hProc) {
        printf("[-] Could not find DLL in any svchost process\n");
        printf("    Stopping and removing temporary service...\n");
        SERVICE_STATUS ss;
        ControlService(svc, SERVICE_CONTROL_STOP, &ss);
        DeleteService(svc);
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return NULL;
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return hProc;
}

static void cleanup_temp_service(void)
{
    printf("[*] Cleaning up temporary service...\n");
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) return;

    SC_HANDLE svc = OpenServiceA(scm, SVC_TEMP_NAME, SERVICE_ALL_ACCESS);
    if (svc) {
        SERVICE_STATUS ss;
        ControlService(svc, SERVICE_CONTROL_STOP, &ss);
        Sleep(1000);
        if (DeleteService(svc))
            printf("[+] Service deleted: %s\n", SVC_TEMP_NAME);
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);

    HKEY hSvcHost;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost",
                      0, KEY_SET_VALUE, &hSvcHost) == ERROR_SUCCESS) {
        RegDeleteValueA(hSvcHost, SVC_TEMP_NAME);
        RegCloseKey(hSvcHost);
    }

    char reg_path[MAX_PATH];
    snprintf(reg_path, sizeof(reg_path),
             "SYSTEM\\CurrentControlSet\\Services\\%s", SVC_TEMP_NAME);
    RegDeleteKeyA(HKEY_LOCAL_MACHINE, reg_path);
}

static const char* get_basename(const char *path)
{
    const char *name = path;
    const char *p;
    p = strrchr(name, '\\'); if (p) name = p + 1;
    p = strrchr(name, '/');  if (p) name = p + 1;
    return name;
}

static void get_parent_dir(const char *path, char *out, int out_size)
{
    strncpy(out, path, out_size - 1);
    out[out_size - 1] = '\0';
    char *s = strrchr(out, '\\');
    char *f = strrchr(out, '/');
    if (f > s) s = f;
    if (s) *s = '\0';
    else strcpy(out, ".");
}

static void build_output_dir(const char *target_path)
{
    const char *bn = get_basename(target_path);
    char parent[MAX_PATH];
    get_parent_dir(target_path, parent, sizeof(parent));
    snprintf(g_output_dir, sizeof(g_output_dir),
             "%s\\vmp_dump_%s", parent, bn);
}

#define ZIP_LOCAL_SIG       0x04034b50
#define ZIP_CENTRAL_SIG     0x02014b50
#define ZIP_END_SIG         0x06054b50
#define ZIP_ENC_HDR_SIZE    12
#define ZIP_MAX_FILES       128

static DWORD g_crc_table[256];
static int   g_crc_ready = 0;

static void crc32_init(void)
{
    if (g_crc_ready) return;
    for (DWORD i = 0; i < 256; i++) {
        DWORD c = i;
        for (int j = 0; j < 8; j++)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        g_crc_table[i] = c;
    }
    g_crc_ready = 1;
}

static DWORD crc32_update(DWORD crc, const BYTE *buf, DWORD len)
{
    crc ^= 0xFFFFFFFF;
    for (DWORD i = 0; i < len; i++)
        crc = g_crc_table[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFF;
}

typedef struct { DWORD k0, k1, k2; } ZCKeys;

static void zc_update(ZCKeys *k, BYTE c)
{
    k->k0 = g_crc_table[(k->k0 ^ c) & 0xFF] ^ (k->k0 >> 8);
    k->k1 = (k->k1 + (k->k0 & 0xFF)) * 134775813u + 1;
    k->k2 = g_crc_table[(k->k2 ^ (BYTE)(k->k1 >> 24)) & 0xFF] ^ (k->k2 >> 8);
}

static BYTE zc_stream_byte(ZCKeys *k)
{
    WORD t = (WORD)(k->k2 | 2);
    return (BYTE)((t * (t ^ 1)) >> 8);
}

static BYTE zc_encrypt(ZCKeys *k, BYTE plain)
{
    BYTE cipher = plain ^ zc_stream_byte(k);
    zc_update(k, plain);
    return cipher;
}

static void zc_init_password(ZCKeys *k, const char *pw)
{
    k->k0 = 305419896u; k->k1 = 591751049u; k->k2 = 878082192u;
    while (*pw) zc_update(k, (BYTE)*pw++);
}

static void w16(FILE *f, WORD v)  { fwrite(&v, 2, 1, f); }
static void w32(FILE *f, DWORD v) { fwrite(&v, 4, 1, f); }

typedef struct {
    char  name[MAX_PATH]; WORD name_len;
    DWORD crc, comp_size, raw_size, local_offset;
    WORD  dos_date, dos_time;
} ZipFileEntry;

static char g_zip_path[MAX_PATH] = "";

static int create_password_zip(const char *dump_dir)
{
    char zip_path[MAX_PATH];
    snprintf(zip_path, sizeof(zip_path), "%s.dat", dump_dir);

    printf("\n[*] Creating password-protected archive (pass: virus)...\n");
    printf("    Extension: .dat (safe from ransomware, rename to .zip to extract)\n");

    crc32_init();
    srand((unsigned)GetTickCount());

    ZipFileEntry entries[ZIP_MAX_FILES];
    int num_entries = 0;

    WIN32_FIND_DATAA fd;
    char search[MAX_PATH];
    snprintf(search, sizeof(search), "%s\\*", dump_dir);
    HANDLE hFind = FindFirstFileA(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) { printf("[-] No files to zip\n"); return 0; }
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (num_entries >= ZIP_MAX_FILES) break;
        ZipFileEntry *e = &entries[num_entries];
        strncpy(e->name, fd.cFileName, MAX_PATH - 1); e->name[MAX_PATH - 1] = '\0';
        e->name_len = (WORD)strlen(e->name);
        e->raw_size = fd.nFileSizeLow;
        e->comp_size = e->raw_size + ZIP_ENC_HDR_SIZE;
        e->crc = 0;
        SYSTEMTIME st; GetLocalTime(&st);
        e->dos_time = (WORD)((st.wSecond / 2) | (st.wMinute << 5) | (st.wHour << 11));
        e->dos_date = (WORD)(st.wDay | (st.wMonth << 5) | ((st.wYear - 1980) << 9));
        num_entries++;
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);

    if (num_entries == 0) { printf("[-] No files found\n"); return 0; }

    FILE *zf = fopen(zip_path, "wb");
    if (!zf) { printf("[-] Cannot create %s\n", zip_path); return 0; }

    BYTE io_buf[8192];
    const char *password = "virus";

    for (int i = 0; i < num_entries; i++) {
        ZipFileEntry *e = &entries[i];
        char src[MAX_PATH];
        snprintf(src, sizeof(src), "%s\\%s", dump_dir, e->name);
        FILE *sf = fopen(src, "rb");
        if (!sf) continue;
        DWORD crc = 0;
        for (;;) { DWORD n = (DWORD)fread(io_buf, 1, sizeof(io_buf), sf); if (!n) break; crc = crc32_update(crc, io_buf, n); }
        e->crc = crc;
        e->local_offset = (DWORD)ftell(zf);
        w32(zf, ZIP_LOCAL_SIG); w16(zf, 20); w16(zf, 0x0001); w16(zf, 0);
        w16(zf, e->dos_time); w16(zf, e->dos_date); w32(zf, e->crc);
        w32(zf, e->comp_size); w32(zf, e->raw_size); w16(zf, e->name_len); w16(zf, 0);
        fwrite(e->name, 1, e->name_len, zf);
        ZCKeys keys; zc_init_password(&keys, password);
        BYTE enc_hdr[ZIP_ENC_HDR_SIZE];
        for (int j = 0; j < 11; j++) enc_hdr[j] = zc_encrypt(&keys, (BYTE)(rand() & 0xFF));
        enc_hdr[11] = zc_encrypt(&keys, (BYTE)(e->crc >> 24));
        fwrite(enc_hdr, 1, ZIP_ENC_HDR_SIZE, zf);
        fseek(sf, 0, SEEK_SET);
        for (;;) { DWORD n = (DWORD)fread(io_buf, 1, sizeof(io_buf), sf); if (!n) break; for (DWORD j = 0; j < n; j++) io_buf[j] = zc_encrypt(&keys, io_buf[j]); fwrite(io_buf, 1, n, zf); }
        fclose(sf);
    }
    DWORD cd_offset = (DWORD)ftell(zf);
    for (int i = 0; i < num_entries; i++) {
        ZipFileEntry *e = &entries[i];
        w32(zf, ZIP_CENTRAL_SIG); w16(zf, 20); w16(zf, 20); w16(zf, 0x0001); w16(zf, 0);
        w16(zf, e->dos_time); w16(zf, e->dos_date); w32(zf, e->crc);
        w32(zf, e->comp_size); w32(zf, e->raw_size); w16(zf, e->name_len); w16(zf, 0);
        w16(zf, 0); w16(zf, 0); w16(zf, 0); w32(zf, 0x00000020); w32(zf, e->local_offset);
        fwrite(e->name, 1, e->name_len, zf);
    }
    DWORD cd_size = (DWORD)ftell(zf) - cd_offset;
    w32(zf, ZIP_END_SIG); w16(zf, 0); w16(zf, 0);
    w16(zf, (WORD)num_entries); w16(zf, (WORD)num_entries);
    w32(zf, cd_size); w32(zf, cd_offset); w16(zf, 0);
    DWORD zip_size = (DWORD)ftell(zf);
    fclose(zf);

    strncpy(g_zip_path, zip_path, MAX_PATH - 1);
    printf("[+] Archive created: %s\n", zip_path);
    printf("    %d files, %u bytes\n", num_entries, (unsigned)zip_size);
    printf("    Password: virus\n");
    printf("    To extract: rename .dat -> .zip, then unzip with password\n");
    return 1;
}

#define MAX_WATCH_DIRS      16
#define MAX_SNAPSHOT_FILES   1024
#define MAX_NEW_FILES        64
#define MAX_BASELINE_PIDS    1024
#define MAX_NEW_PIDS         64
#define DROPPER_POLL_MS      500

typedef struct {
    int is_packed;
    int vmp_sections;
    int zeroed_sections;
    int minimal_imports;
    int has_overlay;
    char details[256];
} PackerCheckResult;

typedef struct {
    char path[MAX_PATH];
    DWORD size_low;
} FSEntry;

typedef struct {
    HANDLE  hProcess;
    HANDLE  hThread;
    DWORD   pid;
    DWORD64 image_base;
    char    image_path[MAX_PATH];
} TargetInfo;

static FSEntry  g_fs_snapshot[MAX_SNAPSHOT_FILES];
static int      g_fs_count = 0;
static char     g_watch_dirs[MAX_WATCH_DIRS][MAX_PATH];
static int      g_watch_dir_count = 0;
static char     g_self_path[MAX_PATH] = "";
static DWORD    g_baseline_pids[MAX_BASELINE_PIDS];
static int      g_baseline_pid_count = 0;

static int check_file_for_packer(const char *filepath, PackerCheckResult *result)
{
    memset(result, 0, sizeof(*result));

    FILE *f = fopen(filepath, "rb");
    if (!f) {
        snprintf(result->details, sizeof(result->details), "Cannot open file");
        return 0;
    }

    BYTE hdr[4096];
    size_t nread = fread(hdr, 1, sizeof(hdr), f);

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fclose(f);

    if (nread < 256 || hdr[0] != 'M' || hdr[1] != 'Z') {
        snprintf(result->details, sizeof(result->details), "Not a PE file");
        return 0;
    }

    DWORD pe_off = *(DWORD*)(hdr + 0x3C);
    if (pe_off + 256 > nread) {
        snprintf(result->details, sizeof(result->details), "PE header beyond read range");
        return 0;
    }

    BYTE *pe = hdr + pe_off;
    if (*(DWORD*)pe != 0x00004550) {
        snprintf(result->details, sizeof(result->details), "Invalid PE signature");
        return 0;
    }

    WORD num_secs = *(WORD*)(pe + 6);
    WORD opt_size = *(WORD*)(pe + 20);
    BYTE *sec_tbl = pe + 24 + opt_size;

    DWORD last_section_end = 0;
    for (int i = 0; i < num_secs && i < 32; i++) {
        BYTE *s = sec_tbl + i * 40;
        if ((BYTE*)(s + 40) > hdr + nread) break;

        char name[9];
        memcpy(name, s, 8);
        name[8] = '\0';

        DWORD vsize   = *(DWORD*)(s + 8);
        DWORD raw_off  = *(DWORD*)(s + 20);
        DWORD raw_sz   = *(DWORD*)(s + 16);
        if (raw_off + raw_sz > last_section_end)
            last_section_end = raw_off + raw_sz;

        if (strstr(name, ".vmp") || strstr(name, ".VMP") || strstr(name, "vmp")) {
            result->vmp_sections++;
        }

        int is_bssish = (strcmp(name, ".bss") == 0 || strcmp(name, ".data") == 0);
        if (!is_bssish && raw_sz > 0 && vsize > 0x100000 && vsize > raw_sz * 3) {
            result->vmp_sections++;
        }

        if (!is_bssish && vsize > 0 && raw_sz == 0) {
            result->zeroed_sections++;
        }
    }

    if (file_size > 0 && last_section_end > 0 && (long)last_section_end < file_size) {
        long overlay_size = file_size - last_section_end;
        if (overlay_size > 4096) {
            result->has_overlay = 1;
        }
    }

    WORD magic = *(WORD*)(pe + 24);
    DWORD import_rva = 0;
    if (magic == PE32_MAGIC && pe_off + 24 + 104 < nread) {
        import_rva = *(DWORD*)(pe + 24 + 104);
    } else if (magic == PE32PLUS_MAGIC && pe_off + 24 + 120 < nread) {
        import_rva = *(DWORD*)(pe + 24 + 120);
    }

    if (import_rva == 0) result->minimal_imports = 1;

    if (result->vmp_sections > 0 || result->zeroed_sections >= 2) {
        result->is_packed = 1;
        snprintf(result->details, sizeof(result->details),
                 "VMProtect detected: %d VMP section(s), %d zeroed section(s), overlay=%s",
                 result->vmp_sections, result->zeroed_sections,
                 result->has_overlay ? "yes" : "no");
    } else if (result->has_overlay && result->minimal_imports) {
        result->is_packed = 1;
        snprintf(result->details, sizeof(result->details),
                 "Likely packed: overlay present + minimal imports");
    } else {
        snprintf(result->details, sizeof(result->details),
                 "Not packed (no VMProtect markers found)");
    }

    return result->is_packed;
}

static void build_watch_dirs(const char *target_path)
{
    g_watch_dir_count = 0;
    char buf[MAX_PATH];

    char parent[MAX_PATH];
    strncpy(parent, target_path, MAX_PATH - 1);
    parent[MAX_PATH - 1] = '\0';
    char *last = strrchr(parent, '\\');
    if (!last) last = strrchr(parent, '/');
    if (last) *last = '\0';
    strncpy(g_watch_dirs[g_watch_dir_count++], parent, MAX_PATH);

    if (ExpandEnvironmentStringsA("%USERPROFILE%\\Desktop", buf, MAX_PATH))
        strncpy(g_watch_dirs[g_watch_dir_count++], buf, MAX_PATH);

    if (ExpandEnvironmentStringsA("%TEMP%", buf, MAX_PATH))
        strncpy(g_watch_dirs[g_watch_dir_count++], buf, MAX_PATH);

    if (ExpandEnvironmentStringsA("%APPDATA%", buf, MAX_PATH))
        strncpy(g_watch_dirs[g_watch_dir_count++], buf, MAX_PATH);

    if (ExpandEnvironmentStringsA("%LOCALAPPDATA%", buf, MAX_PATH))
        strncpy(g_watch_dirs[g_watch_dir_count++], buf, MAX_PATH);

    if (ExpandEnvironmentStringsA("%PROGRAMDATA%", buf, MAX_PATH))
        strncpy(g_watch_dirs[g_watch_dir_count++], buf, MAX_PATH);

    printf("[*] Watching %d directories for new PE files\n", g_watch_dir_count);
}

static int is_pe_extension(const char *name)
{
    const char *ext = strrchr(name, '.');
    if (!ext) return 0;
    return (_stricmp(ext, ".exe") == 0 || _stricmp(ext, ".dll") == 0 ||
            _stricmp(ext, ".scr") == 0 || _stricmp(ext, ".com") == 0 ||
            _stricmp(ext, ".cpl") == 0);
}

static void scan_dir_for_pes(const char *dir)
{
    char search[MAX_PATH];
    snprintf(search, sizeof(search), "%s\\*", dir);
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            continue;
        }
        if (!is_pe_extension(fd.cFileName)) continue;
        if (g_fs_count >= MAX_SNAPSHOT_FILES) break;

        FSEntry *e = &g_fs_snapshot[g_fs_count];
        snprintf(e->path, MAX_PATH, "%s\\%s", dir, fd.cFileName);
        e->size_low = fd.nFileSizeLow;
        g_fs_count++;
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);
}

static void take_fs_snapshot(void)
{
    g_fs_count = 0;
    for (int i = 0; i < g_watch_dir_count; i++)
        scan_dir_for_pes(g_watch_dirs[i]);
    printf("[*] Filesystem snapshot: %d PE files in baseline\n", g_fs_count);
}

static int find_new_pe_files(char new_files[][MAX_PATH], int max_results)
{
    int found = 0;
    for (int d = 0; d < g_watch_dir_count && found < max_results; d++) {
        char search[MAX_PATH];
        snprintf(search, sizeof(search), "%s\\*", g_watch_dirs[d]);
        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA(search, &fd);
        if (hFind == INVALID_HANDLE_VALUE) continue;

        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            if (!is_pe_extension(fd.cFileName)) continue;

            char fullpath[MAX_PATH];
            snprintf(fullpath, sizeof(fullpath), "%s\\%s", g_watch_dirs[d], fd.cFileName);

            if (g_self_path[0] && _stricmp(g_self_path, fullpath) == 0) continue;

            int in_baseline = 0;
            for (int j = 0; j < g_fs_count; j++) {
                if (_stricmp(g_fs_snapshot[j].path, fullpath) == 0) {
                    in_baseline = 1;
                    break;
                }
            }
            if (!in_baseline && found < max_results) {
                strncpy(new_files[found], fullpath, MAX_PATH);
                found++;
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);

        snprintf(search, sizeof(search), "%s\\*", g_watch_dirs[d]);
        hFind = FindFirstFileA(search, &fd);
        if (hFind == INVALID_HANDLE_VALUE) continue;
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (fd.cFileName[0] == '.') continue;

            char subdir[MAX_PATH];
            snprintf(subdir, sizeof(subdir), "%s\\%s", g_watch_dirs[d], fd.cFileName);

            char sub_search[MAX_PATH];
            snprintf(sub_search, sizeof(sub_search), "%s\\*", subdir);
            WIN32_FIND_DATAA fd2;
            HANDLE hFind2 = FindFirstFileA(sub_search, &fd2);
            if (hFind2 == INVALID_HANDLE_VALUE) continue;
            do {
                if (fd2.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                if (!is_pe_extension(fd2.cFileName)) continue;
                char fullpath2[MAX_PATH];
                snprintf(fullpath2, sizeof(fullpath2), "%s\\%s", subdir, fd2.cFileName);
                if (g_self_path[0] && _stricmp(g_self_path, fullpath2) == 0) continue;
                int in_bl = 0;
                for (int j = 0; j < g_fs_count; j++) {
                    if (_stricmp(g_fs_snapshot[j].path, fullpath2) == 0) { in_bl = 1; break; }
                }
                if (!in_bl && found < max_results) {
                    strncpy(new_files[found], fullpath2, MAX_PATH);
                    found++;
                }
            } while (FindNextFileA(hFind2, &fd2));
            FindClose(hFind2);
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
    return found;
}

static void take_process_snapshot(void)
{
    g_baseline_pid_count = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if (g_baseline_pid_count < MAX_BASELINE_PIDS)
                g_baseline_pids[g_baseline_pid_count++] = pe.th32ProcessID;
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
}

static int find_new_processes(DWORD new_pids[], int max_results)
{
    int found = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if (pe.th32ProcessID < 8) continue;
            int in_baseline = 0;
            for (int i = 0; i < g_baseline_pid_count; i++) {
                if (g_baseline_pids[i] == pe.th32ProcessID) { in_baseline = 1; break; }
            }
            if (!in_baseline && found < max_results) {
                new_pids[found++] = pe.th32ProcessID;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

static int get_process_image_path(DWORD pid, char *path, int path_size)
{
    path[0] = '\0';
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return 0;

    typedef BOOL (WINAPI *pfnQueryFullProcessImageNameA)(HANDLE, DWORD, LPSTR, PDWORD);
    static pfnQueryFullProcessImageNameA pQuery = NULL;
    static int resolved = 0;
    if (!resolved) {
        HMODULE hK32 = GetModuleHandleA("kernel32.dll");
        if (hK32) pQuery = (pfnQueryFullProcessImageNameA)
            GetProcAddress(hK32, "QueryFullProcessImageNameA");
        resolved = 1;
    }

    if (pQuery) {
        DWORD sz = (DWORD)path_size;
        if (pQuery(hProc, 0, path, &sz)) {
            CloseHandle(hProc);
            return 1;
        }
    }

    CloseHandle(hProc);
    HANDLE modSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (modSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 me;
        me.dwSize = sizeof(me);
        if (Module32First(modSnap, &me)) {
            strncpy(path, me.szExePath, path_size - 1);
            path[path_size - 1] = '\0';
            CloseHandle(modSnap);
            return 1;
        }
        CloseHandle(modSnap);
    }
    return 0;
}

static HANDLE get_main_thread_handle(DWORD pid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return NULL;
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    HANDLE hThread = NULL;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                if (hThread) break;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return hThread;
}

static int attach_and_assess(HANDLE hProc, HANDLE hThread, DWORD64 image_base)
{

    if (hThread) SuspendThread(hThread);

    if (!read_pe_sections(hProc, image_base)) {
        printf("[-] Cannot read PE sections from attached process\n");
        if (hThread) ResumeThread(hThread);
        return -1;
    }

    int decrypted_count = 0;
    for (int i = 0; i < g_num_sections; i++) {
        SectionInfo *si = &g_sections[i];
        if (si->vsize == 0 || si->vsize < 0x1000) continue;
        int nz = 0;
        for (int j = 0; j < FINGERPRINT_SIZE; j++)
            if (si->fingerprint[j] != 0) nz++;
        if (nz > (int)(FINGERPRINT_SIZE * 0.8))
            decrypted_count++;
    }

    if (decrypted_count >= 2) {
        printf("[+] Sections already decrypted (%d sections with data). Dumping now.\n",
               decrypted_count);
        return 1;
    } else {
        printf("[*] Sections still encrypted (%d decrypted). Resuming for monitor loop.\n",
               decrypted_count);
        if (hThread) ResumeThread(hThread);
        return 0;
    }
}

static int wait_for_named_process(const char *proc_name, int timeout_sec, TargetInfo *found)
{
    int ticks = 0;
    int max_ticks = (timeout_sec * 1000) / DROPPER_POLL_MS;

    printf("[*] Polling for process '%s' (up to %ds)...\n", proc_name, timeout_sec);

    while (ticks < max_ticks) {
        Sleep(DROPPER_POLL_MS);
        ticks++;

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) continue;
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe)) {
            do {
                if (_stricmp(pe.szExeFile, proc_name) == 0) {
                    CloseHandle(snap);
                    printf("[+] Found '%s' (PID %u) at %.1fs\n",
                           proc_name, pe.th32ProcessID,
                           (float)(ticks * DROPPER_POLL_MS) / 1000.0f);

                    found->pid = pe.th32ProcessID;
                    found->hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
                    found->hThread = get_main_thread_handle(pe.th32ProcessID);
                    get_process_image_path(pe.th32ProcessID, found->image_path, MAX_PATH);

                    if (found->hProcess) {
                        detect_target_architecture_vmp(found->hProcess, &found->image_base);
                    }
                    return (found->hProcess != NULL) ? 1 : 0;
                }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);

        if (ticks % 20 == 0)
            printf("    ... waiting for '%s' (%.0fs)\n", proc_name,
                   (float)(ticks * DROPPER_POLL_MS) / 1000.0f);
    }

    printf("[!] Timeout: '%s' never appeared after %ds\n", proc_name, timeout_sec);
    return 0;
}

static int dropper_mode(const char *target_exe, int timeout_sec, TargetInfo *found)
{
    memset(found, 0, sizeof(*found));

    build_watch_dirs(target_exe);
    take_fs_snapshot();
    take_process_snapshot();

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    char cmdline[MAX_PATH * 2];
    strncpy(cmdline, target_exe, sizeof(cmdline) - 1);
    cmdline[sizeof(cmdline) - 1] = '\0';

    printf("[*] Launching dropper (normal, not suspended)...\n");
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcess failed for dropper (error %u)\n", (unsigned)GetLastError());
        return 0;
    }
    printf("[+] Dropper PID=%u\n", pi.dwProcessId);
    CloseHandle(pi.hThread);

    int ticks = 0;
    int max_ticks = (timeout_sec * 1000) / DROPPER_POLL_MS;
    int dropper_exited = 0;

    while (ticks < max_ticks) {
        Sleep(DROPPER_POLL_MS);
        ticks++;

        if (!dropper_exited) {
            DWORD ec;
            if (!GetExitCodeProcess(pi.hProcess, &ec) || ec != STILL_ACTIVE) {
                dropper_exited = 1;
                printf("[*] Dropper exited at %.1fs. Scanning for 10 more seconds...\n",
                       (float)(ticks * DROPPER_POLL_MS) / 1000.0f);
                int remaining = (10 * 1000) / DROPPER_POLL_MS;
                if (ticks + remaining < max_ticks)
                    max_ticks = ticks + remaining;
            }
        }

        char new_files[MAX_NEW_FILES][MAX_PATH];
        int nf = find_new_pe_files(new_files, MAX_NEW_FILES);

        for (int i = 0; i < nf; i++) {
            PackerCheckResult pr;
            if (check_file_for_packer(new_files[i], &pr)) {
                printf("[+] PACKED PE ON DISK: %s (%s)\n", new_files[i], pr.details);

                DWORD new_pids[MAX_NEW_PIDS];
                int np = find_new_processes(new_pids, MAX_NEW_PIDS);
                for (int p = 0; p < np; p++) {
                    char img_path[MAX_PATH];
                    if (get_process_image_path(new_pids[p], img_path, MAX_PATH)) {
                        if (_stricmp(img_path, new_files[i]) == 0 ||
                            _stricmp(get_basename(img_path), get_basename(new_files[i])) == 0) {
                            printf("[+] MATCHED PROCESS: PID %u (%s)\n", new_pids[p], img_path);
                            found->pid = new_pids[p];
                            found->hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, new_pids[p]);
                            found->hThread = get_main_thread_handle(new_pids[p]);
                            strncpy(found->image_path, img_path, MAX_PATH);
                            if (found->hProcess)
                                detect_target_architecture_vmp(found->hProcess, &found->image_base);
                            CloseHandle(pi.hProcess);
                            return (found->hProcess != NULL) ? 1 : 0;
                        }
                    }
                }

                printf("[*] Packed PE found but not yet running. Waiting...\n");
            }
        }

        DWORD new_pids[MAX_NEW_PIDS];
        int np = find_new_processes(new_pids, MAX_NEW_PIDS);
        for (int p = 0; p < np; p++) {
            char img_path[MAX_PATH];
            if (!get_process_image_path(new_pids[p], img_path, MAX_PATH)) continue;

            if (strstr(img_path, "\\Windows\\") && !strstr(img_path, "\\Temp\\")) continue;

            DWORD file_attr = GetFileAttributesA(img_path);
            if (file_attr != INVALID_FILE_ATTRIBUTES) {
                PackerCheckResult pr;
                if (check_file_for_packer(img_path, &pr)) {
                    printf("[+] PACKED PROCESS: PID %u (%s) - %s\n",
                           new_pids[p], img_path, pr.details);
                    found->pid = new_pids[p];
                    found->hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, new_pids[p]);
                    found->hThread = get_main_thread_handle(new_pids[p]);
                    strncpy(found->image_path, img_path, MAX_PATH);
                    if (found->hProcess)
                        detect_target_architecture_vmp(found->hProcess, &found->image_base);
                    CloseHandle(pi.hProcess);
                    return (found->hProcess != NULL) ? 1 : 0;
                }
            }
        }

        if (ticks % 20 == 0)
            printf("    ... scanning (%.0fs, %d new files, %d new procs)\n",
                   (float)(ticks * DROPPER_POLL_MS) / 1000.0f, nf, np);
    }

    printf("[!] Dropper mode timeout (%ds). No packed payload found.\n", timeout_sec);
    CloseHandle(pi.hProcess);
    return 0;
}

static void write_dropper_info(const char *original, const char *payload, DWORD pid,
                               const char *method, float discovery_time)
{
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s\\dropper_mode_info.txt", g_output_dir);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "Dropper Mode Activated\n");
    fprintf(f, "Original Sample: %s\n", original);
    fprintf(f, "Packed Payload: %s\n", payload);
    fprintf(f, "Payload PID: %u\n", pid);
    fprintf(f, "Discovery Method: %s\n", method);
    fprintf(f, "Discovery Time: %.1f seconds\n", discovery_time);
    fclose(f);
    printf("[+] Wrote dropper_mode_info.txt\n");
}

int main(int argc, char *argv[])
{
    printf("  VMProtect Dumper, don't sell source code\n");

    int kill_vmtools = 0;

    if (argc < 2) {
        printf("Usage: %s <target.exe|target.dll> [options]\n\n", argv[0]);
        printf("  Drag & drop a VMProtect-protected PE onto this exe,\n");
        printf("  or run from command line.\n\n");
        printf("  Output folder is auto-created next to the sample:\n");
        printf("    vmp_dump_{sample_filename}\\\n\n");
        printf("Options:\n");
        printf("  --dll-export=Name   For DLL targets: specify export to call\n");
        printf("                      (default: DllRegisterServer)\n");
        printf("  --wait-for=Name     Wait for a specific process to spawn, then dump it\n");
        printf("  --dropper-timeout=N Dropper mode timeout in seconds (default: 60)\n");
        printf("  --force-direct      Skip packer check, use direct monitor mode\n");
        printf("  --force-dropper     Force dropper mode even if target appears packed\n");
        printf("  --kill-vmtools      Kill VMware/VBox tools (disables shared folders!)\n");
        printf("                      Copy this tool to the VM FIRST.\n");
        printf("  --no-pause          Exit immediately after dumping (no Press Enter prompt)\n");
        printf("  --no-harvest        Disable memory harvester (section-only monitoring)\n");
        printf("  --pesieve-path=PATH Path to pe-sieve exe (default: auto-detect)\n\n");
        printf("DLL examples:\n");
        printf("  %s malware.dll\n", argv[0]);
        printf("  %s malware.dll --dll-export=ServiceMain\n", argv[0]);
        printf("  %s malware.dll --dll-export=#1\n", argv[0]);
        printf("\nPress Enter to exit...");
        if (!g_no_pause) getchar();
        return 1;
    }

    enable_debug_privilege();
    GetModuleFileNameA(NULL, g_self_path, MAX_PATH);

    const char *target = argv[1];

    for (int i = 2; i < argc; i++) {
        if (strncmp(argv[i], "--dll-export=", 13) == 0) {
            strncpy(g_dll_export, argv[i] + 13, sizeof(g_dll_export) - 1);
        } else if (strncmp(argv[i], "--wait-for=", 11) == 0) {
            strncpy(g_wait_for_process, argv[i] + 11, sizeof(g_wait_for_process) - 1);
        } else if (strncmp(argv[i], "--dropper-timeout=", 18) == 0) {
            g_dropper_timeout = atoi(argv[i] + 18);
            if (g_dropper_timeout < 5) g_dropper_timeout = 5;
            if (g_dropper_timeout > 300) g_dropper_timeout = 300;
        } else if (strcmp(argv[i], "--force-direct") == 0) {
            g_force_direct = 1;
        } else if (strcmp(argv[i], "--force-dropper") == 0) {
            g_force_dropper = 1;
        } else if (strcmp(argv[i], "--kill-vmtools") == 0) {
            kill_vmtools = 1;
        } else if (strcmp(argv[i], "--no-pause") == 0) {
            g_no_pause = 1;
        } else if (strcmp(argv[i], "--no-harvest") == 0) {
            g_harvest_enabled = 0;
        } else if (strncmp(argv[i], "--pesieve-path=", 15) == 0) {
            strncpy(g_harvest.pesieve_path, argv[i] + 15, MAX_PATH - 1);
        }
    }

    char target_fullpath[MAX_PATH];
    if (GetFullPathNameA(target, MAX_PATH, target_fullpath, NULL)) {
        target = target_fullpath;
    }

    DWORD attr = GetFileAttributesA(target);
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        printf("[-] File not found: %s\n", target);
        printf("\nPress Enter to exit...");
        if (!g_no_pause) getchar();
        return 1;
    }

    build_output_dir(target);
    CreateDirectoryA(g_output_dir, NULL);

    const char *ext = strrchr(target, '.');
    if (ext && (_stricmp(ext, ".dll") == 0 || _stricmp(ext, ".ocx") == 0 ||
                _stricmp(ext, ".cpl") == 0))
    {
        g_is_dll = 1;
    }

    printf("[*] Target: %s%s\n", get_basename(target), g_is_dll ? " (DLL)" : " (EXE)");
    printf("[*] Output: %s\n", g_output_dir);

    if (g_is_dll && g_dll_export[0] == '\0') {
        printf("\n");
        printf("=======================================================\n");
        printf("  ERROR: DLL target requires --dll-export argument!\n");
        printf("=======================================================\n\n");
        printf("  DLLs cannot be drag-and-dropped. Run from command line:\n\n");
        printf("    %s %s --dll-export=ExportName\n\n", get_basename(argv[0]), get_basename(target));
        printf("  Common exports:\n");
        printf("    --dll-export=DllRegisterServer   (regsvr32 DLLs)\n");
        printf("    --dll-export=ServiceMain         (service DLLs - auto creates temp service)\n");
        printf("    --dll-export=#1                  (ordinal exports)\n\n");
        printf("  Use a PE viewer (CFF Explorer, PE-bear, dumpbin /exports)\n");
        printf("  to check which export the DLL has.\n");
        printf("\nPress Enter to exit...");
        if (!g_no_pause) getchar();
        return 1;
    }

    if (g_is_dll && (_stricmp(g_dll_export, "ServiceMain") == 0 ||
                     _stricmp(g_dll_export, "SvcMain") == 0)) {
        g_is_service_dll = 1;
    }

    if (g_is_dll)
        printf("[*] DLL export: %s%s\n", g_dll_export,
               g_is_service_dll ? " (service DLL mode)" : " (rundll32 mode)");
    printf("\n");

    kill_monitor_processes(kill_vmtools);

    char target_dir[MAX_PATH];
    get_parent_dir(target, target_dir, sizeof(target_dir));

    HANDLE hTargetProc = NULL;
    HANDLE hTargetThread = NULL;
    DWORD  target_pid = 0;
    int    own_process = 0;

    if (g_is_service_dll) {
        DWORD64 svc_dll_base = 0;
        DWORD svc_pid = 0;
        hTargetProc = launch_service_dll(target, &svc_dll_base, &svc_pid);
        if (!hTargetProc) {
            printf("[-] Service DLL launch failed\n");
            cleanup_temp_service();
            printf("\nPress Enter to exit...");
            if (!g_no_pause) getchar();
            return 1;
        }
        target_pid = svc_pid;
        g_image_base = svc_dll_base;
        own_process = 0;

        if (!read_pe_sections(hTargetProc, g_image_base)) {
            printf("[-] Cannot read PE sections from service DLL\n");
            cleanup_temp_service();
            CloseHandle(hTargetProc);
            printf("\nPress Enter to exit...");
            if (!g_no_pause) getchar();
            return 1;
        }

        printf("\n[*] Service DLL loaded. Dumping immediately (already unpacked)...\n");

        capture_oep(hTargetProc, NULL, g_image_base, g_size_of_image ? g_size_of_image : 0x1000000);
        dump_all(hTargetProc, g_image_base, target);
        capture_dropped_files(target_dir);
        capture_dropped_files(".");

        cleanup_temp_service();
        CloseHandle(hTargetProc);

    } else {

        int skip_monitor = 0;
        int used_dropper_mode = 0;
        char dropper_payload_path[MAX_PATH] = "";
        DWORD dropper_payload_pid = 0;
        float dropper_discovery_time = 0;

        if (g_wait_for_process[0] != '\0' && !g_is_dll) {
            printf("\n[*] === TARGETED MODE: --wait-for=%s ===\n", g_wait_for_process);

            char cmdline[MAX_PATH * 2];
            strncpy(cmdline, target, sizeof(cmdline) - 1);
            cmdline[sizeof(cmdline) - 1] = '\0';
            STARTUPINFOA si2;
            PROCESS_INFORMATION pi2;
            memset(&si2, 0, sizeof(si2)); si2.cb = sizeof(si2);
            memset(&pi2, 0, sizeof(pi2));
            CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si2, &pi2);
            printf("[+] Launched dropper PID=%u\n", pi2.dwProcessId);
            CloseHandle(pi2.hThread);

            TargetInfo found;
            memset(&found, 0, sizeof(found));
            DWORD t_start = GetTickCount();
            if (wait_for_named_process(g_wait_for_process, g_dropper_timeout, &found)) {
                dropper_discovery_time = (float)(GetTickCount() - t_start) / 1000.0f;
                strncpy(dropper_payload_path, found.image_path, MAX_PATH);
                dropper_payload_pid = found.pid;

                PackerCheckResult pr;
                int packed = check_file_for_packer(found.image_path, &pr);
                if (packed) printf("[+] Confirmed packed: %s\n", pr.details);
                else printf("[!] WARNING: '%s' not packed. Dumping anyway.\n", g_wait_for_process);

                hTargetProc = found.hProcess;
                hTargetThread = found.hThread;
                target_pid = found.pid;
                g_image_base = found.image_base;
                own_process = 0;

                int assess = attach_and_assess(hTargetProc, hTargetThread, g_image_base);
                if (assess == 1) skip_monitor = 1;
                else if (assess < 0) { hTargetProc = NULL; hTargetThread = NULL; }
                used_dropper_mode = 1;
            } else {
                printf("[!] '%s' never appeared. Falling back to direct mode.\n", g_wait_for_process);
                TerminateProcess(pi2.hProcess, 0);
            }
            CloseHandle(pi2.hProcess);

        } else if (g_force_direct || g_is_dll) {
            printf("[*] Direct mode (--force-direct or DLL target)\n");

        } else if (g_force_dropper) {
            printf("\n[*] === FORCED DROPPER MODE ===\n");
            TargetInfo found;
            memset(&found, 0, sizeof(found));
            DWORD t_start = GetTickCount();
            if (dropper_mode(target, g_dropper_timeout, &found)) {
                dropper_discovery_time = (float)(GetTickCount() - t_start) / 1000.0f;
                strncpy(dropper_payload_path, found.image_path, MAX_PATH);
                dropper_payload_pid = found.pid;
                hTargetProc = found.hProcess;
                hTargetThread = found.hThread;
                target_pid = found.pid;
                g_image_base = found.image_base;
                own_process = 0;
                int assess = attach_and_assess(hTargetProc, hTargetThread, g_image_base);
                if (assess == 1) skip_monitor = 1;
                else if (assess < 0) { hTargetProc = NULL; hTargetThread = NULL; }
                used_dropper_mode = 1;
            }

        } else {
            PackerCheckResult packer_result;
            int is_packed = check_file_for_packer(target, &packer_result);
            printf("[*] Packer check: %s\n", packer_result.details);

            if (!is_packed) {
                printf("\n[*] === AUTO DROPPER MODE (target not packed) ===\n");
                TargetInfo found;
                memset(&found, 0, sizeof(found));
                DWORD t_start = GetTickCount();
                if (dropper_mode(target, g_dropper_timeout, &found)) {
                    dropper_discovery_time = (float)(GetTickCount() - t_start) / 1000.0f;
                    strncpy(dropper_payload_path, found.image_path, MAX_PATH);
                    dropper_payload_pid = found.pid;
                    hTargetProc = found.hProcess;
                    hTargetThread = found.hThread;
                    target_pid = found.pid;
                    g_image_base = found.image_base;
                    own_process = 0;
                    int assess = attach_and_assess(hTargetProc, hTargetThread, g_image_base);
                    if (assess == 1) skip_monitor = 1;
                    else if (assess < 0) { hTargetProc = NULL; hTargetThread = NULL; }
                    used_dropper_mode = 1;
                } else {
                    printf("[!] No packed payload found. Falling back to direct mode.\n");
                }
            } else {
                printf("[*] Target is packed. Using direct mode.\n");
            }
        }

        if (skip_monitor && hTargetProc) {

            printf("\n[*] Dumping already-decrypted process...\n");
            DWORD skip_pid = GetProcessId(hTargetProc);
            if (g_harvest_enabled) {
                harvest_init();
                detect_pesieve_path();
                take_region_snapshot(hTargetProc, g_image_base, g_size_of_image);
            }
            capture_oep(hTargetProc, hTargetThread, g_image_base,
                        g_size_of_image ? g_size_of_image : 0x1000000);
            dump_all(hTargetProc, g_image_base, target);
            if (g_harvest_enabled) {
                run_pesieve(skip_pid);
                write_harvest_report(0);
            }
            capture_dropped_files(target_dir);
            capture_dropped_files(".");

            if (used_dropper_mode && dropper_payload_path[0]) {
                write_dropper_info(target, dropper_payload_path,
                                   dropper_payload_pid,
                                   g_wait_for_process[0] ? "wait-for" :
                                   g_force_dropper ? "force-dropper" : "auto-dropper",
                                   dropper_discovery_time);
            }

            TerminateProcess(hTargetProc, 0);
            CloseHandle(hTargetProc);
            if (hTargetThread) CloseHandle(hTargetThread);

        } else if (hTargetProc && hTargetThread) {

            printf("\n[*] Monitoring attached process for VMProtect decryption...\n");

            neutralize_antidebug(hTargetProc);
            install_gpa_hook(hTargetProc);

            if (g_harvest_enabled) {
                harvest_init();
                detect_pesieve_path();
                take_region_snapshot(hTargetProc, g_image_base, g_size_of_image);
                harvest_log("[T+0.0s] Baseline: %d exec regions outside PE",
                            g_harvest.current.count);
                printf("[*] Harvest baseline: %d executable regions outside PE\n",
                       g_harvest.current.count);
            }

            int ticks = 0, max_ticks = (MAX_MONITOR_SEC * 1000) / POLL_INTERVAL_MS;
            int dump_done = 0;
            int first_change_tick = -1;

            while (!dump_done && ticks < max_ticks) {
                Sleep(POLL_INTERVAL_MS);
                ticks++;

                install_gpa_hook(hTargetProc);
                poll_gpa_log(hTargetProc);
                if (g_hook_cave && (ticks < 40 || ticks % 20 == 0))
                    patch_iat_slots_for_hooks(hTargetProc);

                DWORD ec;
                int alive = (GetExitCodeProcess(hTargetProc, &ec) && ec == STILL_ACTIVE);
                int changed = check_changes(hTargetProc, g_image_base);

                int harvest_trigger = 0;
                if (g_harvest_enabled && (ticks % HARVEST_SNAP_INTERVAL == 0) && alive) {
                    take_region_snapshot(hTargetProc, g_image_base, g_size_of_image);
                    check_region_changes();
                    if (g_harvest.new_this_cycle >= HARVEST_REGION_THRESHOLD)
                        harvest_trigger = 1;
                }

                if (g_harvest_enabled && (ticks % HARVEST_BEHAV_INTERVAL == 0) && alive) {
                    check_behavioral_trigger();
                    if (g_harvest.behavioral_trigger && g_harvest.current.count > 0)
                        harvest_trigger = 1;
                }

                if (changed > 0 && first_change_tick < 0) {
                    first_change_tick = ticks;
                    printf("[!] Section changes detected! Waiting 3s for VMProtect init...\n");
                }

                if (first_change_tick > 0 && (ticks - first_change_tick) * POLL_INTERVAL_MS >= 3000) {
                    if (hTargetThread) SuspendThread(hTargetThread);
                    printf("[!] VMProtect init complete. Process SUSPENDED.\n");

                    if (hTargetThread) {
                        ResumeThread(hTargetThread);
                        Sleep(500);
                        SuspendThread(hTargetThread);
                    }
                    check_changes(hTargetProc, g_image_base);
                    if (g_harvest_enabled)
                        take_region_snapshot(hTargetProc, g_image_base, g_size_of_image);

                    capture_oep(hTargetProc, hTargetThread, g_image_base,
                                g_size_of_image ? g_size_of_image : 0x1000000);
                    dump_all(hTargetProc, g_image_base, target);
                    if (g_harvest_enabled && alive) run_pesieve(target_pid);
                    dump_done = 1;

                    capture_dropped_files(target_dir);
                    capture_dropped_files(".");

                    if (used_dropper_mode && dropper_payload_path[0]) {
                        write_dropper_info(target, dropper_payload_path,
                                           dropper_payload_pid,
                                           g_wait_for_process[0] ? "wait-for" :
                                           g_force_dropper ? "force-dropper" : "auto-dropper",
                                           dropper_discovery_time);
                    }

                    printf("[*] Terminating process.\n");
                    TerminateProcess(hTargetProc, 0);
                }

                if (harvest_trigger && !dump_done && first_change_tick < 0) {
                    printf("[!] HARVEST TRIGGER: %s at %.1fs\n",
                           g_harvest.new_this_cycle >= HARVEST_REGION_THRESHOLD
                             ? "3+ new executable regions"
                             : "behavioral signal + regions",
                           (float)(ticks * POLL_INTERVAL_MS) / 1000.0f);
                    harvest_log("[T+%.1fs] DUMP TRIGGER: %s",
                                (float)(ticks * POLL_INTERVAL_MS) / 1000.0f,
                                g_harvest.new_this_cycle >= HARVEST_REGION_THRESHOLD
                                  ? "REGION_THRESHOLD" : "BEHAVIORAL");
                    Sleep(HARVEST_SETTLE_MS);
                    take_region_snapshot(hTargetProc, g_image_base, g_size_of_image);
                    if (hTargetThread) SuspendThread(hTargetThread);

                    capture_oep(hTargetProc, hTargetThread, g_image_base,
                                g_size_of_image ? g_size_of_image : 0x1000000);
                    dump_all(hTargetProc, g_image_base, target);
                    if (alive) run_pesieve(target_pid);
                    dump_done = 1;
                    capture_dropped_files(target_dir);
                    capture_dropped_files(".");
                    TerminateProcess(hTargetProc, 0);
                }

                if (!alive && !dump_done) {
                    printf("[!] Process exited (code %u) at %.1fs\n", (unsigned)ec,
                           (float)(ticks * POLL_INTERVAL_MS) / 1000.0f);
                    printf("[!] Cannot capture OEP -- process already dead\n");
                    if (g_harvest_enabled)
                        take_region_snapshot(hTargetProc, g_image_base, g_size_of_image);
                    dump_all(hTargetProc, g_image_base, target);
                    capture_dropped_files(target_dir);
                    capture_dropped_files(".");
                    dump_done = 1;
                }

                if (ticks % 200 == 0 && !dump_done)
                    printf("    ... monitoring (%.0fs) sections=%d regions=%d\n",
                           (float)(ticks * POLL_INTERVAL_MS) / 1000.0f,
                           changed, g_harvest_enabled ? g_harvest.current.count : 0);
            }

            if (!dump_done) {
                printf("[!] Timeout (%ds). Dumping current state...\n", MAX_MONITOR_SEC);
                if (hTargetThread) SuspendThread(hTargetThread);
                if (g_harvest_enabled)
                    take_region_snapshot(hTargetProc, g_image_base, g_size_of_image);
                capture_oep(hTargetProc, hTargetThread, g_image_base,
                            g_size_of_image ? g_size_of_image : 0x1000000);
                dump_all(hTargetProc, g_image_base, target);
                if (g_harvest_enabled) run_pesieve(target_pid);
                capture_dropped_files(target_dir);
                TerminateProcess(hTargetProc, 0);
            }

            if (g_harvest_enabled)
                write_harvest_report(ticks * POLL_INTERVAL_MS);

            CloseHandle(hTargetProc);
            if (hTargetThread) CloseHandle(hTargetThread);

        } else {

            char cmdline[MAX_PATH * 2];
            if (g_is_dll) {
                snprintf(cmdline, sizeof(cmdline),
                         "rundll32.exe \"%s\",%s", target, g_dll_export);
                printf("[*] DLL launch: %s\n", cmdline);
            } else {
                strncpy(cmdline, target, sizeof(cmdline) - 1);
                cmdline[sizeof(cmdline) - 1] = '\0';
            }

            STARTUPINFOA si;
            PROCESS_INFORMATION pi;
            memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
            memset(&pi, 0, sizeof(pi));

            printf("[*] Launching as SUSPENDED (direct mode)...\n");
            if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                               CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
                DWORD err = GetLastError();
                printf("[-] CreateProcess failed (error %u)\n", (unsigned)err);
                if (err == 740)
                    printf("    Hint: Try running this tool as Administrator.\n");
                printf("\nPress Enter to exit...");
                if (!g_no_pause) getchar();
                return 1;
            }
            printf("[+] PID=%u TID=%u\n", pi.dwProcessId, pi.dwThreadId);
            hTargetProc = pi.hProcess;
            hTargetThread = pi.hThread;
            target_pid = pi.dwProcessId;
            own_process = 1;

            CONTEXT ctx;
            memset(&ctx, 0, sizeof(ctx));

#ifdef _WIN64
            ctx.ContextFlags = CONTEXT_INTEGER;
            if (GetThreadContext(pi.hThread, &ctx)) {
                SIZE_T nr;
                ReadProcessMemory(pi.hProcess, (LPCVOID)(ctx.Rdx + 0x10),
                                 &g_image_base, 8, &nr);
                printf("[+] PEB=0x%llX ImageBase=0x%llX\n",
                       (unsigned long long)ctx.Rdx, (unsigned long long)g_image_base);
            }
#else
            ctx.ContextFlags = CONTEXT_INTEGER;
            if (GetThreadContext(pi.hThread, &ctx)) {
                SIZE_T nr;
                DWORD base32 = 0;
                ReadProcessMemory(pi.hProcess, (LPCVOID)(ctx.Ebx + 0x08),
                                 &base32, 4, &nr);
                g_image_base = base32;
                printf("[+] PEB=0x%08X ImageBase=0x%08X\n", ctx.Ebx, base32);
            }
#endif

            if (g_is_dll && g_image_base != 0) {
                printf("[*] Host is rundll32. Will search for DLL module after resume.\n");
            }

            if (g_image_base == 0) {
                BYTE t[2]; SIZE_T nr;
                DWORD64 bases[] = { 0x140000000, 0x180000000, 0x400000, 0x10000000, 0 };
                for (int i = 0; bases[i] != 0; i++) {
                    if (ReadProcessMemory(pi.hProcess, (LPCVOID)bases[i], t, 2, &nr) &&
                        t[0] == 'M' && t[1] == 'Z') {
                        g_image_base = bases[i];
                        printf("[+] Found PE at fallback base 0x%llX\n",
                               (unsigned long long)g_image_base);
                        break;
                    }
                }
            }

            if (g_image_base == 0) {
                printf("[-] Cannot find image base\n");
                TerminateProcess(pi.hProcess, 1);
                CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
                printf("\nPress Enter to exit...");
                if (!g_no_pause) getchar();
                return 1;
            }

            if (!read_pe_sections(pi.hProcess, g_image_base)) {
                printf("[-] Cannot read PE sections\n");
                TerminateProcess(pi.hProcess, 1);
                CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
                printf("\nPress Enter to exit...");
                if (!g_no_pause) getchar();
                return 1;
            }

            DWORD64 dll_base = 0;

            neutralize_antidebug(pi.hProcess);
            install_gpa_hook(pi.hProcess);

            printf("\n[*] Resuming process...\n");
            ResumeThread(pi.hThread);

            if (g_is_dll) {
                printf("[*] Waiting for rundll32 to load DLL...\n");
                Sleep(2000);

                HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                                       pi.dwProcessId);
                if (snap != INVALID_HANDLE_VALUE) {
                    MODULEENTRY32W me;
                    me.dwSize = sizeof(me);

                    char abs_dll[MAX_PATH];
                    GetFullPathNameA(target, MAX_PATH, abs_dll, NULL);

                    if (Module32FirstW(snap, &me)) {
                        do {
                            char mod_path[MAX_PATH];
                            WideCharToMultiByte(CP_ACP, 0, me.szExePath, -1,
                                               mod_path, MAX_PATH, NULL, NULL);

                            if (_stricmp(mod_path, abs_dll) == 0) {
                                dll_base = (DWORD64)me.modBaseAddr;
                                printf("[+] Found DLL module at 0x%llX (size: %u)\n",
                                       (unsigned long long)dll_base, me.modBaseSize);
                                g_image_base = dll_base;
                                g_num_sections = 0;
                                read_pe_sections(pi.hProcess, dll_base);
                                break;
                            }
                        } while (Module32NextW(snap, &me));
                    }
                    CloseHandle(snap);

                    if (dll_base == 0) {
                        printf("[!] DLL not found by path. Trying filename match...\n");
                        const char *dll_name = get_basename(target);
                        snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                                       pi.dwProcessId);
                        if (snap != INVALID_HANDLE_VALUE) {
                            MODULEENTRY32W me2;
                            me2.dwSize = sizeof(me2);
                            if (Module32FirstW(snap, &me2)) {
                                do {
                                    char mod_ascii[MAX_PATH];
                                    WideCharToMultiByte(CP_ACP, 0, me2.szModule, -1,
                                                       mod_ascii, MAX_PATH, NULL, NULL);
                                    if (_stricmp(mod_ascii, dll_name) == 0) {
                                        dll_base = (DWORD64)me2.modBaseAddr;
                                        printf("[+] Found DLL module: %s at 0x%llX\n",
                                               mod_ascii, (unsigned long long)dll_base);
                                        g_image_base = dll_base;
                                        g_num_sections = 0;
                                        read_pe_sections(pi.hProcess, dll_base);
                                        break;
                                    }
                                } while (Module32NextW(snap, &me2));
                            }
                            CloseHandle(snap);
                        }
                    }

                    if (dll_base == 0) {
                        printf("[!] DLL not found in loaded modules. Dumping host process.\n");
                    }
                }
            }

            if (g_harvest_enabled) {
                harvest_init();
                detect_pesieve_path();
                take_region_snapshot(hTargetProc, g_image_base, g_size_of_image);
                harvest_log("[T+0.0s] Baseline: %d exec regions outside PE",
                            g_harvest.current.count);
                printf("[*] Harvest baseline: %d executable regions outside PE\n",
                       g_harvest.current.count);
            }

            int ticks = 0, max_ticks = (MAX_MONITOR_SEC * 1000) / POLL_INTERVAL_MS;
            int dump_done = 0;
            int first_change_tick = -1;

            while (!dump_done && ticks < max_ticks) {
                Sleep(POLL_INTERVAL_MS);
                ticks++;

                install_gpa_hook(hTargetProc);
                poll_gpa_log(hTargetProc);
                if (g_hook_cave && (ticks < 40 || ticks % 20 == 0))
                    patch_iat_slots_for_hooks(hTargetProc);

                DWORD ec;
                int alive = (GetExitCodeProcess(hTargetProc, &ec) && ec == STILL_ACTIVE);
                int changed = check_changes(hTargetProc, g_image_base);

                int harvest_trigger = 0;
                if (g_harvest_enabled && (ticks % HARVEST_SNAP_INTERVAL == 0) && alive) {
                    take_region_snapshot(hTargetProc, g_image_base, g_size_of_image);
                    check_region_changes();
                    if (g_harvest.new_this_cycle >= HARVEST_REGION_THRESHOLD)
                        harvest_trigger = 1;
                }

                if (g_harvest_enabled && (ticks % HARVEST_BEHAV_INTERVAL == 0) && alive) {
                    check_behavioral_trigger();
                    if (g_harvest.behavioral_trigger && g_harvest.current.count > 0)
                        harvest_trigger = 1;
                }

                if (changed > 0 && first_change_tick < 0) {
                    first_change_tick = ticks;
                    printf("[!] Section changes detected! Waiting 3s for VMProtect init...\n");
                }

                if (first_change_tick > 0 && (ticks - first_change_tick) * POLL_INTERVAL_MS >= 3000) {
                    if (hTargetThread) SuspendThread(hTargetThread);
                    printf("[!] VMProtect init complete. Process SUSPENDED.\n");

                    if (hTargetThread) {
                        ResumeThread(hTargetThread);
                        Sleep(500);
                        SuspendThread(hTargetThread);
                    }
                    check_changes(hTargetProc, g_image_base);
                    if (g_harvest_enabled)
                        take_region_snapshot(hTargetProc, g_image_base, g_size_of_image);

                    capture_oep(hTargetProc, hTargetThread, g_image_base,
                                g_size_of_image ? g_size_of_image : 0x1000000);
                    dump_all(hTargetProc, g_image_base, target);
                    if (g_harvest_enabled && alive) run_pesieve(pi.dwProcessId);
                    dump_done = 1;

                    capture_dropped_files(target_dir);
                    capture_dropped_files(".");

                    printf("[*] Terminating process.\n");
                    TerminateProcess(hTargetProc, 0);
                }

                if (harvest_trigger && !dump_done && first_change_tick < 0) {
                    printf("[!] HARVEST TRIGGER: %s at %.1fs\n",
                           g_harvest.new_this_cycle >= HARVEST_REGION_THRESHOLD
                             ? "3+ new executable regions"
                             : "behavioral signal + regions",
                           (float)(ticks * POLL_INTERVAL_MS) / 1000.0f);
                    harvest_log("[T+%.1fs] DUMP TRIGGER: %s",
                                (float)(ticks * POLL_INTERVAL_MS) / 1000.0f,
                                g_harvest.new_this_cycle >= HARVEST_REGION_THRESHOLD
                                  ? "REGION_THRESHOLD" : "BEHAVIORAL");
                    Sleep(HARVEST_SETTLE_MS);
                    take_region_snapshot(hTargetProc, g_image_base, g_size_of_image);
                    if (hTargetThread) SuspendThread(hTargetThread);

                    capture_oep(hTargetProc, hTargetThread, g_image_base,
                                g_size_of_image ? g_size_of_image : 0x1000000);
                    dump_all(hTargetProc, g_image_base, target);
                    if (alive) run_pesieve(pi.dwProcessId);
                    dump_done = 1;
                    capture_dropped_files(target_dir);
                    capture_dropped_files(".");
                    TerminateProcess(hTargetProc, 0);
                }

                if (!alive && !dump_done) {
                    printf("[!] Process exited (code %u) at %.1fs\n", (unsigned)ec,
                           (float)(ticks * POLL_INTERVAL_MS) / 1000.0f);
                    printf("[!] Cannot capture OEP -- process already dead\n");
                    if (g_harvest_enabled)
                        take_region_snapshot(hTargetProc, g_image_base, g_size_of_image);
                    dump_all(hTargetProc, g_image_base, target);
                    capture_dropped_files(target_dir);
                    capture_dropped_files(".");
                    dump_done = 1;
                }

                if (ticks % 200 == 0 && !dump_done)
                    printf("    ... monitoring (%.0fs) sections=%d regions=%d\n",
                           (float)(ticks * POLL_INTERVAL_MS) / 1000.0f,
                           changed, g_harvest_enabled ? g_harvest.current.count : 0);
            }

            if (!dump_done) {
                printf("[!] Timeout (%ds). Dumping current state...\n", MAX_MONITOR_SEC);
                if (hTargetThread) SuspendThread(hTargetThread);
                if (g_harvest_enabled)
                    take_region_snapshot(hTargetProc, g_image_base, g_size_of_image);
                capture_oep(hTargetProc, hTargetThread, g_image_base,
                            g_size_of_image ? g_size_of_image : 0x1000000);
                dump_all(hTargetProc, g_image_base, target);
                if (g_harvest_enabled) run_pesieve(pi.dwProcessId);
                capture_dropped_files(target_dir);
                TerminateProcess(hTargetProc, 0);
            }

            if (g_harvest_enabled)
                write_harvest_report(ticks * POLL_INTERVAL_MS);

            CloseHandle(hTargetProc);
            if (hTargetThread) CloseHandle(hTargetThread);
        }

    }

    int zip_ok = create_password_zip(g_output_dir);

    printf("\n=======================================================\n");
    printf("  DONE!\n");
    printf("  Dump folder : %s\n", g_output_dir);
    if (zip_ok) {
        printf("  Archive     : %s\n", g_zip_path);
        printf("  Password    : virus\n");
        printf("  To extract  : rename .dat -> .zip\n");
    }
    printf("  Files:\n");
    printf("    *_dumped.bin          Full PE dump with repairs (IDA + rename to .exe)\n");
    printf("    *_0x*.bin             Individual section dumps\n");
    printf("    resolved_imports.txt  IAT reconstruction + slot RVAs\n");
    printf("    dump_metadata.json    PE structure & IAT metadata\n");
    printf("    repair_summary.json   OEP + IAT repair results\n");
    printf("    extracted_strings.txt Heap IOCs & config\n");
    printf("    harvest_report.txt    Memory Harvester results\n");
    printf("    region_*.bin          Dynamic executable regions\n");
    printf("    pesieve_out/          PE-sieve scan results\n");
    printf("=======================================================\n");

    {
        char sum_path[MAX_PATH];
        snprintf(sum_path, sizeof(sum_path), "%s\\repair_summary.json", g_output_dir);
        FILE *sf = fopen(sum_path, "w");
        if (sf) {
            LONG ic = g_import_count;
            if (ic > MAX_IMPORTS) ic = MAX_IMPORTS;
            int named = 0;
            for (int i = 0; i < g_resolved_iat_count; i++)
                if (g_resolved_iat[i].import_idx >= 0) named++;

            fprintf(sf, "{\n");
            fprintf(sf, "  \"version\": \"5.0\",\n");
            fprintf(sf, "  \"machine\": \"0x%04X\",\n", (unsigned)g_machine);
            fprintf(sf, "  \"machine_name\": \"%s\",\n",
                    g_machine == 0x8664 ? "x64" : g_machine == 0x14C ? "x86" : "unknown");
            fprintf(sf, "  \"image_base\": \"0x%llX\",\n", (unsigned long long)g_image_base);
            fprintf(sf, "  \"size_of_image\": \"0x%llX\",\n", (unsigned long long)g_size_of_image);
            fprintf(sf, "  \"oep_captured\": %s,\n", g_oep_captured ? "true" : "false");
            fprintf(sf, "  \"oep_rva\": \"0x%08lX\",\n", (unsigned long)g_oep_rva);
            fprintf(sf, "  \"oep_source\": \"%s\",\n",
                    g_oep_crt_rva != 0 ? "crt_pattern" :
                    g_oep_thread_rva != 0 ? "thread_ip" : "none");
            fprintf(sf, "  \"oep_thread_rva\": \"0x%08lX\",\n", (unsigned long)g_oep_thread_rva);
            fprintf(sf, "  \"oep_crt_rva\": \"0x%08lX\",\n", (unsigned long)g_oep_crt_rva);
            fprintf(sf, "  \"exports_cataloged\": %ld,\n", (long)ic);
            fprintf(sf, "  \"iat_thunks_resolved\": %d,\n", g_resolved_iat_count);
            fprintf(sf, "  \"iat_named_imports\": %d,\n", named);
            fprintf(sf, "  \"iat_slots_scanned\": %d,\n", g_iat_slot_count);
            fprintf(sf, "  \"gpa_hook_installed\": %d,\n", g_hook_installed_count);
            fprintf(sf, "  \"vid_fixes\": %d,\n", g_vid_fix_count);
            fprintf(sf, "  \"orig_imports_parsed\": %d,\n", g_orig_import_count);

            fprintf(sf, "  \"resolved_iat\": [\n");
            for (int i = 0; i < g_resolved_iat_count; i++) {
                ResolvedIATEntry *re = &g_resolved_iat[i];
                fprintf(sf, "    {\"iat_rva\": \"0x%08lX\", ", (unsigned long)re->iat_rva);
                fprintf(sf, "\"thunk_addr\": \"0x%llX\", ", (unsigned long long)re->thunk_addr);
                fprintf(sf, "\"resolved_addr\": \"0x%llX\"", (unsigned long long)re->resolved_addr);
                if (re->import_idx >= 0) {
                    fprintf(sf, ", \"module\": \"");
                    json_escape(sf, re->module);
                    fprintf(sf, "\", \"function\": \"");
                    json_escape(sf, re->function);
                    fprintf(sf, "\"");
                }
                fprintf(sf, "}%s\n", (i < g_resolved_iat_count - 1) ? "," : "");
            }
            fprintf(sf, "  ]\n");
            fprintf(sf, "}\n");
            fclose(sf);
            printf("\n  Repair summary: %s\n", sum_path);
            printf("  OEP: 0x%08lX (%s) | IAT patched: %d | Named: %d\n",
                   (unsigned long)g_oep_rva,
                   g_oep_crt_rva != 0 ? "CRT" : g_oep_thread_rva != 0 ? "TIP" : "none",
                   g_resolved_iat_count, named);
        }
    }

    if (!g_no_pause) {
        printf("\nPress Enter to exit...");
        getchar();
    }
    return 0;
}
