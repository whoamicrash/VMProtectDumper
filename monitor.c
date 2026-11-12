#include "vmpd.h"

WORD         g_machine = 0;

HarvestState g_harvest;

static char     g_harvest_watch_dirs[MAX_WATCH_DIRS_FWD][MAX_PATH];

static int      g_harvest_watch_count = 0;

void scan_process_strings(HANDLE hProc)
{
    printf("\n[*] Extracting raw strings from process memory...\n");

    char report_path[MAX_PATH];
    snprintf(report_path, sizeof(report_path), "%s\\extracted_strings.txt", g_output_dir);
    FILE *report = fopen(report_path, "w");
    if (!report) {
        printf("[-] Cannot create string report\n");
        return;
    }

    fprintf(report, "=== VMProtect Dumper v6.0 - Extracted Strings (raw) ===\n\n");

    MEMORY_BASIC_INFORMATION mbi;
    DWORD64 addr = 0x10000;
    int total_regions = 0;
    int total_strings = 0;

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
                            DWORD64 saddr = region_base + off + str_start;
                            fprintf(report, "0x%016llX: %s\n",
                                    (unsigned long long)saddr, tmp);
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
                            DWORD64 saddr = region_base + off + str_start;
                            fprintf(report, "0x%016llX W: %s\n",
                                    (unsigned long long)saddr, tmp);
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
    fprintf(report, "Strings extracted: %d\n", total_strings);
    fclose(report);
    free(page_buf);

    printf("[+] Strings extracted: %d -> %s\n", total_strings, report_path);
}

void capture_dropped_files(const char *target_dir)
{
    printf("\n[*] Scanning for dropped files...\n");

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
        if (strstr(name, ".txt") || strstr(name, ".TXT") ||
            strstr(name, ".html") || strstr(name, ".htm") ||
            strstr(name, ".hta") || strstr(name, ".ini") ||
            strstr(name, ".log") || strstr(name, ".cfg"))
        {
            is_note = 1;
        }

        const char *ext = strrchr(name, '.');
        int is_pe = 0;
        if (ext && (_stricmp(ext, ".exe") == 0 || _stricmp(ext, ".dll") == 0 ||
                    _stricmp(ext, ".scr") == 0 || _stricmp(ext, ".com") == 0 ||
                    _stricmp(ext, ".pif") == 0 || _stricmp(ext, ".sys") == 0)) {
            is_pe = 1;
        }

        if (is_note || is_pe) {

            char src[MAX_PATH], dst[MAX_PATH];
            snprintf(src, sizeof(src), "%s\\%s", target_dir, name);
            snprintf(dst, sizeof(dst), "%s\\%s", g_output_dir,
                     is_pe ? name : name);

            if (CopyFileA(src, dst, FALSE)) {
                printf("[+] Captured dropped file%s: %s (%lu bytes)\n",
                       is_pe ? " (PE)" : "", name, fd.nFileSizeLow);
                found++;
            }
        }
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);

    if (found == 0) printf("    No dropped files found in %s\n", target_dir);
}

void kill_monitor_processes(int kill_vmtools)
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
        "cuckoomon.exe",
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

static DWORD harvest_start_tick = 0;

static float harvest_elapsed_sec(void)
{
    return (float)(GetTickCount() - harvest_start_tick) / 1000.0f;
}

void harvest_init(void)
{
    char saved_pesieve[MAX_PATH];
    strncpy(saved_pesieve, g_harvest.pesieve_path, MAX_PATH - 1);
    saved_pesieve[MAX_PATH - 1] = '\0';
    memset(&g_harvest, 0, sizeof(g_harvest));
    if (saved_pesieve[0])
        strncpy(g_harvest.pesieve_path, saved_pesieve, MAX_PATH - 1);
    harvest_start_tick = GetTickCount();

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

void harvest_log(const char *fmt, ...)
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

int take_region_snapshot(HANDLE hProc, DWORD64 image_base, DWORD soi)
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

int check_region_changes(void)
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
                        harvest_elapsed_sec(),
                        g_harvest.current.index,
                        ADDR_CAST(cr->base_addr), (unsigned)cr->size);
        }
        if (cr->fp_changed) {
            fp_changes++;
            harvest_log("[T+%.1fs] Snap #%d: CHANGED fp at " ADDR_FMT,
                        harvest_elapsed_sec(),
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
                        harvest_elapsed_sec(),
                        g_harvest.current.index,
                        ADDR_CAST(g_harvest.previous.regions[j].base_addr));
        }
    }

    g_harvest.new_this_cycle = new_count;
    g_harvest.disappeared += disappeared;
    g_harvest.fp_changes += fp_changes;
    return new_count + fp_changes;
}

int dump_dynamic_regions(HANDLE hProc)
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

void detect_pesieve_path(void)
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

int run_pesieve(DWORD target_pid)
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

int check_behavioral_trigger(void)
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
                    harvest_elapsed_sec(), new_files);
    }
    return new_files;
}

void write_harvest_report(DWORD total_elapsed_ms)
{
    char rpath[MAX_PATH];
    snprintf(rpath, sizeof(rpath), "%s\\harvest_report.txt", g_output_dir);

    FILE *f = fopen(rpath, "w");
    if (!f) return;

    fprintf(f, "=== Clarity Memory Harvester v" VMPD_VERSION " Report ===\n");
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

