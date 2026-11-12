#include "vmpd.h"
#include <math.h>

static FSEntry  g_fs_snapshot[MAX_SNAPSHOT_FILES];

static int      g_fs_count = 0;

static char     g_watch_dirs[MAX_WATCH_DIRS][MAX_PATH];

static int      g_watch_dir_count = 0;

char     g_self_path[MAX_PATH] = "";

static DWORD    g_baseline_pids[MAX_BASELINE_PIDS];

static int      g_baseline_pid_count = 0;

int check_file_for_packer(const char *filepath, PackerCheckResult *result)
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

int attach_and_assess(HANDLE hProc, HANDLE hThread, DWORD64 image_base)
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
        DWORD hist[256];
        memset(hist, 0, sizeof(hist));
        for (int j = 0; j < FINGERPRINT_SIZE; j++) {
            if (si->fingerprint[j] != 0) nz++;
            hist[si->fingerprint[j]]++;
        }
        double H = 0.0;
        for (int k = 0; k < 256; k++) {
            if (!hist[k]) continue;
            double p = (double)hist[k] / (double)FINGERPRINT_SIZE;
            H -= p * log(p) / log(2.0);
        }
        int dense = nz > (int)(FINGERPRINT_SIZE * 0.8);
        int plausible_code = (H >= 3.0 && H <= 7.2);
        if (dense && plausible_code)
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

int wait_for_named_process(const char *proc_name, int timeout_sec, TargetInfo *found)
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
                    printf("[+] Found '%s' (PID %lu) at %.1fs\n",
                           proc_name, (unsigned long)pe.th32ProcessID,
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

int dropper_mode(const char *target_exe, int timeout_sec, TargetInfo *found)
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
    snprintf(cmdline, sizeof(cmdline), "\"%s\"", target_exe);

    printf("[*] Launching dropper (normal, not suspended)...\n");
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcess failed for dropper (error %u)\n", (unsigned)GetLastError());
        return 0;
    }
    printf("[+] Dropper PID=%lu\n", (unsigned long)pi.dwProcessId);
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
                            printf("[+] MATCHED PROCESS: PID %lu (%s)\n", (unsigned long)new_pids[p], img_path);
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
                    printf("[+] PACKED PROCESS: PID %lu (%s) - %s\n",
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

void write_dropper_info(const char *original, const char *payload, DWORD pid,
                               const char *method, float discovery_time)
{
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s\\dropper_mode_info.txt", g_output_dir);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "Dropper Mode Activated\n");
    fprintf(f, "Original Sample: %s\n", original);
    fprintf(f, "Packed Payload: %s\n", payload);
    fprintf(f, "Payload PID: %lu\n", (unsigned long)pid);
    fprintf(f, "Discovery Method: %s\n", method);
    fprintf(f, "Discovery Time: %.1f seconds\n", discovery_time);
    fclose(f);
    printf("[+] Wrote dropper_mode_info.txt\n");
}

