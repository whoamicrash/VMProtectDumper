#include "vmpd.h"

DWORD64      g_image_base = 0;

DWORD        g_size_of_image = 0;

char         g_output_dir[MAX_PATH] = ".";

static char         g_dll_export[256] = "";

static int          g_is_dll = 0;

static int          g_is_service_dll = 0;

static int          g_no_pause = 0;

static char         g_wait_for_process[MAX_PATH] = "";

static int          g_force_direct = 0;

static int          g_force_dropper = 0;

static int          g_dropper_timeout = 60;

int  g_no_smt = 0;

static int  g_no_hooks = 0;

static int  g_no_antidebug = 0;

DWORD        g_oep_thread_rva = 0;

DWORD        g_oep_crt_rva = 0;

int          g_harvest_enabled = 1;

long g_smt_resolved = -1;

long g_smt_unresolved = 0;

long g_smt_already_real = 0;

long g_smt_collatz = 0;

long g_smt_bombs = 0;

unsigned long long g_smt_instr = 0;

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
    smt_run(target_name);
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

const char* get_basename(const char *path)
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

char g_zip_path[MAX_PATH] = "";

char g_zip_password[256] = "";

static void write_repair_summary(void)
{
    char sum_path[MAX_PATH];
    snprintf(sum_path, sizeof(sum_path), "%s\\repair_summary.json", g_output_dir);
    FILE *sf = fopen(sum_path, "w");
    if (!sf) return;
    LONG ic = g_import_count;
    if (ic > MAX_IMPORTS) ic = MAX_IMPORTS;
    int named = 0;
    for (int i = 0; i < g_resolved_iat_count; i++)
        if (g_resolved_iat[i].import_idx >= 0 || g_resolved_iat[i].module[0] != '\0') named++;

    fprintf(sf, "{\n");
    fprintf(sf, "  \"version\": \"" VMPD_VERSION "\",\n");
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
    fprintf(sf, "  \"smt_resolved\": %ld,\n", g_smt_resolved);
    fprintf(sf, "  \"smt_unresolved\": %ld,\n", g_smt_unresolved);
    fprintf(sf, "  \"smt_already_real\": %ld,\n", g_smt_already_real);
    fprintf(sf, "  \"smt_collatz_bypasses\": %ld,\n", g_smt_collatz);
    fprintf(sf, "  \"smt_loop_bombs\": %ld,\n", g_smt_bombs);
    fprintf(sf, "  \"smt_instructions\": %llu,\n", (unsigned long long)g_smt_instr);

    fprintf(sf, "  \"resolved_iat\": [\n");
    for (int i = 0; i < g_resolved_iat_count; i++) {
        ResolvedIATEntry *re = &g_resolved_iat[i];
        fprintf(sf, "    {\"iat_rva\": \"0x%08lX\", ", (unsigned long)re->iat_rva);
        fprintf(sf, "\"thunk_addr\": \"0x%llX\", ", (unsigned long long)re->thunk_addr);
        fprintf(sf, "\"resolved_addr\": \"0x%llX\"", (unsigned long long)re->resolved_addr);
        if (re->import_idx >= 0 || re->module[0] != '\0') {
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

int main(int argc, char *argv[])
{
    printf("  VMProtect Dumper v" VMPD_VERSION " (SMT engine) - don't sell source code\n");

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
        printf("  --pesieve-path=PATH Path to pe-sieve exe (default: auto-detect)\n");
        printf("  --zip-password=PW   Protect the output archive with your own password\n");
        printf("                      (without this argument the archive is NOT encrypted)\n");
        printf("  --no-smt            Disable the SMT post-dump analysis engine\n");
        printf("                      (default: enabled, writes smt_*.txt/json reports)\n");
        printf("  --no-hooks          Disable inline GetProcAddress/LoadLibrary hooks\n");
        printf("                      (read-based IAT rebuild + SMT engine stay active)\n");
        printf("  --no-antidebug      Do not neutralize anti-debug checks in the target\n\n");
        printf("DLL examples:\n");
        printf("  %s target.dll\n", argv[0]);
        printf("  %s target.dll --dll-export=ServiceMain\n", argv[0]);
        printf("  %s target.dll --dll-export=#1\n", argv[0]);
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
        } else if (strncmp(argv[i], "--zip-password=", 15) == 0) {
            strncpy(g_zip_password, argv[i] + 15, sizeof(g_zip_password) - 1);
            g_zip_password[sizeof(g_zip_password) - 1] = '\0';
        } else if (strcmp(argv[i], "--no-smt") == 0) {
            g_no_smt = 1;
        } else if (strcmp(argv[i], "--no-hooks") == 0) {
            g_no_hooks = 1;
        } else if (strcmp(argv[i], "--no-antidebug") == 0) {
            g_no_antidebug = 1;
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
            printf("[+] Launched dropper PID=%lu\n", (unsigned long)pi2.dwProcessId);
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

            if (g_no_antidebug) printf("[*] Anti-debug neutralization disabled (--no-antidebug)\n");
            else neutralize_antidebug(hTargetProc);
            if (g_no_hooks) printf("[*] GPA hooks disabled (--no-hooks)\n");
            else install_gpa_hook(hTargetProc);

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

                if (!g_no_hooks) {
                    install_gpa_hook(hTargetProc);
                    poll_gpa_log(hTargetProc);
                    if (g_hook_cave && (ticks < 40 || ticks % 20 == 0))
                        patch_iat_slots_for_hooks(hTargetProc);
                }

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
            printf("[+] PID=%lu TID=%lu\n", (unsigned long)pi.dwProcessId, (unsigned long)pi.dwThreadId);
            hTargetProc = pi.hProcess;
            hTargetThread = pi.hThread;
            target_pid = pi.dwProcessId;

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

            if (g_no_antidebug) printf("[*] Anti-debug neutralization disabled (--no-antidebug)\n");
            else neutralize_antidebug(pi.hProcess);
            if (g_no_hooks) printf("[*] GPA hooks disabled (--no-hooks)\n");
            else install_gpa_hook(pi.hProcess);

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
                                printf("[+] Found DLL module at 0x%llX (size: %lu)\n",
                                       (unsigned long long)dll_base, (unsigned long)me.modBaseSize);
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

                if (!g_no_hooks) {
                    install_gpa_hook(hTargetProc);
                    poll_gpa_log(hTargetProc);
                    if (g_hook_cave && (ticks < 40 || ticks % 20 == 0))
                        patch_iat_slots_for_hooks(hTargetProc);
                }

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

    write_repair_summary();

    int zip_ok = create_output_zip(g_output_dir);

    printf("\n=======================================================\n");
    printf("  DONE!\n");
    printf("  Dump folder : %s\n", g_output_dir);
    if (zip_ok) {
        printf("  Archive     : %s\n", g_zip_path);
        if (g_zip_password[0]) {
            printf("  Password    : (user-supplied via --zip-password)\n");
            printf("  To extract  : rename .dat -> .zip, unzip with your password\n");
        } else {
            printf("  Password    : none (plain ZIP, --zip-password not set)\n");
            printf("  To extract  : rename .dat -> .zip\n");
        }
    }
    printf("  Files:\n");
    printf("    *_dumped.bin          Full PE dump with repairs (IDA + rename to .exe)\n");
    printf("    *_0x*.bin             Individual section dumps\n");
    printf("    resolved_imports.txt  IAT reconstruction + slot RVAs\n");
    printf("    dump_metadata.json    PE structure & IAT metadata\n");
    printf("    repair_summary.json   OEP + IAT repair results\n");
    printf("    extracted_strings.txt Raw strings from process memory\n");
    printf("    harvest_report.txt    Memory Harvester results\n");
    printf("    region_*.bin          Dynamic executable regions\n");
    printf("    pesieve_out/          PE-sieve scan results\n");
    printf("=======================================================\n");

    if (!g_no_pause) {
        printf("\nPress Enter to exit...");
        getchar();
    }
    return 0;
}

