#include "vmpd.h"


HANDLE launch_service_dll(const char *dll_path, DWORD64 *out_dll_base, DWORD *out_pid)
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
        if (err == 1053) printf(" (timeout - service may still be loaded)");
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
        printf("[+] Service PID: %lu  State: %lu\n", (unsigned long)service_pid, (unsigned long)ssp.dwCurrentState);
    } else {
        printf("[!] QueryServiceStatusEx failed (error %u)\n", (unsigned)GetLastError());
    }

    HANDLE hProc = NULL;

    if (service_pid != 0) {
        hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, service_pid);
        if (!hProc) {
            printf("[-] OpenProcess PID=%lu failed (error %u)\n",
                   (unsigned long)service_pid, (unsigned)GetLastError());
        } else {
            printf("[+] Attached to svchost PID=%lu\n", (unsigned long)service_pid);

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
                            printf("[+] Found DLL at 0x%llX (size: %lu)\n",
                                   (unsigned long long)*out_dll_base, (unsigned long)me.modBaseSize);
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

void cleanup_temp_service(void)
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

