#include "vmpd.h"

SectionInfo  g_sections[MAX_SECTIONS];

int          g_num_sections = 0;

DWORD        g_oep_rva = 0;

int          g_oep_captured = 0;

static pfnNtQueryInformationProcess g_NtQueryInformationProcess = NULL;

int detect_target_architecture_vmp(HANDLE hProcess, DWORD64 *out_image_base)
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

int read_pe_sections(HANDLE hProc, DWORD64 base)
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
    if (pe_off + 24 + (DWORD)opt_size + (DWORD)num_secs * 40 > sizeof(hdr)) {
        printf("[-] PE section table out of bounds (pe_off=0x%X opt=0x%X secs=%u)\n",
               pe_off, opt_size, (unsigned)num_secs);
        return 0;
    }

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

int check_changes(HANDLE hProc, DWORD64 base)
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

void capture_oep(HANDLE hProc, HANDLE hThread, DWORD64 base, DWORD soi)
{
    DWORD thread_rva = 0;
    DWORD crt_rva = 0;

    printf("\n[*] Capturing OEP...\n");

    if (hThread) {
        if (g_machine == IMAGE_FILE_MACHINE_I386) {
            WOW64_CONTEXT wctx;
            memset(&wctx, 0, sizeof(wctx));
            wctx.ContextFlags = WOW64_CONTEXT_CONTROL;
            if (Wow64GetThreadContext(hThread, &wctx)) {
                DWORD64 ip = wctx.Eip;
                if (ip >= base && ip < base + soi) {
                    thread_rva = (DWORD)(ip - base);
                    printf("[+] Thread IP at suspend (WOW64): RVA=0x%08X (VA=0x%llX)\n",
                           thread_rva, (unsigned long long)ip);
                } else {
                    printf("[*] Thread IP outside image (WOW64): VA=0x%llX\n",
                           (unsigned long long)ip);
                }
            } else {
                printf("[-] Wow64GetThreadContext failed (error %u)\n",
                       (unsigned)GetLastError());
            }
        } else {
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

int dump_section(HANDLE hProc, DWORD64 base, SectionInfo *si, int idx)
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

void dump_full_image(HANDLE hProc, DWORD64 base, const char *target_name)
{
    BYTE hdr[4096];
    SIZE_T nr;
    if (!ReadProcessMemory(hProc, (LPCVOID)base, hdr, sizeof(hdr), &nr) || nr < 256)
        return;

    DWORD pe_off = *(DWORD*)(hdr + 0x3C);
    if (pe_off == 0 || pe_off + 256 > sizeof(hdr) ||
        hdr[pe_off] != 'P' || hdr[pe_off + 1] != 'E') {
        printf("[-] PE header offset invalid (0x%X)\n", pe_off);
        return;
    }
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
    if (pe_off != 0 && pe_off + 256 < soi && buf[pe_off] == 'P' && buf[pe_off + 1] == 'E') {
        BYTE *pe = buf + pe_off;

        if (machine == 0x8664) {
            *(DWORD64*)(pe + 24 + 24) = base;
        } else {
            *(DWORD*)(pe + 24 + 28) = (DWORD)base;
        }

        WORD ns = *(WORD*)(pe + 6);
        WORD os = *(WORD*)(pe + 20);
        if ((DWORD)ns > MAX_SECTIONS) ns = MAX_SECTIONS;
        if (pe_off + 24 + (DWORD)os + (DWORD)ns * 40 >= soi) {
            printf("[-] section table out of image bounds, header repair skipped\n");
            ns = 0;
        }
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
    printf("[+] Full PE dump: %s (%lu bytes, %.1f MB)\n", fname, (unsigned long)soi, soi / (1024.0 * 1024.0));
    free(buf);
}

void log_import(const char *module, const char *function, DWORD64 addr)
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

