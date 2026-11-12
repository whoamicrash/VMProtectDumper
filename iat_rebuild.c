#include "vmpd.h"

ImportEntry  g_imports[MAX_IMPORTS];

volatile LONG g_import_count = 0;

IATSlotEntry g_iat_slots[MAX_IAT_SLOTS];

int          g_iat_slot_count = 0;

static OrigImport g_orig_imports[MAX_ORIG_IMPORTS];

int        g_orig_import_count = 0;

static VidFixEntry g_vid_fixes[MAX_VID_FIXES];

int         g_vid_fix_count = 0;

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
            memcpy(oi->dll, dll, sizeof(oi->dll) - 1);
            oi->dll[sizeof(oi->dll) - 1] = '\0';

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

static void vid_build_fresh_import_dir(const char *dump_path, const char *target_name);

void rebuild_imports_vid(HANDLE hProc, DWORD64 base, const char *target_name)
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
    if (pe_off == 0 || pe_off + 264 > sizeof(hdr) ||
        hdr[pe_off] != 'P' || hdr[pe_off + 1] != 'E') {
        printf("[-] VID: target PE header offset invalid (0x%lX)\n", (unsigned long)pe_off);
        return;
    }
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
                if (WriteProcessMemory(hProc, (LPVOID)(ULONG_PTR)slot_addr,
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
    char vid_dump_path[MAX_PATH];
    const char *vbn = get_basename(target_name);
    if (!vbn) vbn = target_name;
    snprintf(vid_dump_path, sizeof(vid_dump_path), "%s\\%s_dumped.bin",
             g_output_dir, vbn);
    vid_build_fresh_import_dir(vid_dump_path, target_name);
}
static void wr_imp_word(BYTE *p, DWORD v)
{
    p[0] = (BYTE)(v & 0xFF);
    p[1] = (BYTE)((v >> 8) & 0xFF);
}

static void wr_imp_dword(BYTE *p, DWORD v)
{
    for (int i = 0; i < 4; i++) p[i] = (BYTE)((v >> (8 * i)) & 0xFF);
}

static void wr_imp_qword(BYTE *p, DWORD64 v)
{
    for (int i = 0; i < 8; i++) p[i] = (BYTE)((v >> (8 * i)) & 0xFF);
}

static DWORD vid_align_up(DWORD v, DWORD a)
{
    return (a == 0) ? v : ((v + a - 1) & ~(a - 1));
}

static void vid_build_fresh_import_dir(const char *dump_path, const char *target_name)
{
    (void)target_name;
    FILE *f = fopen(dump_path, "r+b");
    if (!f) {
        printf("[-] VID step 4: cannot open dump %s\n", dump_path);
        return;
    }

    BYTE hdr[4096];
    if (fread(hdr, 1, sizeof(hdr), f) != sizeof(hdr)) { fclose(f); return; }
    if (hdr[0] != 'M' || hdr[1] != 'Z') { fclose(f); return; }
    DWORD pe_off = *(DWORD*)(hdr + 0x3C);
    if (pe_off == 0 || pe_off + 264 > sizeof(hdr) ||
        hdr[pe_off] != 'P' || hdr[pe_off + 1] != 'E') {
        printf("[-] VID step 4: dump PE header invalid\n");
        fclose(f);
        return;
    }
    BYTE *pe = hdr + pe_off;
    WORD machine = *(WORD*)(pe + 4);
    int ptr_size = (machine == 0x8664) ? 8 : 4;
    int dd_base = (machine == 0x8664) ? (24 + 112) : (24 + 96);
    DWORD sect_align = *(DWORD*)(pe + 24 + 32);
    DWORD file_align = *(DWORD*)(pe + 24 + 36);
    DWORD size_of_image = *(DWORD*)(pe + 24 + 56);
    WORD ns = *(WORD*)(pe + 6);
    if (sect_align == 0) sect_align = 0x1000;
    if (file_align == 0) file_align = 0x200;
    if (ns >= 16) {
        printf("[!] VID step 4: no free section header slot (ns=%u), skipped\n", ns);
        fclose(f);
        return;
    }

    const char *dlls[256];
    char dllbuf[256][64];
    int ndll = 0;
    int per_dll[256];
    for (int i = 0; i < 256; i++) per_dll[i] = 0;
    for (int i = 0; i < g_vid_fix_count && ndll < 256; i++) {
        int found = -1;
        for (int k = 0; k < ndll; k++)
            if (_stricmp_null_safe(dllbuf[k], g_vid_fixes[i].module) == 0) { found = k; break; }
        if (found < 0) {
            strncpy(dllbuf[ndll], g_vid_fixes[i].module, 63);
            dllbuf[ndll][63] = 0;
            found = ndll++;
        }
        per_dll[found]++;
        (void)dlls;
    }
    if (ndll == 0) {
        printf("[*] VID step 4: no resolved imports recorded, fresh import directory skipped\n");
        fclose(f);
        return;
    }

    DWORD idt_len = (DWORD)(ndll + 1) * 20;
    DWORD int_len = 0, name_len = 0;
    for (int k = 0; k < ndll; k++) {
        int_len += (DWORD)(per_dll[k] + 1) * ptr_size;
        name_len += (DWORD)strlen(dllbuf[k]) + 6;
        name_len += 2;
        for (int i = 0; i < g_vid_fix_count; i++) {
            if (_stricmp_null_safe(g_vid_fixes[i].module, dllbuf[k]) == 0)
                name_len += (DWORD)strlen(g_vid_fixes[i].function) + 4;
        }
    }
    DWORD ft_len = int_len;
    DWORD blob_len = idt_len + int_len + ft_len + name_len + 64;

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    DWORD vid_rva = vid_align_up(size_of_image, sect_align);
    DWORD vid_raw = vid_align_up((DWORD)fsize, file_align);
    DWORD vid_vlen = vid_align_up(blob_len, sect_align);

    BYTE *blob = (BYTE*)calloc(1, blob_len);
    if (!blob) { fclose(f); return; }

    DWORD name_off = idt_len;
    DWORD names_end = idt_len;
    for (int k = 0; k < ndll; k++) {
        names_end += (DWORD)strlen(dllbuf[k]) + 1;
    }
    DWORD ibn_off = names_end;
    for (int k = 0; k < ndll; k++) ibn_off += (DWORD)strlen(dllbuf[k]) + 1;
    DWORD int_arrays = ibn_off;
    for (int i = 0; i < g_vid_fix_count; i++)
        int_arrays += (DWORD)strlen(g_vid_fixes[i].function) + 1;
    int_arrays = vid_align_up(int_arrays, 16);

    DWORD cursor_int = int_arrays;
    DWORD cursor_ft = int_arrays + int_len;
    BYTE *idt = blob;
    DWORD e = 0;
    for (int k = 0; k < ndll; k++) {
        DWORD name_rva = vid_rva + name_off;
        wr_imp_dword(idt + e * 20 + 12, name_rva);
        DWORD oft_rva = vid_rva + cursor_int;
        wr_imp_dword(idt + e * 20 + 0, oft_rva);
        DWORD ft_rva = vid_rva + cursor_ft;
        wr_imp_dword(idt + e * 20 + 16, ft_rva);

        DWORD ii = cursor_int;
        DWORD ff = cursor_ft;
        for (int i = 0; i < g_vid_fix_count; i++) {
            if (_stricmp_null_safe(g_vid_fixes[i].module, dllbuf[k]) != 0) continue;
            BYTE *ibn = blob + ibn_off;
            wr_imp_word(ibn, 0);
            strcpy((char*)ibn + 2, g_vid_fixes[i].function);
            DWORD ibn_rva = vid_rva + ibn_off;
            DWORD ord_flag = (machine == 0x8664) ? 0x8000000000000000ULL : 0x80000000UL;
            (void)ord_flag;
            if (ptr_size == 8) {
                wr_imp_qword(blob + ii, ibn_rva);
                wr_imp_qword(blob + ff, g_vid_fixes[i].resolved_addr);
                ii += 8;
                ff += 8;
            } else {
                wr_imp_dword(blob + ii, ibn_rva);
                wr_imp_dword(blob + ff, (DWORD)g_vid_fixes[i].resolved_addr);
                ii += 4;
                ff += 4;
            }
            ibn_off += (DWORD)strlen(g_vid_fixes[i].function) + 3;
        }
        if (ptr_size == 8) {
            wr_imp_qword(blob + ii, 0);
            wr_imp_qword(blob + ff, 0);
        } else {
            wr_imp_dword(blob + ii, 0);
            wr_imp_dword(blob + ff, 0);
        }
        cursor_int += (DWORD)(per_dll[k] + 1) * ptr_size;
        cursor_ft += (DWORD)(per_dll[k] + 1) * ptr_size;
        e++;
    }
    for (int k = 0; k < ndll; k++) {
        strcpy((char*)blob + name_off, dllbuf[k]);
        name_off += (DWORD)strlen(dllbuf[k]) + 1;
    }

    fseek(f, (long)vid_raw, SEEK_SET);
    fwrite(blob, 1, blob_len, f);

    *(DWORD*)(pe + dd_base + 0) = vid_rva;
    *(DWORD*)(pe + dd_base + 4) = idt_len;
    *(DWORD*)(pe + 24 + 56) = vid_rva + vid_vlen;

    BYTE *sh = hdr + pe_off + 24 + (machine == 0x8664 ? 240 : 224) + (DWORD)ns * 40;
    memset(sh, 0, 40);
    memcpy(sh, ".vid", 4);
    *(DWORD*)(sh + 8)  = blob_len;
    *(DWORD*)(sh + 12) = vid_rva;
    *(DWORD*)(sh + 16) = blob_len;
    *(DWORD*)(sh + 20) = vid_raw;
    *(DWORD*)(sh + 36) = 0xC0000040;
    *(WORD*)(pe + 6) = (WORD)(ns + 1);

    fseek(f, 0, SEEK_SET);
    fwrite(hdr, 1, sizeof(hdr), f);
    fclose(f);
    free(blob);

    printf("[+] VID step 4: fresh import directory built in dump: %d DLL(s), %d function(s),\n"
           "    section .vid RVA=0x%08lX raw=0x%08lX len=0x%lX, DD1 -> 0x%08lX/0x%lX, SizeOfImage=0x%lX\n",
           ndll, g_vid_fix_count, (unsigned long)vid_rva, (unsigned long)vid_raw, (unsigned long)blob_len, (unsigned long)vid_rva, (unsigned long)idt_len,
           (unsigned long)(vid_rva + vid_vlen));
}


void reconstruct_iat(HANDLE hProc, DWORD64 base)
{
    printf("\n[*] Reconstructing IAT from loaded modules...\n");

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

int rewrite_resolved_imports_report(void)
{
    char report_path[MAX_PATH];
    snprintf(report_path, sizeof(report_path), "%s\\resolved_imports.txt", g_output_dir);
    FILE *report = fopen(report_path, "w");
    if (!report) return -1;

    fprintf(report, "=== VMProtect Dumper v" VMPD_VERSION " - Resolved Imports ===\n");
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
            fprintf(report, "%s!%s = 0x%016llX  @ RVA=0x%08lX\n",
                    e->module, e->function,
                    (unsigned long long)e->resolved_addr, (unsigned long)slot_rva);
        } else {
            fprintf(report, "%s!%s = 0x%016llX\n",
                    e->module, e->function,
                    (unsigned long long)e->resolved_addr);
        }
        written++;
    }

    int lazy = 0;
    for (int i = 0; i < g_resolved_iat_count; i++) {
        ResolvedIATEntry *re = &g_resolved_iat[i];
        if (re->import_idx >= 0 || re->module[0] == '\0') continue;
        fprintf(report, "%s!%s = 0x%016llX  @ RVA=0x%08lX  [smt lazy]\n",
                re->module, re->function,
                (unsigned long long)re->resolved_addr, (unsigned long)re->iat_rva);
        lazy++;
    }

    fprintf(report, "\n=== Summary ===\n");
    fprintf(report, "Total resolved exports: %d\n", written);
    fprintf(report, "IAT slots mapped: %d\n", g_iat_slot_count);
    if (lazy > 0)
        fprintf(report, "SMT lazy-resolved: %d\n", lazy);
    fclose(report);
    return written;
}

void scan_for_iat_entries(HANDLE hProc, DWORD64 base)
{
    if (g_import_count == 0) return;

    printf("[*] Scanning for IAT entries in process memory...\n");

    int written = rewrite_resolved_imports_report();
    if (written >= 0) {
        char report_path[MAX_PATH];
        snprintf(report_path, sizeof(report_path), "%s\\resolved_imports.txt", g_output_dir);
        printf("[+] Import catalog: %d entries -> %s\n", written, report_path);
    }
}

int g_resolved_iat_count = 0;

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
#ifdef _WIN64

            DWORD disp = *(DWORD*)(code + 2);
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

void resolve_iat_thunks(HANDLE hProc, DWORD64 base)
{
    BYTE hdr[4096];
    SIZE_T nr;
    if (!ReadProcessMemory(hProc, (LPCVOID)base, hdr, sizeof(hdr), &nr) || nr < 256)
        return;

    DWORD pe_off = *(DWORD*)(hdr + 0x3C);
    if (pe_off == 0 || pe_off + 264 > sizeof(hdr) ||
        hdr[pe_off] != 'P' || hdr[pe_off + 1] != 'E') {
        printf("[-] IAT header offset invalid (0x%lX)\n", (unsigned long)pe_off);
        return;
    }
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
    if (num_slots > MAX_IAT_RESOLVED) {
        printf("[!] IAT has %d slots, resolving first %d (MAX_IAT_RESOLVED); "
               "remaining slots stay untouched\n", num_slots, MAX_IAT_RESOLVED);
        num_slots = MAX_IAT_RESOLVED;
    }

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
            if (g_resolved_iat[i].import_idx >= 0 || g_resolved_iat[i].module[0] != '\0') named++;
        printf("[+] Named imports: %d of %d resolved entries\n", named, resolved_count);
    }
}

void patch_dumped_iat(const char *target_name)
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

void scan_iat_slots(HANDLE hProc, DWORD64 base)
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

