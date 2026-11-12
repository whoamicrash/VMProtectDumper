#include "vmpd.h"

void json_escape(FILE *f, const char *s)
{
    while (*s) {
        if (*s == '"') fprintf(f, "\\\"");
        else if (*s == '\\') fprintf(f, "\\\\");
        else fputc(*s, f);
        s++;
    }
}

void write_dump_metadata(HANDLE hProc, DWORD64 base, const char *target_name)
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
    fprintf(f, "  \"dumper_version\": \"" VMPD_VERSION "\",\n");
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

    {
        DWORD64 tls_dir = base + (DWORD64)dd_tls_rva;
        DWORD64 cb_array_va = 0;
        BYTE tdir[64];
        SIZE_T tn = 0;
        DWORD64 cbs[64];
        int tls_n = 0;
        memset(cbs, 0, sizeof(cbs));
        if (dd_tls_rva && ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)tls_dir,
                                            tdir, g_machine == 0x8664 ? 40 : 24, &tn)) {
            if (g_machine == 0x8664) {
                cb_array_va = *(DWORD64*)(tdir + 24);
            } else {
                cb_array_va = *(DWORD*)(tdir + 12);
            }
        }
        if (cb_array_va) {
            for (int i = 0; i < 64; i++) {
                DWORD64 cb = 0;
                SIZE_T cn = 0;
                DWORD64 slot = cb_array_va + (DWORD64)(g_machine == 0x8664 ? 8 : 4) * (DWORD64)i;
                if (!ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)slot, &cb,
                                       g_machine == 0x8664 ? 8 : 4, &cn))
                    break;
                if (!cb) break;
                cbs[tls_n++] = cb;
            }
        }
        fprintf(f, "  \"tls_callbacks\": [");
        for (int i = 0; i < tls_n; i++)
            fprintf(f, "\n    \"0x%llX\"%s", (unsigned long long)cbs[i],
                    (i < tls_n - 1) ? "," : "");
        fprintf(f, "%s],\n", tls_n ? "\n  " : "");
        fprintf(f, "  \"tls_callbacks_va\": \"0x%llX\",\n", (unsigned long long)cb_array_va);
    }

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
        if (re->import_idx >= 0 || re->module[0] != '\0') {
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

