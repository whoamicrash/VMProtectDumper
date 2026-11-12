#include "vmpd.h"

DWORD64 g_hook_cave = 0;

static DWORD64 g_hook_gpa_addr = 0;

static DWORD64 g_hook_lla_addr = 0;

static DWORD64 g_hook_llw_addr = 0;

int   g_hook_installed_count = 0;

static char  g_target_image_name[128] = "";

static int lde64_len(const BYTE *p, int max_len);


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

static void cb_put8(CodeBuf *c, BYTE v)
{
    if (c->len < c->cap) c->buf[c->len++] = v;
}

static void cb_put32(CodeBuf *c, DWORD v)
{
    cb_put8(c, (BYTE)(v & 0xFF));
    cb_put8(c, (BYTE)((v >> 8) & 0xFF));
    cb_put8(c, (BYTE)((v >> 16) & 0xFF));
    cb_put8(c, (BYTE)((v >> 24) & 0xFF));
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

void install_gpa_hook(HANDLE hProc)
{
#ifdef _WIN64
    if (g_hook_cave != 0) return;

    if (g_machine == IMAGE_FILE_MACHINE_I386) {
        static int wow64_said = 0;
        if (!wow64_said) {
            wow64_said = 1;
            printf("[*] target is 32-bit (WOW64): x64 inline hooks not applicable,\n"
                   "    hooking skipped. Read-based IAT rebuild + SMT engine stay active.\n");
        }
        return;
    }

    if (is_wine_host()) {
        static int wine_said = 0;
        if (!wine_said) {
            wine_said = 1;
            printf("[*] wine host: inline hooks disabled entirely (no cross-process\n"
                   "    writes, no cave allocation). Read-based IAT rebuild + SMT engine\n"
                   "    stay active.\n");
        }
        return;
    }

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
#else
    printf("[*] GPA hook: x86 target, inline hooks skipped (order-based IAT rebuild will be used)\n");
#endif
}

int patch_iat_slots_for_hooks(HANDLE hProc)
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
                printf("[iatdbg] mod %ls imp_rva=0x%lX imp_sz=0x%lX\n", me.szModule, (unsigned long)imp_rva, (unsigned long)imp_sz);

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

void poll_gpa_log(HANDLE hProc)
{
#ifdef _WIN64
    if (g_hook_cave == 0 || !hProc) return;

    BYTE hdr[0x20];
    SIZE_T nread;
    if (!ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)g_hook_cave, hdr,
                           sizeof(hdr), &nread))
        return;

    LONGLONG count = *(LONGLONG*)(hdr + 8);
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
                        memcpy(func_name, tmp, sizeof(func_name) - 1);
                        func_name[sizeof(func_name) - 1] = '\0';
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
                        memcpy(func_name, tmp, sizeof(func_name) - 1);
                        func_name[sizeof(func_name) - 1] = '\0';
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
                        memcpy(func_name, tmp, sizeof(func_name) - 1);
                        func_name[sizeof(func_name) - 1] = '\0';
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

    if (count >= HOOK_RING_MAX) {
        LONGLONG zero = 0;
        SIZE_T wr = 0;
        if (WriteProcessMemory(hProc, (LPVOID)(ULONG_PTR)(g_hook_cave + 8),
                               &zero, sizeof(zero), &wr) && wr == sizeof(zero)) {
            consumed = 0;
            printf("[*] GPA hook ring: counter reset, oldest entries will be overwritten (circular)\n");
        }
    }
#endif
}

void neutralize_antidebug(HANDLE hProc)
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
    BYTE cur_bd = 0;
    DWORD cur_nf = 0;
    ReadProcessMemory(hProc, (LPCVOID)(peb + 2), &cur_bd, 1, &nread);
#ifdef _WIN64
    ReadProcessMemory(hProc, (LPCVOID)(peb + 0xBC), &cur_nf, 4, &nread);
#else
    ReadProcessMemory(hProc, (LPCVOID)(peb + 0x68), &cur_nf, 4, &nread);
#endif
    int wrote = 0;
    if (cur_bd != 0) {
        BYTE zero = 0;
        WriteProcessMemory(hProc, (LPVOID)(peb + 2), &zero, 1, &nread);
        wrote++;
    }
    if (cur_nf != 0) {
        DWORD flag = 0;
#ifdef _WIN64
        WriteProcessMemory(hProc, (LPVOID)(peb + 0xBC), &flag, 4, &nread);
#else
        WriteProcessMemory(hProc, (LPVOID)(peb + 0x68), &flag, 4, &nread);
#endif
        wrote++;
    }
    printf("[+] Anti-debug: PEB.BeingDebugged=%u, NtGlobalFlag=0x%X -> %s (PEB=0x%llX)\n",
           (unsigned)cur_bd, (unsigned)cur_nf,
           wrote ? "patched" : "already clean (no writes)",
           (unsigned long long)peb);
}

