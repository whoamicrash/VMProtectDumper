#include "vmpd.h"


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

static void random_bytes(BYTE *out, DWORD n)
{
    HMODULE h = GetModuleHandleA("advapi32.dll");
    BOOLEAN (WINAPI *pGen)(PVOID, ULONG) = NULL;
    if (h)
        *(FARPROC *)&pGen = GetProcAddress(h, "SystemFunction036");
    if (pGen && pGen(out, n)) return;
    BYTE seed[8];
    LARGE_INTEGER pc;
    QueryPerformanceCounter(&pc);
    for (int i = 0; i < 8; i++)
        seed[i] = (BYTE)(((ULONG_PTR)&h >> (i % 12)) ^ (pc.QuadPart >> (i * 4)));
    DWORD s = 0;
    for (int i = 0; i < 8; i++) s = (s << 5) ^ (seed[i] + i * 0x9E);
    for (DWORD i = 0; i < n; i++) {
        s = s * 1664525u + 1013904223u;
        out[i] ^= (BYTE)(s >> 13);
    }
}

static void w16(FILE *f, WORD v)  { fwrite(&v, 2, 1, f); }

static void w32(FILE *f, DWORD v) { fwrite(&v, 4, 1, f); }

static int collect_zip_dir(const char *root, const char *rel_prefix,
                           ZipFileEntry *entries, int cap, int *num,
                           int *truncated)
{
    char search[MAX_PATH];
    if (rel_prefix[0])
        snprintf(search, sizeof(search), "%s\\%s\\*", root, rel_prefix);
    else
        snprintf(search, sizeof(search), "%s\\*", root);
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return 0;
    do {
        if (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, "..")) continue;
        char rel[MAX_PATH];
        if (rel_prefix[0])
            snprintf(rel, sizeof(rel), "%s\\%s", rel_prefix, fd.cFileName);
        else
            snprintf(rel, sizeof(rel), "%s", fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (rel_prefix[0] == 0)
                collect_zip_dir(root, rel, entries, cap, num, truncated);
            continue;
        }
        if (*num >= cap) { *truncated = 1; continue; }
        ZipFileEntry *e = &entries[*num];
        memset(e, 0, sizeof(*e));
        strncpy(e->name, rel, MAX_PATH - 1);
        e->name_len = (WORD)strlen(e->name);
        ULARGE_INTEGER fs;
        fs.HighPart = fd.nFileSizeHigh;
        fs.LowPart = fd.nFileSizeLow;
        e->raw_size = fs.QuadPart > 0x7FFFFFFF ? 0x7FFFFFFF : (DWORD)fs.QuadPart;
        e->comp_size = (g_zip_password[0] != 0) ? (e->raw_size + ZIP_ENC_HDR_SIZE) : e->raw_size;
        e->crc = 0;
        SYSTEMTIME st;
        FILETIME lft = fd.ftLastWriteTime;
        FileTimeToLocalFileTime(&lft, &lft);
        FileTimeToSystemTime(&lft, &st);
        e->dos_time = (WORD)((st.wSecond / 2) | (st.wMinute << 5) | (st.wHour << 11));
        e->dos_date = (WORD)(st.wDay | (st.wMonth << 5) |
                             (((st.wYear < 1980 ? 1980 : st.wYear) - 1980) << 9));
        (*num)++;
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);
    return 1;
}

static DWORD file_actual_size(FILE *sf)
{
    long cur = ftell(sf);
    fseek(sf, 0, SEEK_END);
    long end = ftell(sf);
    fseek(sf, cur, SEEK_SET);
    return (end < 0) ? 0 : (DWORD)end;
}

int create_output_zip(const char *dump_dir)
{
    char zip_path[MAX_PATH];
    snprintf(zip_path, sizeof(zip_path), "%s.dat", dump_dir);

    int with_pw = (g_zip_password[0] != 0);

    if (with_pw)
        printf("\n[*] Creating password-protected archive (user-supplied password)...\n");
    else
        printf("\n[*] Creating archive (no password: --zip-password not set)...\n");
    printf("    Extension: .dat (rename to .zip to extract)\n");

    crc32_init();

    ZipFileEntry *entries = (ZipFileEntry *)calloc(ZIP_MAX_FILES, sizeof(ZipFileEntry));
    if (!entries) { printf("[-] ZIP: out of memory\n"); return 0; }
    int num_entries = 0;
    int truncated = 0;
    collect_zip_dir(dump_dir, "", entries, ZIP_MAX_FILES, &num_entries, &truncated);
    if (truncated)
        printf("[!] ZIP: more than %d files found, archive truncated to %d\n",
               ZIP_MAX_FILES, ZIP_MAX_FILES);

    if (num_entries == 0) {
        printf("[-] No files found\n");
        free(entries);
        return 0;
    }

    FILE *zf = fopen(zip_path, "wb");
    if (!zf) {
        printf("[-] Cannot create %s\n", zip_path);
        free(entries);
        return 0;
    }

    BYTE io_buf[8192];
    const char *password = g_zip_password;

    for (int i = 0; i < num_entries; i++) {
        ZipFileEntry *e = &entries[i];
        char src[MAX_PATH];
        snprintf(src, sizeof(src), "%s\\%s", dump_dir, e->name);
        FILE *sf = fopen(src, "rb");
        if (!sf) {
            e->raw_size = 0;
            e->comp_size = with_pw ? ZIP_ENC_HDR_SIZE : 0;
            e->skip = 1;
            continue;
        }
        e->raw_size = file_actual_size(sf);
        e->comp_size = with_pw ? (e->raw_size + ZIP_ENC_HDR_SIZE) : e->raw_size;
        DWORD crc = 0;
        for (;;) {
            DWORD n = (DWORD)fread(io_buf, 1, sizeof(io_buf), sf);
            if (!n) break;
            crc = crc32_update(crc, io_buf, n);
        }
        e->crc = crc;
        e->local_offset = (DWORD)ftell(zf);
        w32(zf, ZIP_LOCAL_SIG); w16(zf, 20);
        w16(zf, with_pw ? 0x0001 : 0x0000);
        w16(zf, 0);
        w16(zf, e->dos_time); w16(zf, e->dos_date); w32(zf, e->crc);
        w32(zf, e->comp_size); w32(zf, e->raw_size); w16(zf, e->name_len); w16(zf, 0);
        fwrite(e->name, 1, e->name_len, zf);
        ZCKeys keys;
        if (with_pw) {
            zc_init_password(&keys, password);
            BYTE enc_hdr[ZIP_ENC_HDR_SIZE];
            BYTE rnd[ZIP_ENC_HDR_SIZE];
            random_bytes(rnd, ZIP_ENC_HDR_SIZE);
            for (int j = 0; j < 11; j++)
                enc_hdr[j] = zc_encrypt(&keys, rnd[j]);
            enc_hdr[11] = zc_encrypt(&keys, (BYTE)(e->crc >> 24));
            fwrite(enc_hdr, 1, ZIP_ENC_HDR_SIZE, zf);
        }
        fseek(sf, 0, SEEK_SET);
        if (with_pw) {
            for (;;) {
                DWORD n = (DWORD)fread(io_buf, 1, sizeof(io_buf), sf);
                if (!n) break;
                for (DWORD j = 0; j < n; j++) io_buf[j] = zc_encrypt(&keys, io_buf[j]);
                fwrite(io_buf, 1, n, zf);
            }
        } else {
            for (;;) {
                DWORD n = (DWORD)fread(io_buf, 1, sizeof(io_buf), sf);
                if (!n) break;
                fwrite(io_buf, 1, n, zf);
            }
        }
        fclose(sf);
    }

    DWORD cd_offset = (DWORD)ftell(zf);
    int cd_count = 0;
    for (int i = 0; i < num_entries; i++) {
        ZipFileEntry *e = &entries[i];
        if (e->skip) continue;
        w32(zf, ZIP_CENTRAL_SIG); w16(zf, 20); w16(zf, 20);
        w16(zf, with_pw ? 0x0001 : 0x0000);
        w16(zf, 0);
        w16(zf, e->dos_time); w16(zf, e->dos_date); w32(zf, e->crc);
        w32(zf, e->comp_size); w32(zf, e->raw_size); w16(zf, e->name_len); w16(zf, 0);
        w16(zf, 0); w16(zf, 0); w16(zf, 0); w32(zf, 0x00000020); w32(zf, e->local_offset);
        fwrite(e->name, 1, e->name_len, zf);
        cd_count++;
    }
    DWORD cd_size = (DWORD)ftell(zf) - cd_offset;
    w32(zf, ZIP_END_SIG); w16(zf, 0); w16(zf, 0);
    w16(zf, (WORD)cd_count); w16(zf, (WORD)cd_count);
    w32(zf, cd_size); w32(zf, cd_offset); w16(zf, 0);
    DWORD zip_size = (DWORD)ftell(zf);
    fclose(zf);
    free(entries);

    strncpy(g_zip_path, zip_path, MAX_PATH - 1);
    printf("[+] Archive created: %s\n", zip_path);
    printf("    %d files, %u bytes\n", cd_count, (unsigned)zip_size);
    if (with_pw) {
        printf("    Password: (user-supplied via --zip-password)\n");
        printf("    To extract: rename .dat -> .zip, then unzip with your password\n");
    } else {
        printf("    Password: none (plain ZIP)\n");
        printf("    To extract: rename .dat -> .zip\n");
    }
    return 1;
}
