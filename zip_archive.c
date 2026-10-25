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

static void w16(FILE *f, WORD v)  { fwrite(&v, 2, 1, f); }

static void w32(FILE *f, DWORD v) { fwrite(&v, 4, 1, f); }

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
        e->comp_size = with_pw ? (e->raw_size + ZIP_ENC_HDR_SIZE) : e->raw_size;
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
    const char *password = g_zip_password;

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
        w32(zf, ZIP_LOCAL_SIG); w16(zf, 20);
        if (with_pw) {
            w16(zf, 0x0001);
        } else {
            w16(zf, 0x0000);
        }
        w16(zf, 0);
        w16(zf, e->dos_time); w16(zf, e->dos_date); w32(zf, e->crc);
        w32(zf, e->comp_size); w32(zf, e->raw_size); w16(zf, e->name_len); w16(zf, 0);
        fwrite(e->name, 1, e->name_len, zf);
        ZCKeys keys;
        if (with_pw) {
            zc_init_password(&keys, password);
            BYTE enc_hdr[ZIP_ENC_HDR_SIZE];
            for (int j = 0; j < 11; j++) enc_hdr[j] = zc_encrypt(&keys, (BYTE)(rand() & 0xFF));
            enc_hdr[11] = zc_encrypt(&keys, (BYTE)(e->crc >> 24));
            fwrite(enc_hdr, 1, ZIP_ENC_HDR_SIZE, zf);
        }
        fseek(sf, 0, SEEK_SET);
        if (with_pw) {
            for (;;) { DWORD n = (DWORD)fread(io_buf, 1, sizeof(io_buf), sf); if (!n) break; for (DWORD j = 0; j < n; j++) io_buf[j] = zc_encrypt(&keys, io_buf[j]); fwrite(io_buf, 1, n, zf); }
        } else {
            for (;;) { DWORD n = (DWORD)fread(io_buf, 1, sizeof(io_buf), sf); if (!n) break; fwrite(io_buf, 1, n, zf); }
        }
        fclose(sf);
    }
    DWORD cd_offset = (DWORD)ftell(zf);
    for (int i = 0; i < num_entries; i++) {
        ZipFileEntry *e = &entries[i];
        w32(zf, ZIP_CENTRAL_SIG); w16(zf, 20); w16(zf, 20);
        if (with_pw) {
            w16(zf, 0x0001);
        } else {
            w16(zf, 0x0000);
        }
        w16(zf, 0);
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
    if (with_pw) {
        printf("    Password: (user-supplied via --zip-password)\n");
        printf("    To extract: rename .dat -> .zip, then unzip with your password\n");
    } else {
        printf("    Password: none (plain ZIP)\n");
        printf("    To extract: rename .dat -> .zip\n");
    }
    return 1;
}

