#ifndef VMPD_H
#define VMPD_H

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define VMPD_VERSION "6.0"

int _stricmp_null_safe(const char *a, const char *b);

#ifdef _WIN64
#define ADDR_FMT    "0x%llX"
#define ADDR_FMTW   "0x%016llX"
#define ADDR_CAST(x) (unsigned long long)(x)
#else
#define ADDR_FMT    "0x%08X"
#define ADDR_FMTW   "0x%08X"
#define ADDR_CAST(x) (unsigned)(x)
#endif

#define MAX_SECTIONS        32
#define POLL_INTERVAL_MS    50
#define MAX_MONITOR_SEC     300
#define FINGERPRINT_SIZE    64
#define MAX_STR_LEN         1024
#define MIN_STR_LEN         4
#define MAX_IMPORTS         65536
#define MAX_IAT_SLOTS       8192
#define OEP_SCAN_SIZE       4096

#define MAX_DYNAMIC_REGIONS      256
#define REGION_FP_SIZE           64
#define HARVEST_SNAP_INTERVAL    10
#define HARVEST_BEHAV_INTERVAL   40
#define HARVEST_REGION_THRESHOLD 3
#define HARVEST_SETTLE_MS        3000
#define PESIEVE_TIMEOUT_MS       60000

typedef struct {
    char    name[16];
    DWORD   rva;
    DWORD   vsize;
    DWORD   raw_size;
    DWORD   characteristics;
    BYTE    fingerprint[FINGERPRINT_SIZE];
    int     changed;
    int     was_zeroed;
    int     nz_bytes;
} SectionInfo;

#define MAX_WATCH_DIRS_FWD  16
#define PE32_MAGIC          0x10b
#define PE32PLUS_MAGIC      0x20b
#define ProcessBasicInformation     0
#define ProcessWow64Information     26
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define OEP_MAX_SCAN  (256 * 1024)
#define HOOK_RING_MAX       8192
#define HOOK_ENTRY_SIZE     32
#define HOOK_HDR_SIZE       0x100
#define HOOK_RING_OFF       0x100
#define HOOK_RING_BYTES     (HOOK_RING_MAX * HOOK_ENTRY_SIZE)
#define HOOK_TRAMP_OFF      (HOOK_RING_OFF + HOOK_RING_BYTES)       
#define HOOK_TRAMP_SIZE     256
#define HOOK_BODY_OFF       (HOOK_TRAMP_OFF + 3 * HOOK_TRAMP_SIZE)  
#define HOOK_BODY_SIZE      256
#define HOOK_SLOTS_OFF      (HOOK_BODY_OFF + 3 * HOOK_BODY_SIZE)    
#define HOOK_PARAM_OFF      (HOOK_SLOTS_OFF + 64)                   
#define HOOK_STUB_OFF       (HOOK_PARAM_OFF + 128)                  
#define HOOK_TOTAL_SIZE     (HOOK_STUB_OFF + 256)
#define HOOK_TAG_GPA 0
#define HOOK_TAG_LLA 1
#define HOOK_TAG_LLW 2
#define MAX_ORIG_IMPORTS 16384
#define MAX_VID_FIXES 8192
#define MAX_IAT_RESOLVED 512
#define SMT_MAX_INSN_LEN 15
#define SMT_RUN_RESOLVED   1
#define SMT_RUN_RET        2
#define SMT_RUN_CAP        3
#define SMT_RUN_DECODE     4
#define SMT_RUN_DIV        5
#define SMT_RUN_HOOK       6
#define SMT_RUN_EXPR_OOM   7
#define SVC_TEMP_NAME "VmpDumpTempSvc"
#define ZIP_LOCAL_SIG       0x04034b50
#define ZIP_CENTRAL_SIG     0x02014b50
#define ZIP_END_SIG         0x06054b50
#define ZIP_ENC_HDR_SIZE    12
#define ZIP_MAX_FILES       4096
#define MAX_WATCH_DIRS      16
#define MAX_SNAPSHOT_FILES   1024
#define MAX_NEW_FILES        64
#define MAX_BASELINE_PIDS    1024
#define MAX_NEW_PIDS         64
#define DROPPER_POLL_MS      500

typedef struct {
    char    module[128];
    char    function[256];
    DWORD64 resolved_addr;
} ImportEntry;

typedef struct {
    DWORD   slot_rva;
    int     import_idx;
} IATSlotEntry;

typedef struct {
    DWORD64   base_addr;
    SIZE_T    size;
    DWORD     protect;
    BYTE      fingerprint[REGION_FP_SIZE];
    int       snapshot_first;
    int       snapshot_last;
    int       fp_changed;
    int       dumped;
} DynamicRegion;

typedef struct {
    DynamicRegion regions[MAX_DYNAMIC_REGIONS];
    int           count;
    int           index;
    DWORD         tick_ms;
} RegionSnapshot;

typedef struct {
    RegionSnapshot current;
    RegionSnapshot previous;

    DynamicRegion  all_seen[MAX_DYNAMIC_REGIONS * 2];
    int            all_seen_count;

    int  new_this_cycle;
    int  disappeared;
    int  fp_changes;

    int  behavioral_trigger;
    int  new_file_count;

    char timeline[64][256];
    int  timeline_count;

    int  pesieve_ran;
    int  pesieve_exit_code;
    int  pesieve_file_count;
    char pesieve_path[MAX_PATH];
} HarvestState;



typedef LONG NTSTATUS;


typedef struct _MY_PROCESS_BASIC_INFORMATION {
    NTSTATUS  ExitStatus;
    PVOID     PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG      BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} MY_PROCESS_BASIC_INFORMATION;

typedef NTSTATUS (NTAPI *pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG  ProcessInformationClass,
    PVOID  ProcessInformation,
    ULONG  ProcessInformationLength,
    PULONG ReturnLength
);

#include <ctype.h>
#ifndef QWORD
typedef unsigned long long QWORD;
#endif

typedef struct {
    char dll[64];
    char func[256];
    WORD hint;
} OrigImport;

typedef struct {
    DWORD64 slot_rva;
    DWORD64 resolved_addr;
    char    module[64];
    char    function[256];
    int     status;
} VidFixEntry;

typedef struct {
    BYTE *buf;
    int   len;
    int   cap;
} CodeBuf;

typedef struct {
    DWORD   iat_rva;
    DWORD64 thunk_addr;
    DWORD64 resolved_addr;
    int     import_idx;
    char    module[128];
    char    function[256];
} ResolvedIATEntry;

typedef struct { DWORD k0, k1, k2; } ZCKeys;

typedef struct {
    char  name[MAX_PATH]; WORD name_len;
    DWORD crc, comp_size, raw_size, local_offset;
    WORD  dos_date, dos_time;
    BYTE  skip;
} ZipFileEntry;


typedef struct {
    int is_packed;
    int vmp_sections;
    int zeroed_sections;
    int minimal_imports;
    int has_overlay;
    char details[256];
} PackerCheckResult;

typedef struct {
    char path[MAX_PATH];
    DWORD size_low;
} FSEntry;

typedef struct {
    HANDLE  hProcess;
    HANDLE  hThread;
    DWORD   pid;
    DWORD64 image_base;
    char    image_path[MAX_PATH];
} TargetInfo;


extern DWORD64 g_image_base;
extern DWORD g_size_of_image;
extern char g_output_dir[MAX_PATH];
extern int g_no_smt;
extern DWORD g_oep_thread_rva;
extern DWORD g_oep_crt_rva;
extern int g_harvest_enabled;
extern long g_smt_resolved;
extern long g_smt_unresolved;
extern long g_smt_already_real;
extern long g_smt_collatz;
extern long g_smt_bombs;
extern unsigned long long g_smt_instr;
extern char g_zip_path[MAX_PATH];
extern char g_zip_password[256];
extern SectionInfo g_sections[MAX_SECTIONS];
extern int g_num_sections;
extern DWORD g_oep_rva;
extern int g_oep_captured;
extern DWORD64 g_hook_cave;
extern int g_hook_installed_count;
extern ImportEntry g_imports[MAX_IMPORTS];
extern volatile LONG g_import_count;
extern IATSlotEntry g_iat_slots[MAX_IAT_SLOTS];
extern int g_iat_slot_count;
extern int g_orig_import_count;
extern int g_vid_fix_count;
extern int g_resolved_iat_count;
extern ResolvedIATEntry g_resolved_iat[MAX_IAT_RESOLVED];
extern WORD g_machine;
extern HarvestState g_harvest;
extern char g_self_path[MAX_PATH];

const char* get_basename(const char *path);
int detect_target_architecture_vmp(HANDLE hProcess, DWORD64 *out_image_base);
int read_pe_sections(HANDLE hProc, DWORD64 base);
int check_changes(HANDLE hProc, DWORD64 base);
void capture_oep(HANDLE hProc, HANDLE hThread, DWORD64 base, DWORD soi);
int dump_section(HANDLE hProc, DWORD64 base, SectionInfo *si, int idx);
void dump_full_image(HANDLE hProc, DWORD64 base, const char *target_name);
void log_import(const char *module, const char *function, DWORD64 addr);
void install_gpa_hook(HANDLE hProc);
int patch_iat_slots_for_hooks(HANDLE hProc);
void poll_gpa_log(HANDLE hProc);
void neutralize_antidebug(HANDLE hProc);
void rebuild_imports_vid(HANDLE hProc, DWORD64 base, const char *target_name);
void reconstruct_iat(HANDLE hProc, DWORD64 base);
int rewrite_resolved_imports_report(void);
void scan_for_iat_entries(HANDLE hProc, DWORD64 base);
void resolve_iat_thunks(HANDLE hProc, DWORD64 base);
void patch_dumped_iat(const char *target_name);
void scan_iat_slots(HANDLE hProc, DWORD64 base);
void smt_run(const char *target_name);
void scan_process_strings(HANDLE hProc);
void capture_dropped_files(const char *target_dir);
void kill_monitor_processes(int kill_vmtools);
void harvest_init(void);
void harvest_log(const char *fmt, ...);
int take_region_snapshot(HANDLE hProc, DWORD64 image_base, DWORD soi);
int check_region_changes(void);
int dump_dynamic_regions(HANDLE hProc);
void detect_pesieve_path(void);
int run_pesieve(DWORD target_pid);
int check_behavioral_trigger(void);
void write_harvest_report(DWORD total_elapsed_ms);
int check_file_for_packer(const char *filepath, PackerCheckResult *result);
int attach_and_assess(HANDLE hProc, HANDLE hThread, DWORD64 image_base);
int wait_for_named_process(const char *proc_name, int timeout_sec, TargetInfo *found);
int dropper_mode(const char *target_exe, int timeout_sec, TargetInfo *found);
void write_dropper_info(const char *original, const char *payload, DWORD pid, const char *method, float discovery_time);
HANDLE launch_service_dll(const char *dll_path, DWORD64 *out_dll_base, DWORD *out_pid);
void cleanup_temp_service(void);
int create_output_zip(const char *dump_dir);
void json_escape(FILE *f, const char *s);
void write_dump_metadata(HANDLE hProc, DWORD64 base, const char *target_name);

#endif
