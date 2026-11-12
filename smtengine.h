#ifndef SMTENGINE_H
#define SMTENGINE_H

#ifndef SMT_ENGINE_INTERNAL
#define SMT_ENGINE_INTERNAL

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smtsolver.h"

#ifndef SMT_MAX_PATH
#define SMT_MAX_PATH 260
#endif

typedef unsigned char      tu8;
typedef unsigned short     tu16;
typedef unsigned int       tu32;
typedef unsigned long long tu64;
typedef long long          ts64;

#define SMT_PAGE_SIZE       4096u
#define SMT_PAGE_HASH       (1u << 18)
#define SMT_MAX_EXPRS       400000
#define SMT_NODE_CAP        150000
#define SMT_PATH_MAX        4096
#define SMT_QUERY_CAP       96
#define SMT_BRANCH_PERIOD   8
#define SMT_FEAS_PERIOD     64
#define SMT_HASHCONS_SIZE   (1u << 16)
#define SMT_TRACE_CAP       150000
#define SMT_MAX_LOOP_TRACK  512
#define SMT_LOOP_FAST_ITER  128
#define SMT_LOOP_HARD_CAP   300000ULL
#ifdef _WIN32
#define SMT_PATH_FMT        "%s\\"
#else
#define SMT_PATH_FMT        "%s/"
#endif
#define SMT_STUB_INSTR_CAP  4000000ULL
#define SMT_EP_INSTR_CAP    33554432ULL
#define SMT_EP_EARLY_ABORT  8388608ULL
#define SMT_TOTAL_INSTR_CAP 64000000ULL
#define SMT_MAX_HANDLERS    2048
#define SMT_STACK_TOP       0x00007FFEFFFFE000ULL
#define SMT_RET_MAGIC       0x00005E1700000000ULL
#define SMT_GS_BASE         0x00007FF000000000ULL
#define SMT_PEB_ADDR        0x00007FF000000000ULL
#define SMT_TEB_ADDR        0x00007FF000001000ULL
#define SMT_FAKE_DLL_BASE   0x0000640000000000ULL

enum {
    SMT_OP_NONE = 0, SMT_OP_MOV, SMT_OP_LEA, SMT_OP_MOVSX, SMT_OP_MOVZX,
    SMT_OP_MOVSXD, SMT_OP_ADD, SMT_OP_OR, SMT_OP_ADC, SMT_OP_SBB,
    SMT_OP_AND, SMT_OP_SUB, SMT_OP_XOR, SMT_OP_CMP, SMT_OP_TEST,
    SMT_OP_INC, SMT_OP_DEC, SMT_OP_PUSH, SMT_OP_POP, SMT_OP_JMP,
    SMT_OP_JCC, SMT_OP_CALL, SMT_OP_RET, SMT_OP_SETCC, SMT_OP_CMOVCC,
    SMT_OP_SHL, SMT_OP_SHR, SMT_OP_SAR, SMT_OP_ROL, SMT_OP_ROR,
    SMT_OP_NOT, SMT_OP_NEG, SMT_OP_MUL, SMT_OP_IMUL2, SMT_OP_IMUL3,
    SMT_OP_DIV, SMT_OP_IDIV, SMT_OP_XCHG, SMT_OP_BSWAP, SMT_OP_CDQ,
    SMT_OP_CWDE, SMT_OP_NOP, SMT_OP_LEAVE, SMT_OP_PUSHF, SMT_OP_POPF,
    SMT_OP_RDTSC, SMT_OP_ENDBR, SMT_OP_PAUSE,
    SMT_OP_BT, SMT_OP_BTS, SMT_OP_BTR, SMT_OP_BTC, SMT_OP_BSF, SMT_OP_BSR,
    SMT_OP_MOVS, SMT_OP_STOS, SMT_OP_LOOP, SMT_OP_JRCXZ,
    SMT_OP_SSE_MOV, SMT_OP_SSE_XOR,
    SMT_OP_ABORT
};

enum {
    SMT_CC_O = 0, SMT_CC_NO, SMT_CC_B, SMT_CC_NB, SMT_CC_E, SMT_CC_NE,
    SMT_CC_BE, SMT_CC_A, SMT_CC_S, SMT_CC_NS, SMT_CC_P, SMT_CC_NP,
    SMT_CC_L, SMT_CC_GE, SMT_CC_LE, SMT_CC_G
};

enum { SMT_NONE = 0, SMT_REG, SMT_MEM, SMT_IMM };

enum {
    TEX_CONST = 0, TEX_VAR, TEX_ADD, TEX_SUB, TEX_MUL, TEX_AND, TEX_OR,
    TEX_XOR, TEX_NOT, TEX_NEG, TEX_SHL, TEX_SHR, TEX_SAR, TEX_ROL,
    TEX_ROR, TEX_ZEXT, TEX_SEXT, TEX_EXTRACT, TEX_CONCAT, TEX_ITE
};

typedef struct SmtPageNode {
    tu64 key;
    tu8 *data;
    struct SmtPageNode *next;
} SmtPageNode;

typedef struct {
    SmtPageNode *buckets[SMT_PAGE_HASH];
    int page_count;
    tu64 first_touch[128];
    int first_touch_count;
} SmtMem;

typedef struct {
    tu64 r[16];
    tu64 xmm[16][2];
    tu64 rip;
    tu8  cf, zf, sf, of, pf, af, df;
    int  mode64;
} SmtCpu;

typedef struct {
    tu8 type;
    tu8 reg;
    tu8 base, index, scale, seg;
    tu8 riprel;
    tu32 disp;
    tu64 imm;
    tu8 size;
} SmtOperand;

typedef struct {
    tu8 len, op, osize, cond;
    tu8 rep;
    SmtOperand dst, src, third;
    tu64 rel;
    tu64 ip;
} SmtInsn;

typedef struct {
    tu64 head;
    tu64 iters;
    tu64 hist[24];
    tu32 hcount;
    tu32 hpos;
    int  fast_mode;
    int  collatz;
    ts64 collatz_c;
    int  reported;
    tu64 region_lo, region_hi;
} SmtLoop;

typedef struct {
    tu64 addr;
    int  insn_count;
    char summary[160];
} SmtHandler;

typedef struct {
    char module[64];
    char function[192];
    tu64 addr;
} SmtCatalogEntry;


typedef struct {
    tu32 slot_rva;
    tu64 resolved_addr;
    char name[128];
    int  how;
} SmtSlotFix;
#define SMT_MAX_SLOT_FIXES 512
typedef struct {
    tu64 image_base;
    tu32 image_size;
    tu32 machine;
    tu64 ep_rva;
    char dump_path[SMT_MAX_PATH];
    char output_dir[SMT_MAX_PATH];
    char target_name[128];
    SmtCatalogEntry *catalog;
    int  catalog_count;
    tu32 *slot_rvas;
    tu64 *slot_vals;
    int  slot_count;
    int  trace_enabled;
    SmtSlotFix *fixes;
    int  fix_count;
} SmtContext;


typedef struct {
    SmtContext *ctx;
    SmtCpu  cpu;
    SmtMem  mem;
    SmtCtx  smt;
    int      expr_count;
    int      sym_overflow;
    su32     path[SMT_PATH_MAX];
    int      path_count;
    int      reg_var[16];
    int      cmp_a;
    int      cmp_b;
    int      cmp_size;
    int      cmp_is_test;
    int      branches;
    int      last_flags_reg;
    FILE    *smt2;
    tu64     smt2_lines;
    int      queries;
    int      q_sat;
    int      q_unsat;
    int      q_forced;
    int      q_divergent;
    int      q_errors;
    int      feas_checks;
    int      feas_failed;
    int      reg_ver[16];
    int      reg_expr[16];
    SmtLoop  loops[SMT_MAX_LOOP_TRACK];
    int      loop_count;
    SmtHandler handlers[SMT_MAX_HANDLERS];
    int      handler_count;
    tu64  indirect_targets[512];
    int   indirect_count;
    FILE *trace;
    tu64  trace_lines;
    int   trace_capped;
    FILE *handlers_file;
    int   handlers_emitted;
    int   fast_mode;
    tu64  fast_lo, fast_hi;
    tu64  instr_count;
    tu64  instr_cap;
    int   ep_mode;
    tu64  total_instr_count;
    int   aborted;
    char  abort_reason[160];
    tu64  rdtsc_fake;
    int   collatz_bypasses;
    int   loop_bombs;
    struct { tu64 fake_base; char module[64]; } dllmap[64];
    int   dllmap_count;
    tu64  gpa_addr, lla_addr, llw_addr;
} SmtState;

static const char *smt_reg_names[16] = {
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
};

static const char *smt_op_names[62] = {
    "?", "mov", "lea", "movsx", "movzx", "movsxd", "add", "or", "adc",
    "sbb", "and", "sub", "xor", "cmp", "test", "inc", "dec", "push",
    "pop", "jmp", "j", "call", "ret", "set", "cmov", "shl", "shr",
    "sar", "rol", "ror", "not", "neg", "mul", "imul", "imul",
    "div", "idiv", "xchg", "bswap", "cdq", "cwde", "nop", "leave",
    "pushf", "popf", "rdtsc", "endbr64", "pause", "bt", "bts", "btr",
    "btc", "bsf", "bsr", "movs", "stos", "loop", "jrcxz",
    "sse_mov", "sse_xor", "?"
};

static const char *smt_cc_names[16] = {
    "o", "no", "b", "ae", "e", "ne", "be", "a",
    "s", "ns", "p", "np", "l", "ge", "le", "g"
};

static void *smt_xcalloc(size_t n, size_t sz)
{
    void *p = calloc(n ? n : 1, sz ? sz : 1);
    if (!p) { fprintf(stderr, "SMT: out of memory\n"); exit(3); }
    return p;
}

static tu32 smt_page_bucket(tu64 addr)
{
    tu64 pn = addr / SMT_PAGE_SIZE;
    tu64 h = pn * 0x9E3779B97F4A7C15ULL;
    return (tu32)(h >> 40) & (SMT_PAGE_HASH - 1);
}

static tu8 *smt_page_find(SmtMem *m, tu64 addr)
{
    for (SmtPageNode *n = m->buckets[smt_page_bucket(addr)]; n; n = n->next)
        if (n->key == addr / SMT_PAGE_SIZE) return n->data;
    return NULL;
}

static tu8 *smt_page_get(SmtMem *m, tu64 addr)
{
    tu32 b = smt_page_bucket(addr);
    tu64 pn = addr / SMT_PAGE_SIZE;
    for (SmtPageNode *n = m->buckets[b]; n; n = n->next)
        if (n->key == pn) return n->data;
    SmtPageNode *np = (SmtPageNode *)smt_xcalloc(1, sizeof(SmtPageNode));
    np->key = pn;
    np->data = (tu8 *)smt_xcalloc(SMT_PAGE_SIZE, 1);
    np->next = m->buckets[b];
    m->buckets[b] = np;
    m->page_count++;
    if (m->first_touch_count < 128)
        m->first_touch[m->first_touch_count++] = pn * SMT_PAGE_SIZE;
    return np->data;
}

#endif

const char *smt_mnemonic(SmtInsn *ins);
int smt_decode(SmtState *S, tu64 ip, SmtInsn *ins);
int smt_engine_run(SmtContext *ctx);

#endif
