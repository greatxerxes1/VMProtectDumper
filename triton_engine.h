#ifndef TRITON_ENGINE_H
#define TRITON_ENGINE_H

#ifndef TRI_ENGINE_INTERNAL
#define TRI_ENGINE_INTERNAL

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef TRI_MAX_PATH
#define TRI_MAX_PATH 260
#endif

typedef unsigned char      tu8;
typedef unsigned short     tu16;
typedef unsigned int       tu32;
typedef unsigned long long tu64;
typedef long long          ts64;

#define TRI_PAGE_SIZE       4096u
#define TRI_PAGE_HASH       (1u << 18)
#define TRI_MAX_EXPRS       400000
#define TRI_HASHCONS_SIZE   (1u << 16)
#define TRI_TRACE_CAP       150000
#define TRI_MAX_LOOP_TRACK  512
#define TRI_LOOP_FAST_ITER  128
#define TRI_LOOP_HARD_CAP   300000ULL
#ifdef _WIN32
#define TRI_PATH_FMT        "%s\\"
#else
#define TRI_PATH_FMT        "%s/"
#endif
#define TRI_STUB_INSTR_CAP  4000000ULL
#define TRI_EP_INSTR_CAP    33554432ULL
#define TRI_EP_EARLY_ABORT  8388608ULL
#define TRI_TOTAL_INSTR_CAP 64000000ULL
#define TRI_MAX_HANDLERS    2048
#define TRI_STACK_TOP       0x00007FFEFFFFE000ULL
#define TRI_RET_MAGIC       0x00005E1700000000ULL
#define TRI_GS_BASE         0x00007FF000000000ULL
#define TRI_PEB_ADDR        0x00007FF000000000ULL
#define TRI_TEB_ADDR        0x00007FF000001000ULL
#define TRI_FAKE_DLL_BASE   0x0000640000000000ULL

enum {
    TRI_OP_NONE = 0, TRI_OP_MOV, TRI_OP_LEA, TRI_OP_MOVSX, TRI_OP_MOVZX,
    TRI_OP_MOVSXD, TRI_OP_ADD, TRI_OP_OR, TRI_OP_ADC, TRI_OP_SBB,
    TRI_OP_AND, TRI_OP_SUB, TRI_OP_XOR, TRI_OP_CMP, TRI_OP_TEST,
    TRI_OP_INC, TRI_OP_DEC, TRI_OP_PUSH, TRI_OP_POP, TRI_OP_JMP,
    TRI_OP_JCC, TRI_OP_CALL, TRI_OP_RET, TRI_OP_SETCC, TRI_OP_CMOVCC,
    TRI_OP_SHL, TRI_OP_SHR, TRI_OP_SAR, TRI_OP_ROL, TRI_OP_ROR,
    TRI_OP_NOT, TRI_OP_NEG, TRI_OP_MUL, TRI_OP_IMUL2, TRI_OP_IMUL3,
    TRI_OP_DIV, TRI_OP_IDIV, TRI_OP_XCHG, TRI_OP_BSWAP, TRI_OP_CDQ,
    TRI_OP_CWDE, TRI_OP_NOP, TRI_OP_LEAVE, TRI_OP_PUSHF, TRI_OP_POPF,
    TRI_OP_RDTSC, TRI_OP_ENDBR, TRI_OP_PAUSE,
    TRI_OP_BT, TRI_OP_BTS, TRI_OP_BTR, TRI_OP_BTC, TRI_OP_BSF, TRI_OP_BSR,
    TRI_OP_ABORT
};

enum {
    TRI_CC_O = 0, TRI_CC_NO, TRI_CC_B, TRI_CC_NB, TRI_CC_E, TRI_CC_NE,
    TRI_CC_BE, TRI_CC_A, TRI_CC_S, TRI_CC_NS, TRI_CC_P, TRI_CC_NP,
    TRI_CC_L, TRI_CC_GE, TRI_CC_LE, TRI_CC_G
};

enum { TRI_NONE = 0, TRI_REG, TRI_MEM, TRI_IMM };

enum {
    TEX_CONST = 0, TEX_VAR, TEX_ADD, TEX_SUB, TEX_MUL, TEX_AND, TEX_OR,
    TEX_XOR, TEX_NOT, TEX_NEG, TEX_SHL, TEX_SHR, TEX_SAR, TEX_ROL,
    TEX_ROR, TEX_ZEXT, TEX_SEXT, TEX_EXTRACT, TEX_CONCAT, TEX_ITE
};

typedef struct TriPageNode {
    tu64 key;
    tu8 *data;
    struct TriPageNode *next;
} TriPageNode;

typedef struct {
    TriPageNode *buckets[TRI_PAGE_HASH];
    int page_count;
    tu64 first_touch[128];
    int first_touch_count;
} TriMem;

typedef struct {
    tu8  op;
    tu8  size;
    tu8  nch;
    tu64 cval;
    int  ch[2];
    tu64 hash;
} TriExpr;

typedef struct {
    tu64 r[16];
    tu64 rip;
    tu8  cf, zf, sf, of, pf, af, df;
    int  mode64;
} TriCpu;

typedef struct {
    tu8 type;
    tu8 reg;
    tu8 base, index, scale, seg;
    tu8 riprel;
    tu32 disp;
    tu64 imm;
    tu8 size;
} TriOperand;

typedef struct {
    tu8 len, op, osize, cond;
    TriOperand dst, src, third;
    tu64 rel;
    tu64 ip;
} TriInsn;

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
} TriLoop;

typedef struct {
    tu64 addr;
    int  insn_count;
    char summary[160];
} TriHandler;

typedef struct {
    char module[64];
    char function[192];
    tu64 addr;
} TriCatalogEntry;


typedef struct {
    tu32 slot_rva;
    tu64 resolved_addr;
    char name[128];
    int  how;
} TriSlotFix;
#define TRI_MAX_SLOT_FIXES 512
typedef struct {
    tu64 image_base;
    tu32 image_size;
    tu32 machine;
    tu64 ep_rva;
    char dump_path[TRI_MAX_PATH];
    char output_dir[TRI_MAX_PATH];
    char target_name[128];
    TriCatalogEntry *catalog;
    int  catalog_count;
    tu32 *slot_rvas;
    tu64 *slot_vals;
    int  slot_count;
    int  trace_enabled;
    TriSlotFix *fixes;
    int  fix_count;
} TriContext;


typedef struct {
    TriContext *ctx;
    TriCpu  cpu;
    TriMem  mem;
    TriExpr *exprs;
    int      expr_count;
    int      hc_table[TRI_HASHCONS_SIZE];
    int      reg_ver[16];
    int      reg_expr[16];
    int      last_flags_reg;
    TriLoop  loops[TRI_MAX_LOOP_TRACK];
    int      loop_count;
    TriHandler handlers[TRI_MAX_HANDLERS];
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
} TriState;

static const char *tri_reg_names[16] = {
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
};

static const char *tri_op_names[56] = {
    "?", "mov", "lea", "movsx", "movzx", "movsxd", "add", "or", "adc",
    "sbb", "and", "sub", "xor", "cmp", "test", "inc", "dec", "push",
    "pop", "jmp", "j", "call", "ret", "set", "cmov", "shl", "shr",
    "sar", "rol", "ror", "not", "neg", "mul", "imul", "imul",
    "div", "idiv", "xchg", "bswap", "cdq", "cwde", "nop", "leave",
    "pushf", "popf", "rdtsc", "endbr64", "pause", "bt", "bts", "btr",
    "btc", "bsf", "bsr", "?"
};

static const char *tri_cc_names[16] = {
    "o", "no", "b", "ae", "e", "ne", "be", "a",
    "s", "ns", "p", "np", "l", "ge", "le", "g"
};

static void *tri_xcalloc(size_t n, size_t sz)
{
    void *p = calloc(n ? n : 1, sz ? sz : 1);
    if (!p) { fprintf(stderr, "triton: out of memory\n"); exit(3); }
    return p;
}

static tu32 tri_page_bucket(tu64 addr)
{
    tu64 pn = addr / TRI_PAGE_SIZE;
    tu64 h = pn * 0x9E3779B97F4A7C15ULL;
    return (tu32)(h >> 40) & (TRI_PAGE_HASH - 1);
}

static tu8 *tri_page_find(TriMem *m, tu64 addr)
{
    for (TriPageNode *n = m->buckets[tri_page_bucket(addr)]; n; n = n->next)
        if (n->key == addr / TRI_PAGE_SIZE) return n->data;
    return NULL;
}

static tu8 *tri_page_get(TriMem *m, tu64 addr)
{
    tu32 b = tri_page_bucket(addr);
    tu64 pn = addr / TRI_PAGE_SIZE;
    for (TriPageNode *n = m->buckets[b]; n; n = n->next)
        if (n->key == pn) return n->data;
    TriPageNode *np = (TriPageNode *)tri_xcalloc(1, sizeof(TriPageNode));
    np->key = pn;
    np->data = (tu8 *)tri_xcalloc(TRI_PAGE_SIZE, 1);
    np->next = m->buckets[b];
    m->buckets[b] = np;
    m->page_count++;
    if (m->first_touch_count < 128)
        m->first_touch[m->first_touch_count++] = pn * TRI_PAGE_SIZE;
    return np->data;
}

#endif

const char *tri_mnemonic(TriInsn *ins);
int tri_decode(TriState *S, tu64 ip, TriInsn *ins);

#endif
