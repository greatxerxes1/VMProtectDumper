#include "vmpd.h"
#include "triton_engine.h"

ResolvedIATEntry g_resolved_iat[MAX_IAT_RESOLVED];

static int tri_expr_new(TriState *S, tu8 op, tu8 size, tu64 cval, int c0, int c1)
{
    if (S->expr_count >= TRI_MAX_EXPRS) return -1;
    int id = S->expr_count++;
    TriExpr *e = &S->exprs[id];
    e->op = op; e->size = size; e->cval = cval;
    e->ch[0] = c0; e->ch[1] = c1; e->hash = 0;
    return id;
}

static int tri_is_const(TriState *S, int id, tu64 *v)
{
    if (id >= 0 && S->exprs[id].op == TEX_CONST) { *v = S->exprs[id].cval; return 1; }
    return 0;
}

static int tri_mk_const(TriState *S, tu8 size, tu64 v)
{
    tu64 mask = (size >= 8) ? ~0ULL : ((1ULL << (size * 8)) - 1);
    return tri_expr_new(S, TEX_CONST, size, v & mask, -1, -1);
}

static tu64 tri_expr_hash_of(TriState *S, const TriExpr *e)
{
    tu64 h = 1469598103934665603ULL;
    h ^= e->op; h *= 1099511628211ULL;
    h ^= e->size; h *= 1099511628211ULL;
    for (int i = 0; i < 8; i++) { h ^= (tu8)(e->cval >> (i * 8)); h *= 1099511628211ULL; }
    int nch = (e->op == TEX_CONST || e->op == TEX_VAR) ? 0 : ((e->ch[1] >= 0) ? 2 : ((e->ch[0] >= 0) ? 1 : 0));
    for (int i = 0; i < nch; i++) {
        int c = e->ch[i];
        tu64 ch = (c >= 0) ? S->exprs[c].hash : 0;
        for (int k = 0; k < 8; k++) { h ^= (tu8)(ch >> (k * 8)); h *= 1099511628211ULL; }
    }
    return h;
}

static int tri_hc_find(TriState *S, const TriExpr *t, tu64 h)
{
    tu32 b = (tu32)(h >> 32) & (TRI_HASHCONS_SIZE - 1);
    for (tu32 step = 0; step < 16; step++) {
        tu32 slot = (b + step) & (TRI_HASHCONS_SIZE - 1);
        int cur = S->hc_table[slot];
        if (cur < 0) return -1;
        TriExpr *e = &S->exprs[cur];
        if (e->hash == h && e->op == t->op && e->size == t->size &&
            e->cval == t->cval && e->ch[0] == t->ch[0] && e->ch[1] == t->ch[1])
            return cur;
    }
    return -1;
}

static void tri_hc_insert(TriState *S, int id)
{
    tu32 b = (tu32)(S->exprs[id].hash >> 32) & (TRI_HASHCONS_SIZE - 1);
    for (tu32 step = 0; step < TRI_HASHCONS_SIZE; step++) {
        tu32 slot = (b + step) & (TRI_HASHCONS_SIZE - 1);
        if (S->hc_table[slot] < 0) { S->hc_table[slot] = id; return; }
    }
}

static int tri_build(TriState *S, tu8 op, tu8 size, tu64 cval, int c0, int c1)
{
    if (S->expr_count >= TRI_MAX_EXPRS) return -1;
    int id = S->expr_count;
    TriExpr *e = &S->exprs[id];
    e->op = op; e->size = size; e->cval = cval; e->ch[0] = c0; e->ch[1] = c1;
    e->hash = tri_expr_hash_of(S, e);
    int found = tri_hc_find(S, e, e->hash);
    if (found >= 0) return found;
    S->expr_count++;
    tri_hc_insert(S, id);
    return id;
}

static int tri_mk_var(TriState *S, tu8 size, int reg, int ver)
{
    return tri_build(S, TEX_VAR, size, ((tu64)(ver & 0xFFFFF) << 8) | (tu64)(reg & 0xFF), -1, -1);
}

static int tri_simplify(TriState *S, tu8 op, tu8 size, tu64 cval, int a, int b)
{
    tu64 cv, dv;
    int is_c = tri_is_const(S, a, &cv);
    int is_d = (b >= 0) ? tri_is_const(S, b, &dv) : 0;

    switch (op) {
    case TEX_ADD:
        if (is_c && cv == 0) return b;
        if (is_d && dv == 0) return a;
        if (is_c && is_d) return tri_mk_const(S, size, cv + dv);
        break;
    case TEX_SUB:
        if (is_d && dv == 0) return a;
        if (a == b) return tri_mk_const(S, size, 0);
        if (is_c && is_d) return tri_mk_const(S, size, cv - dv);
        break;
    case TEX_MUL:
        if ((is_c && cv == 0) || (is_d && dv == 0)) return tri_mk_const(S, size, 0);
        if (is_c && cv == 1) return b;
        if (is_d && dv == 1) return a;
        if (is_c && is_d) return tri_mk_const(S, size, cv * dv);
        break;
    case TEX_AND:
        if ((is_c && cv == 0) || (is_d && dv == 0)) return tri_mk_const(S, size, 0);
        if (a == b) return a;
        if (is_c && is_d) return tri_mk_const(S, size, cv & dv);
        break;
    case TEX_OR:
        if (a == b) return a;
        if (is_c && cv == 0) return b;
        if (is_d && dv == 0) return a;
        if (is_c && is_d) return tri_mk_const(S, size, cv | dv);
        break;
    case TEX_XOR:
        if (a == b) return tri_mk_const(S, size, 0);
        if (is_c && cv == 0) return b;
        if (is_d && dv == 0) return a;
        if (is_c && is_d) return tri_mk_const(S, size, cv ^ dv);
        break;
    case TEX_NOT:
        if (is_c) return tri_mk_const(S, size, ~cv);
        if (a >= 0 && S->exprs[a].op == TEX_NOT) return S->exprs[a].ch[0];
        break;
    case TEX_NEG:
        if (is_c) return tri_mk_const(S, size, 0 - cv);
        if (a >= 0 && S->exprs[a].op == TEX_NEG) return S->exprs[a].ch[0];
        break;
    case TEX_SHL:
        if (is_d && dv == 0) return a;
        if (is_c && cv == 0) return tri_mk_const(S, size, 0);
        if (is_c && is_d) return tri_mk_const(S, size, (dv >= 64) ? 0 : (cv << dv));
        break;
    case TEX_SHR:
        if (is_d && dv == 0) return a;
        if (is_c && cv == 0) return tri_mk_const(S, size, 0);
        if (is_c && is_d) return tri_mk_const(S, size, (dv >= 64) ? 0 : (cv >> dv));
        break;
    case TEX_SAR:
        if (is_d && dv == 0) return a;
        if (is_c && is_d)
            return tri_mk_const(S, size, (dv >= 64) ? (tu64)((ts64)cv >> 63) : (tu64)((ts64)cv >> dv));
        break;
    case TEX_ROL: {
        if (is_d && dv == 0) return a;
        if (is_c && is_d) {
            tu64 bits = (tu64)(size * 8);
            tu64 sh = dv % (bits ? bits : 1);
            tu64 m = (size >= 8) ? ~0ULL : ((1ULL << (size * 8)) - 1);
            return tri_mk_const(S, size, sh ? (((cv << sh) | (cv >> (bits - sh))) & m) : (cv & m));
        }
        break;
    }
    case TEX_ROR: {
        if (is_d && dv == 0) return a;
        if (is_c && is_d) {
            tu64 bits = (tu64)(size * 8);
            tu64 sh = dv % (bits ? bits : 1);
            tu64 m = (size >= 8) ? ~0ULL : ((1ULL << (size * 8)) - 1);
            return tri_mk_const(S, size, sh ? (((cv >> sh) | (cv << (bits - sh))) & m) : (cv & m));
        }
        break;
    }
    case TEX_ZEXT:
        if (is_c) return tri_mk_const(S, size, cv);
        break;
    case TEX_SEXT:
        if (is_c) {
            int abits = (a >= 0) ? S->exprs[a].size * 8 : 64;
            tu64 sgn = 1ULL << (abits - 1);
            tu64 v = (cv & (sgn - 1));
            if (cv & sgn) v -= sgn;
            return tri_mk_const(S, size, (tu64)v);
        }
        break;
    case TEX_EXTRACT:
        if (is_c) {
            tu64 sh = (cval & 0xFF) * 8;
            tu64 mask = (size >= 8) ? ~0ULL : ((1ULL << (size * 8)) - 1);
            return tri_mk_const(S, size, (cv >> sh) & mask);
        }
        break;
    case TEX_CONCAT: {
        tu64 sh = (cval & 0xFF) * 8;
        if (is_c && is_d) return tri_mk_const(S, size, (dv << sh) | (cv & ((sh < 64) ? ((1ULL << sh) - 1) : ~0ULL)));
        if (is_c && cv == 0) return tri_simplify(S, TEX_SHL, size, 0, b, tri_mk_const(S, 1, sh));
        break;
    }
    default:
        break;
    }
    return tri_build(S, op, size, cval, a, b);
}

static void tri_expr_print(TriState *S, int id, FILE *f, int depth)
{
    if (id < 0 || depth > 12) { fputs("?", f); return; }
    TriExpr *e = &S->exprs[id];
    switch (e->op) {
    case TEX_CONST:
        fprintf(f, "0x%llX", (unsigned long long)e->cval);
        break;
    case TEX_VAR:
        fprintf(f, "%s@%u", tri_reg_names[(int)(e->cval & 0xFF)],
                (unsigned)((e->cval >> 8) & 0xFFFFF));
        break;
    case TEX_NOT: fputs("NOT(", f); tri_expr_print(S, e->ch[0], f, depth + 1); fputs(")", f); break;
    case TEX_NEG: fputs("NEG(", f); tri_expr_print(S, e->ch[0], f, depth + 1); fputs(")", f); break;
    case TEX_ZEXT: fputs("ZEXT(", f); tri_expr_print(S, e->ch[0], f, depth + 1); fprintf(f, "->%u)", e->size * 8); break;
    case TEX_SEXT: fputs("SEXT(", f); tri_expr_print(S, e->ch[0], f, depth + 1); fprintf(f, "->%u)", e->size * 8); break;
    case TEX_EXTRACT:
        fputs("EXTRACT(", f); tri_expr_print(S, e->ch[0], f, depth + 1);
        fprintf(f, ",+%u,%u)", (unsigned)(e->cval & 0xFF), e->size * 8);
        break;
    case TEX_CONCAT:
        fputs("CONCAT(", f); tri_expr_print(S, e->ch[0], f, depth + 1); fputs(",", f);
        tri_expr_print(S, e->ch[1], f, depth + 1); fprintf(f, ",+%u)", (unsigned)(e->cval & 0xFF) * 8);
        break;
    default: {
        const char *sym = "?";
        switch (e->op) {
        case TEX_ADD: sym = "+"; break; case TEX_SUB: sym = "-"; break;
        case TEX_MUL: sym = "*"; break; case TEX_AND: sym = "&"; break;
        case TEX_OR: sym = "|"; break; case TEX_XOR: sym = "^"; break;
        case TEX_SHL: sym = "<<"; break; case TEX_SHR: sym = ">>"; break;
        case TEX_SAR: sym = ">>a"; break; case TEX_ROL: sym = "rotl"; break;
        case TEX_ROR: sym = "rotr"; break;
        default: break;
        }
        fputc('(', f);
        tri_expr_print(S, e->ch[0], f, depth + 1);
        if (e->ch[1] >= 0) { fprintf(f, " %s ", sym); tri_expr_print(S, e->ch[1], f, depth + 1); }
        fputc(')', f);
        break;
    }
    }
}

static tu64 tri_mem_read(TriState *S, tu64 addr, int size)
{
    tu64 v = 0;
    for (int i = 0; i < size; i++) {
        tu8 *pg = tri_page_find(&S->mem, addr + (tu64)i);
        tu8 b;
        if (pg) b = pg[(addr + (tu64)i) % TRI_PAGE_SIZE];
        else b = tri_page_get(&S->mem, addr + (tu64)i)[(addr + (tu64)i) % TRI_PAGE_SIZE];
        v |= (tu64)b << (i * 8);
    }
    return v;
}

static void tri_mem_write(TriState *S, tu64 addr, int size, tu64 v)
{
    for (int i = 0; i < size; i++) {
        tu8 *p = tri_page_get(&S->mem, addr + (tu64)i);
        p[(addr + (tu64)i) % TRI_PAGE_SIZE] = (tu8)(v >> (i * 8));
    }
}

static void tri_mem_load_block(TriState *S, tu64 addr, const tu8 *src, tu64 len)
{
    for (tu64 i = 0; i < len; i++) {
        tu8 *p = tri_page_get(&S->mem, addr + i);
        p[(addr + i) % TRI_PAGE_SIZE] = src[i];
    }
}

static tu64 tri_reg_mask(TriState *S, int osize)
{
    if (osize >= 8) return ~0ULL;
    if (osize == 4 && !S->cpu.mode64) return ~0ULL;
    return (1ULL << (osize * 8)) - 1;
}

static tu64 tri_reg_read(TriState *S, int reg, int osize)
{
    return S->cpu.r[reg] & tri_reg_mask(S, osize);
}

static void tri_reg_write(TriState *S, int reg, int osize, tu64 v)
{
    tu64 m = tri_reg_mask(S, osize);
    if (osize >= 8 || (osize == 4 && !S->cpu.mode64))
        S->cpu.r[reg] = v & m;
    else if (osize == 4)
        S->cpu.r[reg] = v & m;
    else if (osize == 2)
        S->cpu.r[reg] = (S->cpu.r[reg] & ~0xFFFFULL) | (v & 0xFFFF);
    else
        S->cpu.r[reg] = (S->cpu.r[reg] & ~0xFFULL) | (v & 0xFF);
}

static int tri_expr_of_reg(TriState *S, int reg, int osize, int high8)
{
    int full = S->reg_expr[reg];
    int full_size = S->cpu.mode64 ? 8 : 4;
    if (full < 0) return -1;
    if (osize == full_size) return full;
    if (osize == 1 && high8) return tri_simplify(S, TEX_EXTRACT, 1, 1, full, -1);
    return tri_simplify(S, TEX_EXTRACT, (tu8)osize, 0, full, -1);
}

static void tri_reg_write_sym(TriState *S, int reg, int osize, int high8, tu64 cval, int expr_id)
{
    tri_reg_write(S, reg, osize, cval);
    S->reg_ver[reg]++;
    if (S->fast_mode || expr_id < 0) {
        S->reg_expr[reg] = -1;
        return;
    }
    int full_size = S->cpu.mode64 ? 8 : 4;
    if (osize == full_size) {
        S->reg_expr[reg] = expr_id;
        return;
    }
    int old = S->reg_expr[reg];
    if (old < 0) {
        S->reg_expr[reg] = -1;
        return;
    }
    if (S->cpu.mode64 && osize == 4) {
        int z = tri_mk_const(S, 4, 0);
        S->reg_expr[reg] = tri_simplify(S, TEX_CONCAT, 8, 4, expr_id, z);
        return;
    }
    if (osize == 1 && high8) {
        int lo = tri_simplify(S, TEX_EXTRACT, 1, 0, old, -1);
        int lo2 = tri_simplify(S, TEX_CONCAT, 2, 1, lo, expr_id);
        int hi = tri_simplify(S, TEX_EXTRACT, 2, 2, old, -1);
        S->reg_expr[reg] = tri_simplify(S, TEX_CONCAT, 4, 2, lo2, hi);
        return;
    }
    if (osize == 1) {
        int hi = tri_simplify(S, TEX_EXTRACT, 3, 1, old, -1);
        S->reg_expr[reg] = tri_simplify(S, TEX_CONCAT, 4, 1, expr_id, hi);
        return;
    }
    int hi = tri_simplify(S, TEX_EXTRACT, 2, 2, old, -1);
    S->reg_expr[reg] = tri_simplify(S, TEX_CONCAT, 4, 2, expr_id, hi);
}

static int tri_cond_eval(TriState *S, int cc)
{
    tu8 cf = S->cpu.cf, zf = S->cpu.zf, sf = S->cpu.sf;
    tu8 of = S->cpu.of, pf = S->cpu.pf;
    switch (cc) {
    case TRI_CC_O: return of;
    case TRI_CC_NO: return !of;
    case TRI_CC_B: return cf;
    case TRI_CC_NB: return !cf;
    case TRI_CC_E: return zf;
    case TRI_CC_NE: return !zf;
    case TRI_CC_BE: return cf || zf;
    case TRI_CC_A: return !cf && !zf;
    case TRI_CC_S: return sf;
    case TRI_CC_NS: return !sf;
    case TRI_CC_P: return pf;
    case TRI_CC_NP: return !pf;
    case TRI_CC_L: return sf != of;
    case TRI_CC_GE: return sf == of;
    case TRI_CC_LE: return zf || (sf != of);
    case TRI_CC_G: return !zf && (sf == of);
    default: return 0;
    }
}

static tu8 tri_parity(tu64 v)
{
    v ^= v >> 32; v ^= v >> 16; v ^= v >> 8; v ^= v >> 4;
    v ^= v >> 2; v ^= v >> 1;
    return (tu8)((~v) & 1);
}

static void tri_set_zsp(TriState *S, tu64 res, int osize)
{
    tu64 m = (osize >= 8) ? ~0ULL : ((1ULL << (osize * 8)) - 1);
    tu64 v = res & m;
    S->cpu.zf = (v == 0);
    S->cpu.sf = (tu8)((v >> (osize * 8 - 1)) & 1);
    S->cpu.pf = tri_parity(v & 0xFF);
}

static void tri_flags_add(TriState *S, tu64 a, tu64 b, tu64 res, int osize)
{
    tu64 bits = (tu64)(osize * 8);
    tu64 m = (bits >= 64) ? ~0ULL : ((1ULL << bits) - 1);
    tu64 sa = (a >> (bits - 1)) & 1;
    tu64 sb = (b >> (bits - 1)) & 1;
    tu64 sr = ((res & m) >> (bits - 1)) & 1;
    S->cpu.cf = (bits >= 64) ? (res < (a & m)) || (res < (b & m)) : ((res >> bits) & 1);
    if (bits >= 64) S->cpu.cf = (res < a) ? 1 : 0;
    S->cpu.of = (tu8)((sa == sb) && (sr != sa));
    S->cpu.af = (tu8)(((a ^ b ^ res) >> 4) & 1);
    tri_set_zsp(S, res, osize);
}

static void tri_flags_sub(TriState *S, tu64 a, tu64 b, tu64 res, int osize)
{
    tu64 bits = (tu64)(osize * 8);
    tu64 m = (bits >= 64) ? ~0ULL : ((1ULL << bits) - 1);
    tu64 sa = (a >> (bits - 1)) & 1;
    tu64 sb = (b >> (bits - 1)) & 1;
    tu64 sr = ((res & m) >> (bits - 1)) & 1;
    S->cpu.cf = ((a & m) < (b & m));
    S->cpu.of = (tu8)((sa != sb) && (sr != sa));
    S->cpu.af = (tu8)(((a ^ b ^ res) >> 4) & 1);
    tri_set_zsp(S, res, osize);
}

static void tri_flags_logic(TriState *S, tu64 res, int osize)
{
    S->cpu.cf = 0;
    S->cpu.of = 0;
    S->cpu.af = 0;
    tri_set_zsp(S, res, osize);
}


static tu64 tri_eff_addr_compute(TriState *S, TriInsn *ins);

static int _stricmp_null_safe(const char *a, const char *b)
{
    if (!a || !b) return -1;
    char ca, cb;
    for (;;) {
        ca = *a++; cb = *b++;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return ca - cb;
        if (!ca) return 0;
    }
}

static int tri_cat_by_addr(TriState *S, tu64 addr)
{
    TriContext *ctx = S->ctx;
    for (int i = 0; i < ctx->catalog_count; i++)
        if (ctx->catalog[i].addr == addr) return i;
    return -1;
}

static tu64 tri_cat_find(TriState *S, const char *module, const char *func)
{
    TriContext *ctx = S->ctx;
    for (int i = 0; i < ctx->catalog_count; i++) {
        if (func && _stricmp_null_safe(ctx->catalog[i].function, func) == 0) {
            if (!module || !module[0]) return ctx->catalog[i].addr;
            if (_stricmp_null_safe(ctx->catalog[i].module, module) == 0)
                return ctx->catalog[i].addr;
        }
    }
    return 0;
}

static int tri_read_import_name(TriState *S, tu64 addr, char *out, int cap)
{
    if (!addr || cap < 64) return 0;
    tu16 hint = (tu16)tri_mem_read(S, addr, 2);
    (void)hint;
    int n = 0;
    for (int i = 0; i < 63; i++) {
        tu8 c = (tu8)tri_mem_read(S, addr + 2 + (tu64)i, 1);
        if (c == 0) break;
        if (c < 0x20 || c > 0x7E) return 0;
        out[n++] = (char)c;
    }
    out[n] = 0;
    if (n < 4 || n >= 63) return 0;
    return n;
}

static void tri_read_cstr(TriState *S, tu64 addr, char *out, int cap)
{
    int n = 0;
    while (n < cap - 1) {
        tu8 b = (tu8)tri_mem_read(S, addr + (tu64)n, 1);
        if (!b) break;
        out[n++] = (char)b;
    }
    out[n] = 0;
}

static tu64 tri_module_fake_base(TriState *S, const char *module)
{
    for (int i = 0; i < S->dllmap_count; i++)
        if (_stricmp_null_safe(S->dllmap[i].module, module) == 0)
            return S->dllmap[i].fake_base;
    if (S->dllmap_count < 64) {
        tu64 base = TRI_FAKE_DLL_BASE + (tu64)S->dllmap_count * 0x1000000ULL;
        strncpy(S->dllmap[S->dllmap_count].module, module, 63);
        S->dllmap[S->dllmap_count].module[63] = 0;
        S->dllmap[S->dllmap_count].fake_base = base;
        S->dllmap_count++;
        return base;
    }
    return TRI_FAKE_DLL_BASE;
}

static const char *tri_module_by_handle(TriState *S, tu64 handle)
{
    TriContext *ctx = S->ctx;
    if (handle == 0) return NULL;
    for (int i = 0; i < S->dllmap_count; i++)
        if (S->dllmap[i].fake_base == handle) return S->dllmap[i].module;
    tu64 best_lo = 0, best_hi = ~0ULL;
    const char *best_name = NULL;
    for (int i = 0; i < ctx->catalog_count; i++) {
        tu64 a = ctx->catalog[i].addr;
        if (a >= handle && a < handle + 0x2000000ULL) {
            if (!best_name) {
                best_lo = a; best_hi = a;
                best_name = ctx->catalog[i].module;
            } else if (_stricmp_null_safe(ctx->catalog[i].module, best_name) == 0) {
                if (a < best_lo) best_lo = a;
                if (a > best_hi) best_hi = a;
            }
        }
    }
    (void)best_lo; (void)best_hi;
    return best_name;
}

static int tri_api_hook(TriState *S, tu64 target)
{
    int is_gpa = (S->gpa_addr && target == S->gpa_addr);
    int is_lla = (S->lla_addr && target == S->lla_addr);
    int is_llw = (S->llw_addr && target == S->llw_addr);
    if (!is_gpa && !is_lla && !is_llw) return 0;

    int sp_sz = S->cpu.mode64 ? 8 : 4;
    tu64 retaddr = tri_mem_read(S, S->cpu.r[4], sp_sz);

    if (is_gpa) {
        tu64 hmod, hname;
        if (S->cpu.mode64) {
            hmod = S->cpu.r[1];
            hname = S->cpu.r[2];
        } else {
            hmod = tri_mem_read(S, S->cpu.r[4] + 4, 4);
            hname = tri_mem_read(S, S->cpu.r[4] + 8, 4);
        }
        char name[192];
        tri_read_cstr(S, hname, name, sizeof(name));
        const char *mod = tri_module_by_handle(S, hmod);
        tu64 resolved = 0;
        if (name[0]) {
            if (mod) resolved = tri_cat_find(S, mod, name);
            if (!resolved) resolved = tri_cat_find(S, NULL, name);
        }
        S->cpu.r[0] = resolved;
        if (S->cpu.mode64) S->cpu.r[0] &= ~0ULL;
        S->cpu.r[4] += (tu64)sp_sz;
        S->cpu.rip = retaddr;
        if (!S->fast_mode && S->trace && S->trace_lines < TRI_TRACE_CAP) {
            fprintf(S->trace, "  [hook] GetProcAddress(hmod=0x%llX%s%s, \"%s\") -> 0x%llX\n",
                    (unsigned long long)hmod,
                    mod ? " [" : "", mod ? mod : "", name,
                    (unsigned long long)resolved);
            S->trace_lines++;
        }
        return 1;
    }

    tu64 hname = S->cpu.mode64 ? S->cpu.r[1] : tri_mem_read(S, S->cpu.r[4] + 4, 4);
    char name[192];
    tri_read_cstr(S, hname, name, sizeof(name));
    char base[64];
    strncpy(base, name, sizeof(base) - 1);
    base[sizeof(base) - 1] = 0;
    char *dot = strrchr(base, '.');
    if (dot) *dot = 0;
    tu64 fb = tri_module_fake_base(S, base);
    S->cpu.r[0] = fb;
    S->cpu.r[4] += (tu64)sp_sz;
    S->cpu.rip = retaddr;
    if (!S->fast_mode && S->trace && S->trace_lines < TRI_TRACE_CAP) {
        fprintf(S->trace, "  [hook] LoadLibrary(\"%s\") -> 0x%llX (fake base)\n",
                name, (unsigned long long)fb);
        S->trace_lines++;
    }
    return 1;
}

static TriLoop *tri_loop_find_or_add(TriState *S, tu64 head)
{
    for (int i = 0; i < S->loop_count; i++)
        if (S->loops[i].head == head) return &S->loops[i];
    if (S->loop_count >= TRI_MAX_LOOP_TRACK) return NULL;
    TriLoop *L = &S->loops[S->loop_count++];
    memset(L, 0, sizeof(*L));
    L->head = head;
    L->region_lo = head;
    L->region_hi = head;
    return L;
}

static void tri_loop_note_value(TriLoop *L, tu64 v)
{
    L->hist[L->hpos] = v;
    L->hpos = (L->hpos + 1) % 24;
    if (L->hcount < 24) L->hcount++;
}

static int tri_loop_check_collatz(TriLoop *L, ts64 *out_c)
{
    if (L->hcount < 8) return 0;
    ts64 c = 0;
    int have_c = 0;
    int odd_steps = 0;
    tu32 n = L->hcount;
    for (tu32 i = 0; i + 1 < n; i++) {
        int idx0 = (int)((L->hpos + 24 - n + i) % 24);
        int idx1 = (int)((L->hpos + 24 - n + i + 1) % 24);
        ts64 x = (ts64)L->hist[idx0];
        ts64 y = (ts64)L->hist[idx1];
        if (x <= 0 || y < 0) return 0;
        if ((x & 1) == 0) {
            if (y != (x >> 1)) return 0;
        } else {
            ts64 ci = y - 3 * x;
            if (!have_c) { c = ci; have_c = 1; }
            else if (ci != c) return 0;
            odd_steps++;
        }
    }
    if (!have_c || odd_steps < 2) return 0;
    *out_c = c;
    return 1;
}

static void tri_record_indirect(TriState *S, tu64 target)
{
    TriContext *ctx = S->ctx;
    if (target < ctx->image_base || target >= ctx->image_base + ctx->image_size) return;
    for (int i = 0; i < S->indirect_count; i++)
        if (S->indirect_targets[i] == target) return;
    if (S->indirect_count < 512)
        S->indirect_targets[S->indirect_count++] = target;
}

static void tri_trace_line(TriState *S, TriInsn *ins)
{
    if (!S->trace || S->fast_mode) return;
    if (S->trace_lines >= TRI_TRACE_CAP) {
        if (!S->trace_capped) {
            fprintf(S->trace, "... trace capped at %d lines\n", TRI_TRACE_CAP);
            S->trace_capped = 1;
        }
        return;
    }
    char opstr[128];
    snprintf(opstr, sizeof(opstr), "%s", tri_mnemonic(ins));
    if (ins->rel && (ins->op == TRI_OP_CALL || ins->op == TRI_OP_JMP || ins->op == TRI_OP_JCC)) {
        char tb[48];
        tu64 tgt = ins->ip + ins->len + (tu64)(ts64)ins->rel;
        snprintf(tb, sizeof(tb), " ->0x%llX", (unsigned long long)tgt);
        size_t ol = strlen(opstr);
        if (ol + strlen(tb) < sizeof(opstr)) memcpy(opstr + ol, tb, strlen(tb) + 1);
    }
    const char *os[3] = {NULL, NULL, NULL};
    char bufs[3][48];
    TriOperand *ops[3];
    int nops = 0;
    ops[0] = &ins->dst; ops[1] = &ins->src; ops[2] = &ins->third;
    for (int i = 0; i < 3; i++) {
        TriOperand *o = ops[i];
        if (o->type == TRI_NONE || (o->type == TRI_IMM && i > 0 && ins->op != TRI_OP_IMUL3)) continue;
        if (o->type == TRI_REG) {
            snprintf(bufs[i], sizeof(bufs[i]), "%s", tri_reg_names[o->reg & 15]);
            if (ins->osize == 4 && S->cpu.mode64) snprintf(bufs[i], sizeof(bufs[i]), "e%s", tri_reg_names[o->reg & 15] + 1);
            else if (ins->osize == 2) snprintf(bufs[i], sizeof(bufs[i]), "%s", tri_reg_names[o->reg & 15]);
            else if (ins->osize == 1) bufs[i][0] = 0, snprintf(bufs[i], sizeof(bufs[i]), "b%s", tri_reg_names[o->reg & 15] + 1);
            os[nops++] = bufs[i];
        } else if (o->type == TRI_IMM) {
            snprintf(bufs[i], sizeof(bufs[i]), "0x%llX", (unsigned long long)o->imm);
            os[nops++] = bufs[i];
        } else if (o->type == TRI_MEM) {
            tu64 ea = 0;
            if (o->riprel) ea = ins->ip + ins->len + (tu64)(ts64)(int)o->disp;
            else {
                ea = (o->base != 0xFF) ? S->cpu.r[o->base & 15] : 0;
                if (o->index != 0xFF) ea += S->cpu.r[o->index & 15] * o->scale;
                ea += (tu64)(ts64)(int)o->disp;
                if (o->seg == 0x65) ea = TRI_TEB_ADDR + (o->base == 0xFF ? (tu64)(ts64)(int)o->disp : ea);
                else if (o->seg == 0x64) ea = TRI_TEB_ADDR + ea;
            }
            snprintf(bufs[i], sizeof(bufs[i]), "[0x%llX]", (unsigned long long)ea);
            os[nops++] = bufs[i];
        }
    }
    fprintf(S->trace, "%llu 0x%016llX: %s %s%s%s%s%s | rax=%016llX rcx=%016llX rdx=%016llX rsp=%016llX | CF=%u ZF=%u SF=%u OF=%u\n",
            (unsigned long long)S->instr_count,
            (unsigned long long)ins->ip,
            opstr,
            os[0] ? os[0] : "", os[1] ? " " : "", os[1] ? os[1] : "",
            os[2] ? " " : "", os[2] ? os[2] : "",
            (unsigned long long)S->cpu.r[0], (unsigned long long)S->cpu.r[1],
            (unsigned long long)S->cpu.r[2], (unsigned long long)S->cpu.r[4],
            S->cpu.cf, S->cpu.zf, S->cpu.sf, S->cpu.of);
    S->trace_lines++;
}

static int tri_exec_step(TriState *S)
{
    if (S->cpu.rip == TRI_RET_MAGIC) return TRI_RUN_RET;

    TriInsn ins;
    int len = tri_decode(S, S->cpu.rip, &ins);
    (void)len;
    if (ins.op == TRI_OP_ABORT || len <= 0) {
        snprintf(S->abort_reason, sizeof(S->abort_reason),
                 "decode abort at 0x%llX", (unsigned long long)S->cpu.rip);
        return TRI_RUN_DECODE;
    }

    S->instr_count++;
    S->total_instr_count++;
    if (S->instr_cap == 0) S->instr_cap = TRI_STUB_INSTR_CAP;
    if (S->instr_count > S->instr_cap) {
        snprintf(S->abort_reason, sizeof(S->abort_reason),
                 "instruction cap %llu reached at 0x%llX",
                 (unsigned long long)S->instr_cap,
                 (unsigned long long)S->cpu.rip);
        return TRI_RUN_CAP;
    }
    if (S->ep_mode && S->instr_count == TRI_EP_EARLY_ABORT &&
        S->indirect_count == 0 && S->loop_count == 0) {
        snprintf(S->abort_reason, sizeof(S->abort_reason),
                 "no dispatch activity after %llu instr (linear mutation code), early abort at 0x%llX",
                 (unsigned long long)TRI_EP_EARLY_ABORT,
                 (unsigned long long)S->cpu.rip);
        return TRI_RUN_CAP;
    }
    if (S->total_instr_count > TRI_TOTAL_INSTR_CAP) {
        snprintf(S->abort_reason, sizeof(S->abort_reason),
                 "global instruction cap reached");
        return TRI_RUN_CAP;
    }

    if (S->fast_mode && (S->cpu.rip > S->fast_hi || S->cpu.rip < S->fast_lo)) {
        S->fast_mode = 0;
    }
    if (S->expr_count >= TRI_MAX_EXPRS - 64 && !S->fast_mode) {
        S->fast_mode = 1;
        S->fast_lo = S->cpu.rip;
        S->fast_hi = ~0ULL;
    }

    int osize = ins.osize ? ins.osize : 4;
    tu64 a = 0, b = 0, r = 0;
    int ea1 = -1, ea2 = -1;

    if (ins.dst.type == TRI_REG) ea1 = tri_expr_of_reg(S, ins.dst.reg, osize, 0);
    if (ins.src.type == TRI_REG) ea2 = tri_expr_of_reg(S, ins.src.reg, osize, 0);

    tri_trace_line(S, &ins);

    switch (ins.op) {
    case TRI_OP_NOP:
    case TRI_OP_ENDBR:
    case TRI_OP_PAUSE:
        S->cpu.rip += ins.len;
        return 0;

    case TRI_OP_MOV: {
        if (ins.dst.type == TRI_REG && ins.src.type == TRI_IMM) {
            tu64 v = ins.src.imm;
            int ec = (S->fast_mode) ? -1 : tri_mk_const(S, (tu8)osize, v);
            tri_reg_write_sym(S, ins.dst.reg, osize, 0, v, ec);
        } else if (ins.dst.type == TRI_REG && ins.src.type == TRI_REG) {
            tu64 v = tri_reg_read(S, ins.src.reg, osize);
            int ev = (ea2 >= 0) ? ea2 : -1;
            tri_reg_write_sym(S, ins.dst.reg, osize, 0, v, ev);
        } else if (ins.dst.type == TRI_REG && ins.src.type == TRI_MEM) {
            tu64 v = tri_mem_read(S, tri_eff_addr_compute(S, &ins), osize);
            int ec = (S->fast_mode) ? -1 : tri_mk_const(S, (tu8)osize, v);
            tri_reg_write_sym(S, ins.dst.reg, osize, 0, v, ec);
        } else if (ins.dst.type == TRI_MEM) {
            tu64 ea = tri_eff_addr_compute(S, &ins);
            tu64 v = (ins.src.type == TRI_IMM) ? ins.src.imm :
                     tri_reg_read(S, ins.src.reg, osize);
            tri_mem_write(S, ea, osize, v);
        } else if (ins.dst.type == TRI_MEM && ins.src.type == TRI_NONE) {
            return TRI_RUN_DECODE;
        }
        S->cpu.rip += ins.len;
        return 0;
    }

    case TRI_OP_LEA: {
        tu64 ea = tri_eff_addr_compute(S, &ins);
        tri_reg_write_sym(S, ins.dst.reg, osize, 0, ea,
                          (S->fast_mode) ? -1 : tri_mk_const(S, (tu8)osize, ea));
        S->cpu.rip += ins.len;
        return 0;
    }

    case TRI_OP_MOVSX: case TRI_OP_MOVZX: {
        tu64 v;
        if (ins.src.type == TRI_REG) v = tri_reg_read(S, ins.src.reg, ins.src.size);
        else v = tri_mem_read(S, tri_eff_addr_compute(S, &ins), ins.src.size);
        tu64 res;
        if (ins.op == TRI_OP_MOVZX) res = v;
        else {
            tu64 bits = (tu64)(ins.src.size * 8);
            tu64 sgn = 1ULL << (bits - 1);
            res = (v & (sgn - 1)) - (v & sgn);
            res &= (osize == 8) ? ~0ULL : ((1ULL << (osize * 8)) - 1);
        }
        tri_reg_write_sym(S, ins.dst.reg, osize, 0, res,
                          (S->fast_mode) ? -1 :
                          tri_simplify(S, (ins.op == TRI_OP_MOVZX) ? TEX_ZEXT : TEX_SEXT,
                                       (tu8)osize, 0,
                                       tri_mk_const(S, ins.src.size, v), -1));
        S->cpu.rip += ins.len;
        return 0;
    }

    case TRI_OP_MOVSXD: {
        tu64 v = (ins.src.type == TRI_REG) ? tri_reg_read(S, ins.src.reg, 4) :
                 tri_mem_read(S, tri_eff_addr_compute(S, &ins), 4);
        tu64 sgn = 1ULL << 31;
        tu64 res = (v & (sgn - 1)) - (v & sgn);
        tri_reg_write_sym(S, ins.dst.reg, osize, 0, res,
                          (S->fast_mode) ? -1 :
                          tri_simplify(S, TEX_SEXT, (tu8)osize, 0,
                                       tri_mk_const(S, 4, v), -1));
        S->cpu.rip += ins.len;
        return 0;
    }

    case TRI_OP_ADD: case TRI_OP_OR: case TRI_OP_ADC: case TRI_OP_SBB:
    case TRI_OP_AND: case TRI_OP_SUB: case TRI_OP_XOR: case TRI_OP_CMP:
    case TRI_OP_TEST: {
        if (ins.dst.type == TRI_REG) a = tri_reg_read(S, ins.dst.reg, osize);
        else a = tri_mem_read(S, tri_eff_addr_compute(S, &ins), osize);
        if (ins.src.type == TRI_IMM) b = ins.src.imm & ((osize >= 8) ? ~0ULL : ((1ULL << (osize * 8)) - 1));
        else if (ins.src.type == TRI_REG) b = tri_reg_read(S, ins.src.reg, osize);
        else b = tri_mem_read(S, tri_eff_addr_compute(S, &ins), osize);

        int wr = (ins.op != TRI_OP_CMP && ins.op != TRI_OP_TEST);
        switch (ins.op) {
        case TRI_OP_ADD: r = a + b; if (wr) tri_flags_add(S, a, b, r, osize); break;
        case TRI_OP_ADC: r = a + b + S->cpu.cf; if (wr) tri_flags_add(S, a, b + S->cpu.cf, r, osize); break;
        case TRI_OP_SUB: case TRI_OP_CMP: r = a - b; tri_flags_sub(S, a, b, r, osize); break;
        case TRI_OP_SBB: r = a - b - S->cpu.cf; tri_flags_sub(S, a, b + S->cpu.cf, r, osize); break;
        case TRI_OP_AND: r = a & b; tri_flags_logic(S, r, osize); break;
        case TRI_OP_OR: r = a | b; tri_flags_logic(S, r, osize); break;
        case TRI_OP_XOR: r = a ^ b; tri_flags_logic(S, r, osize); break;
        case TRI_OP_TEST: r = a & b; tri_flags_logic(S, r, osize); break;
        }
        if (ins.op == TRI_OP_CMP || ins.op == TRI_OP_TEST) {
            if (ins.dst.type == TRI_REG) S->last_flags_reg = ins.dst.reg;
            else if (ins.src.type == TRI_REG) S->last_flags_reg = ins.src.reg;
        }
        r &= (osize >= 8) ? ~0ULL : ((1ULL << (osize * 8)) - 1);
        if (wr) {
            int er = -1;
            if (!S->fast_mode) {
                tu8 top = (ins.op == TRI_OP_ADD || ins.op == TRI_OP_ADC) ? TEX_ADD :
                          (ins.op == TRI_OP_SUB || ins.op == TRI_OP_SBB) ? TEX_SUB :
                          (ins.op == TRI_OP_AND) ? TEX_AND :
                          (ins.op == TRI_OP_OR) ? TEX_OR : TEX_XOR;
                int ea_o = (ins.dst.type == TRI_REG) ? ea1 :
                           tri_mk_const(S, (tu8)osize, a);
                int eb_o = (ins.src.type == TRI_IMM) ? tri_mk_const(S, (tu8)osize, ins.src.imm) :
                           (ins.src.type == TRI_REG) ? ((ea2 >= 0) ? ea2 : tri_mk_const(S, (tu8)osize, b)) :
                           tri_mk_const(S, (tu8)osize, b);
                er = tri_simplify(S, top, (tu8)osize, 0, ea_o, eb_o);
            }
            if (ins.dst.type == TRI_REG)
                tri_reg_write_sym(S, ins.dst.reg, osize, 0, r, er);
            else
                tri_mem_write(S, tri_eff_addr_compute(S, &ins), osize, r);
        }
        S->cpu.rip += ins.len;
        return 0;
    }

    case TRI_OP_INC: case TRI_OP_DEC: {
        if (ins.dst.type == TRI_REG) a = tri_reg_read(S, ins.dst.reg, osize);
        else a = tri_mem_read(S, tri_eff_addr_compute(S, &ins), osize);
        tu8 cf_save = S->cpu.cf;
        if (ins.op == TRI_OP_INC) { r = a + 1; tri_flags_add(S, a, 1, r, osize); }
        else { r = a - 1; tri_flags_sub(S, a, 1, r, osize); }
        S->cpu.cf = cf_save;
        r &= (osize >= 8) ? ~0ULL : ((1ULL << (osize * 8)) - 1);
        if (!S->fast_mode) {
            int ea_o = (ins.dst.type == TRI_REG) ? ea1 : tri_mk_const(S, (tu8)osize, a);
            int er = tri_simplify(S, (ins.op == TRI_OP_INC) ? TEX_ADD : TEX_SUB,
                                  (tu8)osize, 0, ea_o, tri_mk_const(S, (tu8)osize, 1));
            if (ins.dst.type == TRI_REG)
                tri_reg_write_sym(S, ins.dst.reg, osize, 0, r, er);
            else
                tri_mem_write(S, tri_eff_addr_compute(S, &ins), osize, r);
        } else {
            if (ins.dst.type == TRI_REG) tri_reg_write(S, ins.dst.reg, osize, r);
            else tri_mem_write(S, tri_eff_addr_compute(S, &ins), osize, r);
        }
        S->cpu.rip += ins.len;
        return 0;
    }

    case TRI_OP_PUSH: {
        int sp_sz = S->cpu.mode64 ? 8 : 4;
        tu64 v;
        if (ins.dst.type == TRI_REG) v = tri_reg_read(S, ins.dst.reg, sp_sz);
        else v = ins.dst.imm & ((sp_sz == 8) ? ~0ULL : 0xFFFFFFFFULL);
        S->cpu.r[4] -= (tu64)sp_sz;
        tri_mem_write(S, S->cpu.r[4], sp_sz, v);
        S->cpu.rip += ins.len;
        return 0;
    }

    case TRI_OP_POP: {
        int sp_sz = S->cpu.mode64 ? 8 : 4;
        tu64 v = tri_mem_read(S, S->cpu.r[4], sp_sz);
        S->cpu.r[4] += (tu64)sp_sz;
        if (ins.dst.type == TRI_REG)
            tri_reg_write_sym(S, ins.dst.reg, sp_sz, 0, v,
                              (S->fast_mode) ? -1 : tri_mk_const(S, (tu8)sp_sz, v));
        S->cpu.rip += ins.len;
        return 0;
    }

    case TRI_OP_PUSHF: {
        int sp_sz = S->cpu.mode64 ? 8 : 4;
        tu64 fl = 0;
        fl |= (tu64)S->cpu.cf;
        fl |= (tu64)S->cpu.pf << 2;
        fl |= (tu64)S->cpu.af << 4;
        fl |= (tu64)S->cpu.zf << 6;
        fl |= (tu64)S->cpu.sf << 7;
        fl |= (tu64)S->cpu.df << 10;
        fl |= (tu64)S->cpu.of << 11;
        fl |= 2;
        S->cpu.r[4] -= (tu64)sp_sz;
        tri_mem_write(S, S->cpu.r[4], sp_sz, fl);
        S->cpu.rip += ins.len;
        return 0;
    }

    case TRI_OP_POPF: {
        int sp_sz = S->cpu.mode64 ? 8 : 4;
        tu64 fl = tri_mem_read(S, S->cpu.r[4], sp_sz);
        S->cpu.r[4] += (tu64)sp_sz;
        S->cpu.cf = (tu8)(fl & 1);
        S->cpu.pf = (tu8)((fl >> 2) & 1);
        S->cpu.af = (tu8)((fl >> 4) & 1);
        S->cpu.zf = (tu8)((fl >> 6) & 1);
        S->cpu.sf = (tu8)((fl >> 7) & 1);
        S->cpu.df = (tu8)((fl >> 10) & 1);
        S->cpu.of = (tu8)((fl >> 11) & 1);
        S->cpu.rip += ins.len;
        return 0;
    }

    case TRI_OP_JMP: {
        tu64 target;
        if (ins.rel) target = S->cpu.rip + ins.len + (ts64)ins.rel;
        else if (ins.dst.type == TRI_REG) target = S->cpu.r[ins.dst.reg & 15];
        else target = tri_mem_read(S, tri_eff_addr_compute(S, &ins), S->cpu.mode64 ? 8 : 4);
        if (!ins.rel) {
            tri_record_indirect(S, target);
            if (target < S->cpu.rip) {
                TriLoop *L = tri_loop_find_or_add(S, target);
                if (L) {
                    L->iters++;
                    if (L->region_hi < S->cpu.rip + ins.len) L->region_hi = S->cpu.rip + ins.len;
                    if (L->iters == TRI_LOOP_FAST_ITER && !S->fast_mode) {
                        S->fast_mode = 1;
                        S->fast_lo = target;
                        S->fast_hi = S->cpu.rip + ins.len;
                    }
                    if (L->iters > TRI_LOOP_HARD_CAP && S->indirect_count < 8) {
                        S->loop_bombs++;
                        snprintf(S->abort_reason, sizeof(S->abort_reason),
                                 "jmp loop bomb at 0x%llX (%llu iters, %d targets - ping-pong junk)",
                                 (unsigned long long)target,
                                 (unsigned long long)L->iters, S->indirect_count);
                        return TRI_RUN_CAP;
                    }
                }
            }
        }
        if (tri_api_hook(S, target)) return 0;
        int ci = tri_cat_by_addr(S, target);
        if (ci >= 0) { S->cpu.rip = target; return TRI_RUN_RESOLVED; }
        S->cpu.rip = target;
        return 0;
    }

    case TRI_OP_JCC: {
        tu64 target = S->cpu.rip + ins.len + (ts64)ins.rel;
        int taken = tri_cond_eval(S, ins.cond);
        if (target <= S->cpu.rip && taken) {
            TriLoop *L = tri_loop_find_or_add(S, target);
            if (L) {
                L->iters++;
                if (L->region_hi < S->cpu.rip + ins.len) L->region_hi = S->cpu.rip + ins.len;
                {
                    tu64 tv = (S->last_flags_reg >= 0) ? tri_reg_read(S, S->last_flags_reg, 8) : 0;
                    tri_loop_note_value(L, tv);
                }
                ts64 c = 0;
                if (!L->collatz && tri_loop_check_collatz(L, &c)) {
                    L->collatz = 1;
                    L->collatz_c = c;
                    S->collatz_bypasses++;
                    printf("    [triton] Collatz-type loop at 0x%llX (x -> 3x%lld, x>>1), bypassing via fast-concrete\n",
                           (unsigned long long)target, (long long)c);
                }
                if (L->iters == TRI_LOOP_FAST_ITER && !S->fast_mode) {
                    S->fast_mode = 1;
                    S->fast_lo = target;
                    S->fast_hi = S->cpu.rip + ins.len;
                }
                if (L->iters > TRI_LOOP_HARD_CAP) {
                    S->loop_bombs++;
                    snprintf(S->abort_reason, sizeof(S->abort_reason),
                             "loop bomb at 0x%llX (%llu iterations, divergent Collatz-type?)",
                             (unsigned long long)target,
                             (unsigned long long)L->iters);
                    return TRI_RUN_CAP;
                }
            }
        } else if (target > S->cpu.rip) {
            TriLoop *L = NULL;
            for (int i = 0; i < S->loop_count; i++) {
                if (S->cpu.rip >= S->loops[i].region_lo &&
                    S->cpu.rip <= S->loops[i].region_hi && S->loops[i].iters > 0) {
                    L = &S->loops[i];
                    break;
                }
            }
            if (L && !L->reported && L->iters > 8) {
                L->reported = 1;
                if (S->fast_mode) { S->fast_mode = 0; }
                if (L->collatz) {
                    printf("    [triton] Collatz loop at 0x%llX converged after %llu iterations (exit taken)\n",
                           (unsigned long long)L->head, (unsigned long long)L->iters);
                }
            }
        }
        S->cpu.rip = taken ? target : (S->cpu.rip + ins.len);
        return 0;
    }

    case TRI_OP_CALL: {
        int sp_sz = S->cpu.mode64 ? 8 : 4;
        tu64 target;
        if (ins.rel) target = S->cpu.rip + ins.len + (ts64)ins.rel;
        else if (ins.dst.type == TRI_REG) target = S->cpu.r[ins.dst.reg & 15];
        else target = tri_mem_read(S, tri_eff_addr_compute(S, &ins), sp_sz);
        if (!ins.rel) tri_record_indirect(S, target);
        if (tri_api_hook(S, target)) return 0;
        int ci = tri_cat_by_addr(S, target);
        if (ci >= 0) {
            S->cpu.rip = target;
            return TRI_RUN_RESOLVED;
        }
        S->cpu.r[4] -= (tu64)sp_sz;
        tri_mem_write(S, S->cpu.r[4], sp_sz, S->cpu.rip + ins.len);
        S->cpu.rip = target;
        return 0;
    }

    case TRI_OP_RET: {
        int sp_sz = S->cpu.mode64 ? 8 : 4;
        tu64 v = tri_mem_read(S, S->cpu.r[4], sp_sz);
        S->cpu.r[4] += (tu64)sp_sz;
        if (ins.src.type == TRI_IMM) S->cpu.r[4] += ins.src.imm;
        if (v == TRI_RET_MAGIC) return TRI_RUN_RET;
        S->cpu.rip = v;
        return 0;
    }

    case TRI_OP_SETCC: {
        tu64 v = (tu64)tri_cond_eval(S, ins.cond);
        if (ins.dst.type == TRI_REG) tri_reg_write(S, ins.dst.reg, 1, v);
        else tri_mem_write(S, tri_eff_addr_compute(S, &ins), 1, v);
        S->cpu.rip += ins.len;
        return 0;
    }

    case TRI_OP_CMOVCC: {
        if (tri_cond_eval(S, ins.cond)) {
            tu64 v = (ins.src.type == TRI_REG) ? tri_reg_read(S, ins.src.reg, osize) :
                     tri_mem_read(S, tri_eff_addr_compute(S, &ins), osize);
            tri_reg_write_sym(S, ins.dst.reg, osize, 0, v, (S->fast_mode) ? -1 : ea2);
        }
        S->cpu.rip += ins.len;
        return 0;
    }

    case TRI_OP_SHL: case TRI_OP_SHR: case TRI_OP_SAR: case TRI_OP_ROL: case TRI_OP_ROR: {
        tu64 cnt;
        if (ins.src.type == TRI_IMM) cnt = ins.src.imm & 0x3F;
        else cnt = S->cpu.r[1] & 0x3F;
        if (ins.dst.type == TRI_REG) a = tri_reg_read(S, ins.dst.reg, osize);
        else a = tri_mem_read(S, tri_eff_addr_compute(S, &ins), osize);
        if (cnt == 0) { S->cpu.rip += ins.len; return 0; }
        tu64 bits = (tu64)(osize * 8);
        tu64 m = (bits >= 64) ? ~0ULL : ((1ULL << bits) - 1);
        tu64 av = a & m;
        cnt &= 0x3F;
        if (bits < 64) cnt &= (bits == 32) ? 0x1F : 0x3F;
        switch (ins.op) {
        case TRI_OP_SHL: r = (av << cnt) & m; S->cpu.cf = (tu8)((av >> (bits - cnt)) & 1); break;
        case TRI_OP_SHR: r = (av >> cnt) & m; S->cpu.cf = (tu8)((av >> (cnt - 1)) & 1); break;
        case TRI_OP_SAR: {
            ts64 sv = (ts64)av;
            ts64 sh = (cnt >= 64) ? 63 : (ts64)cnt;
            r = ((tu64)(sv >> sh)) & m;
            S->cpu.cf = (tu8)(((ts64)av >> (sh > 63 ? 63 : sh)) & 1);
            break;
        }
        case TRI_OP_ROL:
            cnt %= bits;
            r = ((av << cnt) | (av >> (bits - cnt))) & m;
            S->cpu.cf = r & 1;
            break;
        case TRI_OP_ROR:
            cnt %= bits;
            r = ((av >> cnt) | (av << (bits - cnt))) & m;
            S->cpu.cf = (r >> (bits - 1)) & 1;
            break;
        }
        if (cnt == 1) {
            if (ins.op == TRI_OP_SHL) S->cpu.of = (tu8)(((r >> (bits - 1)) & 1) ^ S->cpu.cf);
            else if (ins.op == TRI_OP_SHR) S->cpu.of = (tu8)((av >> (bits - 1)) & 1);
            else S->cpu.of = 0;
        }
        tri_set_zsp(S, r, osize);
        if (!S->fast_mode) {
            int ea_o = (ins.dst.type == TRI_REG) ? ea1 : tri_mk_const(S, (tu8)osize, a);
            int ec = (ins.src.type == TRI_IMM) ? tri_mk_const(S, 1, cnt) : tri_mk_const(S, 1, cnt);
            tu8 top = (ins.op == TRI_OP_SHL) ? TEX_SHL : (ins.op == TRI_OP_SHR) ? TEX_SHR :
                      (ins.op == TRI_OP_SAR) ? TEX_SAR : (ins.op == TRI_OP_ROL) ? TEX_ROL : TEX_ROR;
            int er = tri_simplify(S, top, (tu8)osize, 0, ea_o, ec);
            if (ins.dst.type == TRI_REG)
                tri_reg_write_sym(S, ins.dst.reg, osize, 0, r, er);
            else
                tri_mem_write(S, tri_eff_addr_compute(S, &ins), osize, r);
        } else {
            if (ins.dst.type == TRI_REG) tri_reg_write(S, ins.dst.reg, osize, r);
            else tri_mem_write(S, tri_eff_addr_compute(S, &ins), osize, r);
        }
        S->cpu.rip += ins.len;
        return 0;
    }

    case TRI_OP_NOT: case TRI_OP_NEG: {
        if (ins.dst.type == TRI_REG) a = tri_reg_read(S, ins.dst.reg, osize);
        else a = tri_mem_read(S, tri_eff_addr_compute(S, &ins), osize);
        if (ins.op == TRI_OP_NOT) {
            r = (~a) & ((osize >= 8) ? ~0ULL : ((1ULL << (osize * 8)) - 1));
            tri_flags_logic(S, r, osize);
        } else {
            r = 0 - a;
            r &= (osize >= 8) ? ~0ULL : ((1ULL << (osize * 8)) - 1);
            tri_flags_sub(S, 0, a, r, osize);
        }
        if (!S->fast_mode) {
            int ea_o = (ins.dst.type == TRI_REG) ? ea1 : tri_mk_const(S, (tu8)osize, a);
            int er = tri_simplify(S, (ins.op == TRI_OP_NOT) ? TEX_NOT : TEX_NEG,
                                  (tu8)osize, 0, ea_o, -1);
            if (ins.dst.type == TRI_REG)
                tri_reg_write_sym(S, ins.dst.reg, osize, 0, r, er);
            else
                tri_mem_write(S, tri_eff_addr_compute(S, &ins), osize, r);
        } else {
            if (ins.dst.type == TRI_REG) tri_reg_write(S, ins.dst.reg, osize, r);
            else tri_mem_write(S, tri_eff_addr_compute(S, &ins), osize, r);
        }
        S->cpu.rip += ins.len;
        return 0;
    }

    case TRI_OP_MUL: case TRI_OP_IMUL2: {
        int bits8 = osize * 8;
        if (ins.dst.type == TRI_REG) a = tri_reg_read(S, ins.dst.reg, osize);
        else a = tri_mem_read(S, tri_eff_addr_compute(S, &ins), osize);
        tu64 full;
        if (osize == 1) {
            tu64 al = S->cpu.r[0] & 0xFF;
            if (ins.op == TRI_OP_MUL) { full = al * (a & 0xFF); S->cpu.r[0] = (S->cpu.r[0] & ~0xFFFFULL) | (full & 0xFFFF); }
            else { ts64 f = (ts64)(ts64)(signed char)al * (ts64)(signed char)(a & 0xFF);
                   full = (tu64)f & 0xFFFF; S->cpu.r[0] = (S->cpu.r[0] & ~0xFFFFULL) | full; }
        } else if (osize == 2) {
            tu64 ax = S->cpu.r[0] & 0xFFFF;
            if (ins.op == TRI_OP_MUL) { full = ax * (a & 0xFFFF); S->cpu.r[0] = (S->cpu.r[0] & ~0xFFFFFFFFULL) | (full & 0xFFFFFFFF); }
            else { ts64 f = (ts64)(short)ax * (ts64)(short)(a & 0xFFFF);
                   full = (tu64)f & 0xFFFFFFFF; S->cpu.r[0] = (S->cpu.r[0] & ~0xFFFFFFFFULL) | full; }
        } else {
            tu64 lo = S->cpu.r[0];
            if (ins.op == TRI_OP_MUL) full = lo * a;
            else full = (tu64)((ts64)lo * (ts64)a);
            if (S->cpu.mode64) {
                S->cpu.r[0] = full & ~0ULL;
                S->cpu.r[2] = full >> 32;
            } else {
                S->cpu.r[0] = full & 0xFFFFFFFFULL;
                S->cpu.r[2] = full >> 32;
            }
        }
        tu64 hi_mask = (osize >= 8) ? ~0ULL : ((1ULL << (osize * 8)) - 1);
        tu64 hi = (full >> bits8) & hi_mask;
        tu64 lo_r = full & hi_mask;
        if (ins.op == TRI_OP_MUL) S->cpu.cf = S->cpu.of = (hi != 0);
        else {
            ts64 sfull = (ts64)full;
            ts64 sext = sfull >> (bits8 - 1);
            S->cpu.cf = S->cpu.of = (hi != ((tu64)sext & hi_mask));
        }
        if (ins.dst.type == TRI_REG) {
            tu64 res = lo_r;
            int er = (S->fast_mode) ? -1 :
                     tri_simplify(S, TEX_MUL, (tu8)osize, 0, ea1,
                                  tri_mk_const(S, (tu8)osize, a));
            tri_reg_write_sym(S, ins.dst.reg, osize, 0, res, er);
        } else {
            S->reg_expr[0] = -1;
            S->reg_expr[2] = -1;
        }
        S->cpu.rip += ins.len;
        return 0;
    }

    case TRI_OP_IMUL3: {
        tu64 m1, m2;
        if (ins.src.type == TRI_REG) m1 = tri_reg_read(S, ins.src.reg, osize);
        else m1 = tri_mem_read(S, tri_eff_addr_compute(S, &ins), osize);
        m2 = ins.third.imm;
        tu64 full = (tu64)((ts64)m1 * (ts64)m2);
        tu64 m = (osize >= 8) ? ~0ULL : ((1ULL << (osize * 8)) - 1);
        tu64 res = full & m;
        tu64 bits8 = (tu64)(osize * 8);
        tu64 hi = (full >> bits8) & m;
        ts64 sfull = (ts64)full;
        ts64 sext = sfull >> (bits8 - 1);
        S->cpu.cf = S->cpu.of = (hi != ((tu64)sext & m));
        int er = (S->fast_mode) ? -1 :
                 tri_simplify(S, TEX_MUL, (tu8)osize, 0,
                              (ea2 >= 0) ? ea2 : tri_mk_const(S, (tu8)osize, m1),
                              tri_mk_const(S, (tu8)osize, m2));
        tri_reg_write_sym(S, ins.dst.reg, osize, 0, res, er);
        S->cpu.rip += ins.len;
        return 0;
    }

    case TRI_OP_DIV: case TRI_OP_IDIV: {
        if (ins.dst.type == TRI_REG) a = tri_reg_read(S, ins.dst.reg, osize);
        else a = tri_mem_read(S, tri_eff_addr_compute(S, &ins), osize);
        if (a == 0) {
            snprintf(S->abort_reason, sizeof(S->abort_reason),
                     "divide by zero at 0x%llX", (unsigned long long)S->cpu.rip);
            return TRI_RUN_DIV;
        }
        if (osize == 4 && S->cpu.mode64) {
            tu64 n = ((tu64)S->cpu.r[2] << 32) | (S->cpu.r[0] & 0xFFFFFFFFULL);
            if (ins.op == TRI_OP_DIV) {
                tu64 q = n / a, rem = n % a;
                if (q > 0xFFFFFFFFULL) {
                    snprintf(S->abort_reason, sizeof(S->abort_reason),
                             "divide overflow at 0x%llX", (unsigned long long)S->cpu.rip);
                    return TRI_RUN_DIV;
                }
                S->cpu.r[0] = (q & 0xFFFFFFFFULL) | (rem << 32);
            } else {
                ts64 sn = (ts64)(((tu64)S->cpu.r[2] << 32) | (S->cpu.r[0] & 0xFFFFFFFFULL));
                ts64 sa = (ts64)a;
                ts64 q = sn / sa, rem = sn % sa;
                if (q > 0x7FFFFFFFLL || q < -0x80000000LL) {
                    snprintf(S->abort_reason, sizeof(S->abort_reason),
                             "divide overflow at 0x%llX", (unsigned long long)S->cpu.rip);
                    return TRI_RUN_DIV;
                }
                S->cpu.r[0] = ((tu64)q & 0xFFFFFFFFULL) | (((tu64)rem & 0xFFFFFFFFULL) << 32);
            }
        } else if (osize == 8 && S->cpu.mode64) {
            snprintf(S->abort_reason, sizeof(S->abort_reason),
                     "128-bit divide not supported at 0x%llX", (unsigned long long)S->cpu.rip);
            return TRI_RUN_DIV;
        } else if (osize == 4) {
            tu64 n = S->cpu.r[0];
            if (ins.op == TRI_OP_DIV) {
                S->cpu.r[0] = (n / a) & 0xFFFFFFFFULL;
                S->cpu.r[2] = (n % a) & 0xFFFFFFFFULL;
            } else {
                ts64 q = (ts64)n / (ts64)a, rem = (ts64)n % (ts64)a;
                S->cpu.r[0] = (tu64)q & 0xFFFFFFFFULL;
                S->cpu.r[2] = (tu64)rem & 0xFFFFFFFFULL;
            }
        }
        S->cpu.rip += ins.len;
        return 0;
    }

    case TRI_OP_BT:
    case TRI_OP_BTS:
    case TRI_OP_BTR:
    case TRI_OP_BTC:
    case TRI_OP_BSF:
    case TRI_OP_BSR: {
        int width = S->cpu.mode64 ? (ins.osize == 8 ? 64 : (ins.osize == 2 ? 16 : (ins.osize == 1 ? 8 : 32)))
                                  : (ins.osize == 2 ? 16 : (ins.osize == 1 ? 8 : 32));
        int is_reg_dst = (ins.dst.type == TRI_REG);
        tu64 addr = 0;
        if (!is_reg_dst) {
            addr = tri_eff_addr_compute(S, &ins);
            if (ins.dst.size == 0) ins.dst.size = (ins.osize == 8) ? 8 : 4;
        }
        int dbsz = (is_reg_dst && ins.osize == 8) ? 8 : ((ins.dst.size == 8) ? 8 : (ins.dst.size ? ins.dst.size : 4));
        tu64 v = is_reg_dst ? tri_reg_read(S, ins.dst.reg, dbsz) : tri_mem_read(S, addr, dbsz);
        tu64 sv = (ins.src.type == TRI_REG) ? tri_reg_read(S, ins.src.reg, 8) : ins.src.imm;
        tu64 idx = sv & (tu64)(width - 1);
        tu64 mask = 1ULL << idx;
        S->cpu.cf = (tu8)((v >> idx) & 1);
        switch (ins.op) {
        case TRI_OP_BTS: v |= mask; break;
        case TRI_OP_BTR: v &= ~mask; break;
        case TRI_OP_BTC: v ^= mask; break;
        default: break;
        }
        if (ins.op == TRI_OP_BSF || ins.op == TRI_OP_BSR) {
            int dbsz2 = (ins.osize == 8) ? 8 : (ins.osize ? ins.osize : 4);
            if (v == 0) {
                S->cpu.zf = 1;
            } else {
                S->cpu.zf = 0;
                tu64 r = 0;
                if (ins.op == TRI_OP_BSF) { r = 0; while (((v >> r) & 1) == 0) r++; }
                else { r = (tu64)(width - 1); while (((v >> r) & 1) == 0) r--; }
                if (ins.dst.type == TRI_REG) tri_reg_write(S, ins.dst.reg, dbsz2, r);
                else tri_mem_write(S, addr, dbsz2, r);
            }
        } else if (ins.op != TRI_OP_BT) {
            if (is_reg_dst) tri_reg_write(S, ins.dst.reg, dbsz, v);
            else tri_mem_write(S, addr, dbsz, v);
        }
        S->cpu.rip += ins.len;
        return 0;
    }

    case TRI_OP_XCHG: {
        tu64 va, vb;
        if (ins.dst.type == TRI_REG) va = tri_reg_read(S, ins.dst.reg, osize);
        else va = tri_mem_read(S, tri_eff_addr_compute(S, &ins), osize);
        if (ins.src.type == TRI_REG) vb = tri_reg_read(S, ins.src.reg, osize);
        else vb = tri_mem_read(S, tri_eff_addr_compute(S, &ins), osize);
        if (ins.dst.type == TRI_REG) tri_reg_write_sym(S, ins.dst.reg, osize, 0, vb, ea2);
        else tri_mem_write(S, tri_eff_addr_compute(S, &ins), osize, vb);
        if (ins.src.type == TRI_REG) tri_reg_write_sym(S, ins.src.reg, osize, 0, va, ea1);
        else tri_mem_write(S, tri_eff_addr_compute(S, &ins), osize, va);
        S->cpu.rip += ins.len;
        return 0;
    }

    case TRI_OP_BSWAP: {
        tu64 v = tri_reg_read(S, ins.dst.reg, osize);
        tu64 r2 = 0;
        for (int i = 0; i < osize; i++)
            r2 |= ((v >> (i * 8)) & 0xFF) << ((osize - 1 - i) * 8);
        tri_reg_write_sym(S, ins.dst.reg, osize, 0, r2, -1);
        S->cpu.rip += ins.len;
        return 0;
    }

    case TRI_OP_CDQ: {
        if (osize == 4) {
            tu64 eax = S->cpu.r[0] & 0xFFFFFFFFULL;
            tu64 sign = (eax >> 31) & 1;
            if (S->cpu.mode64) S->cpu.r[2] = (sign) ? 0xFFFFFFFFFFFFFFFFULL : 0;
            else S->cpu.r[2] = (sign) ? 0xFFFFFFFFULL : 0;
        } else {
            S->cpu.r[2] = (S->cpu.r[0] >> 32);
        }
        S->cpu.rip += ins.len;
        return 0;
    }

    case TRI_OP_CWDE: {
        if (S->cpu.mode64 && osize == 8) {
            tu64 eax = S->cpu.r[0] & 0xFFFFFFFFULL;
            S->cpu.r[0] = (eax & 0x80000000ULL) ? (eax | 0xFFFFFFFF00000000ULL) : eax;
        } else if (osize == 4) {
            tu64 ax = S->cpu.r[0] & 0xFFFFULL;
            S->cpu.r[0] = (ax & 0x8000ULL) ? ((ax | 0xFFFF0000ULL) & 0xFFFFFFFFULL) : ax;
        }
        S->cpu.rip += ins.len;
        return 0;
    }

    case TRI_OP_LEAVE: {
        S->cpu.r[4] = S->cpu.r[5];
        int sp_sz = S->cpu.mode64 ? 8 : 4;
        tu64 v = tri_mem_read(S, S->cpu.r[4], sp_sz);
        S->cpu.r[4] += (tu64)sp_sz;
        S->cpu.r[5] = v;
        S->cpu.rip += ins.len;
        return 0;
    }

    case TRI_OP_RDTSC: {
        S->rdtsc_fake += 0x1000;
        S->cpu.r[0] = S->rdtsc_fake;
        S->cpu.r[2] = 0;
        S->cpu.rip += ins.len;
        return 0;
    }

    default:
        snprintf(S->abort_reason, sizeof(S->abort_reason),
                 "unsupported op %u at 0x%llX", ins.op, (unsigned long long)S->cpu.rip);
        return TRI_RUN_DECODE;
    }
}

static tu64 tri_eff_addr_compute(TriState *S, TriInsn *ins)
{
    TriOperand *o = (ins->dst.type == TRI_MEM) ? &ins->dst :
                    (ins->src.type == TRI_MEM) ? &ins->src : &ins->dst;
    if (o->type != TRI_MEM) return 0;
    if (o->riprel) {
        return ins->ip + ins->len + (tu64)(ts64)(int)o->disp;
    }
    tu64 ea = (o->base != 0xFF) ? S->cpu.r[o->base & 15] : 0;
    if (o->index != 0xFF) ea += S->cpu.r[o->index & 15] * o->scale;
    ea += (tu64)(ts64)(int)o->disp;
    if ((o->seg == 0x65 || o->seg == 0x64) && o->base == 0xFF && o->index == 0xFF)
        ea = TRI_TEB_ADDR + (tu64)(ts64)(int)o->disp;
    else if (o->seg == 0x65 || o->seg == 0x64)
        ea = TRI_TEB_ADDR + ea;
    return ea;
}

static void tri_cpu_reset(TriState *S, int mode64)
{
    memset(&S->cpu, 0, sizeof(S->cpu));
    S->cpu.mode64 = mode64;
    for (int i = 0; i < 16; i++) S->reg_expr[i] = -1;
    S->last_flags_reg = -1;
    S->fast_mode = 0;
    S->fast_lo = 0;
    S->fast_hi = 0;
}

static void tri_populate_teb_peb(TriState *S)
{
    int mode64 = S->cpu.mode64;
    tu64 peb_ptr_slot = mode64 ? (TRI_TEB_ADDR + 0x30) : (TRI_TEB_ADDR + 0x18);
    int ps = mode64 ? 8 : 4;
    tri_mem_write(S, peb_ptr_slot, ps, TRI_PEB_ADDR);
    tri_mem_write(S, TRI_PEB_ADDR + 0x02, 1, 0);
    tri_mem_write(S, TRI_PEB_ADDR + 0x68, 4, 0);
    tri_mem_write(S, TRI_TEB_ADDR + 0x58, ps, TRI_STACK_TOP);
}

static int tri_rd16(FILE *f, tu16 *v) { return fread(v, 2, 1, f) == 1; }

static int tri_rd32(FILE *f, tu32 *v) { return fread(v, 4, 1, f) == 1; }

static int tri_load_dump_image(TriState *S)
{
    TriContext *ctx = S->ctx;
    FILE *f = fopen(ctx->dump_path, "rb");
    if (!f) {
        printf("[-] TRITON: cannot open dump %s\n", ctx->dump_path);
        return 0;
    }

    tu8 hdr[4096];
    if (fread(hdr, 1, sizeof(hdr), f) != sizeof(hdr)) { fclose(f); return 0; }
    if (hdr[0] != 'M' || hdr[1] != 'Z') { fclose(f); return 0; }
    tu32 pe_off = 0;
    for (int i = 0; i < 4; i++) pe_off |= (tu32)hdr[0x3C + i] << (i * 8);
    if (pe_off + 256 > sizeof(hdr) || hdr[pe_off] != 'P' || hdr[pe_off + 1] != 'E') {
        fclose(f);
        return 0;
    }
    tu8 *pe = hdr + pe_off;
    tu16 machine = (tu16)(pe[4] | (pe[5] << 8));
    tu16 opt_magic = (tu16)(pe[24] | (pe[25] << 8));
    int is64 = (opt_magic == 0x20B);
    ctx->machine = machine;

    tu64 img_base = 0;
    if (is64) {
        for (int i = 0; i < 8; i++) img_base |= (tu64)pe[24 + 24 + i] << (i * 8);
    } else {
        img_base = 0;
        for (int i = 0; i < 4; i++) img_base |= (tu64)pe[24 + 28 + i] << (i * 8);
    }
    tu32 size_of_image = 0;
    {
        int so = is64 ? (24 + 56) : (24 + 56);
        for (int i = 0; i < 4; i++) size_of_image |= (tu32)pe[so + i] << (i * 8);
    }
    tu32 ep_rva = 0;
    for (int i = 0; i < 4; i++) ep_rva |= (tu32)pe[24 + 16 + i] << (i * 8);
    tu32 sect_count = (tu32)pe[6] | ((tu32)pe[7] << 8);
    tu32 size_headers = 0;
    {
        int so = is64 ? (24 + 60) : (24 + 60);
        for (int i = 0; i < 4; i++) size_headers |= (tu32)pe[so + i] << (i * 8);
    }
    tu32 file_align = 0;
    {
        int so = is64 ? (24 + 36) : (24 + 36);
        for (int i = 0; i < 4; i++) file_align |= (tu32)pe[so + i] << (i * 8);
    }

    ctx->image_base = img_base;
    ctx->image_size = size_of_image ? size_of_image : 0x400000;

    if (size_headers > 0x100000) size_headers = 0x100000;
    {
        fseek(f, 0, SEEK_SET);
        tu8 *hb = (tu8 *)malloc(size_headers ? size_headers : 0x400);
        if (hb) {
            size_t n = fread(hb, 1, size_headers ? size_headers : 0x400, f);
            tri_mem_load_block(S, img_base, hb, (tu64)n);
            free(hb);
        }
    }

    long sect_off = (long)(pe_off + 24 + (is64 ? 240 : 224));
    int self_mapped = (file_align && file_align == 0x1000);

    for (tu32 s = 0; s < sect_count; s++) {
        tu8 sh[40];
        memset(sh, 0, sizeof(sh));
        if (fseek(f, sect_off + (long)s * 40, SEEK_SET) != 0) break;
        if (fread(sh, 1, 40, f) != 40) break;
        tu32 vsize = 0, vaddr = 0, rawsize = 0, rawoff = 0;
        for (int i = 0; i < 4; i++) vsize  |= (tu32)sh[8 + i]  << (i * 8);
        for (int i = 0; i < 4; i++) vaddr  |= (tu32)sh[12 + i] << (i * 8);
        for (int i = 0; i < 4; i++) rawsize |= (tu32)sh[16 + i] << (i * 8);
        for (int i = 0; i < 4; i++) rawoff  |= (tu32)sh[20 + i] << (i * 8);
        if (self_mapped) rawoff = vaddr;
        if (!vsize || !rawsize) continue;
        tu64 load_len = (vsize < rawsize) ? (tu64)vsize : (tu64)rawsize;
        if (load_len > 0x20000000ULL) continue;
        if (fseek(f, (long)rawoff, SEEK_SET) != 0) continue;

        tu8 *buf = (tu8 *)malloc(0x10000);
        if (!buf) break;
        tu64 done = 0;
        while (done < load_len) {
            tu64 want = load_len - done;
            if (want > 0x10000) want = 0x10000;
            size_t n = fread(buf, 1, (size_t)want, f);
            if (!n) break;
            tri_mem_load_block(S, img_base + vaddr + done, buf, (tu64)n);
            done += (tu64)n;
        }
        free(buf);
    }

    fclose(f);
    printf("[*] TRITON: dump loaded (machine=%s, base=0x%llX, size=0x%X, ep_orig=0x%llX)\n",
           (machine == 0x8664) ? "x64" : (machine == 0x14C) ? "x86" : "??",
           (unsigned long long)img_base, (unsigned)size_of_image,
           (unsigned long long)ctx->ep_rva);
    return 1;
}

static void tri_find_api_hooks(TriState *S)
{
    TriContext *ctx = S->ctx;
    S->gpa_addr = 0;
    S->lla_addr = 0;
    S->llw_addr = 0;
    for (int i = 0; i < ctx->catalog_count; i++) {
        const char *fn = ctx->catalog[i].function;
        if (!S->gpa_addr && _stricmp_null_safe(fn, "GetProcAddress") == 0)
            S->gpa_addr = ctx->catalog[i].addr;
        else if (!S->lla_addr && _stricmp_null_safe(fn, "LoadLibraryA") == 0)
            S->lla_addr = ctx->catalog[i].addr;
        else if (!S->llw_addr && _stricmp_null_safe(fn, "LoadLibraryW") == 0)
            S->llw_addr = ctx->catalog[i].addr;
    }
}

static const char *tri_stop_name(int stop)
{
    switch (stop) {
    case TRI_RUN_RESOLVED: return "resolved (transfer to catalog address)";
    case TRI_RUN_RET: return "returned to sentinel (RAX checked)";
    case TRI_RUN_CAP: return "budget cap";
    case TRI_RUN_DECODE: return "decode abort";
    case TRI_RUN_DIV: return "divide fault";
    default: return "unknown";
    }
}

static int tri_run_stub(TriState *S, tu64 entry, tu64 *out_addr,
                        char *out_name, int ncap, int *out_stop)
{
    S->instr_count = 0;
    S->instr_cap = TRI_STUB_INSTR_CAP;
    S->ep_mode = 0;
    S->loop_count = 0;
    S->indirect_count = 0;
    S->expr_count = 0;
    memset(S->hc_table, -1, sizeof(S->hc_table));
    tri_cpu_reset(S, (S->ctx->machine == 0x8664));
    tri_populate_teb_peb(S);

    int sp_sz = S->cpu.mode64 ? 8 : 4;
    S->cpu.r[4] = TRI_STACK_TOP - (tu64)sp_sz;
    tri_mem_write(S, S->cpu.r[4], sp_sz, TRI_RET_MAGIC);

    S->cpu.rip = entry;
    if (S->trace && S->trace_lines < TRI_TRACE_CAP) {
        fprintf(S->trace, "\n===== STUB ENTRY 0x%llX =====\n",
                (unsigned long long)entry);
        S->trace_lines++;
    }

    int stop = 0;
    for (;;) {
        stop = tri_exec_step(S);
        if (stop) break;
        if (S->instr_count == 4096 && S->indirect_count == 0 && S->loop_count == 0) {
            snprintf(S->abort_reason, sizeof(S->abort_reason),
                     "stub points to data/encrypted code: 4096 instr, no control flow, no loop");
            stop = TRI_RUN_DECODE;
            break;
        }
    }
    *out_stop = stop;
    *out_addr = 0;
    out_name[0] = 0;

    tu64 cand = (stop == TRI_RUN_RESOLVED) ? S->cpu.rip :
                (stop == TRI_RUN_RET) ? S->cpu.r[0] : 0;
    if (cand && cand != TRI_RET_MAGIC) {
        int ci = tri_cat_by_addr(S, cand);
        if (ci >= 0) {
            *out_addr = cand;
            snprintf(out_name, ncap, "%s!%s",
                     S->ctx->catalog[ci].module, S->ctx->catalog[ci].function);
        } else {
            *out_addr = cand;
            snprintf(out_name, ncap, "unknown_addr_0x%llX", (unsigned long long)cand);
        }
    }

    if (S->trace && S->trace_lines < TRI_TRACE_CAP) {
        fprintf(S->trace, "===== STUB 0x%llX STOP: %s after %llu instr | rax=%016llX rip=%016llX%s%s =====\n",
                (unsigned long long)entry, tri_stop_name(stop),
                (unsigned long long)S->instr_count,
                (unsigned long long)S->cpu.r[0], (unsigned long long)S->cpu.rip,
                S->abort_reason[0] ? " | " : "",
                S->abort_reason);
        S->trace_lines++;
    }
    return stop;
}

static void tri_emit_handlers(TriState *S, tu64 stub_entry)
{
    if (!S->handlers_file) return;
    if (S->indirect_count < 6) return;
    fprintf(S->handlers_file, "\n=== VM dispatcher suspected: stub 0x%llX, %d indirect targets ===\n",
            (unsigned long long)stub_entry, S->indirect_count);
    for (int i = 0; i < S->indirect_count && i < 64; i++) {
        tu64 t = S->indirect_targets[i];
        fprintf(S->handlers_file, "--- handler 0x%llX ---\n", (unsigned long long)t);
        for (int k = 0; k < 24; k++) {
            TriInsn ins;
            tri_decode(S, t, &ins);
            if (ins.op == TRI_OP_ABORT) break;
            char line[256];
            snprintf(line, sizeof(line), "%s", tri_mnemonic(&ins));
            fprintf(S->handlers_file, "  0x%016llX: %s\n", (unsigned long long)t, line);
            t += ins.len;
            if (ins.op == TRI_OP_JMP || ins.op == TRI_OP_RET) break;
        }
    }
    S->handlers_emitted++;
}

static void tri_json_escape(FILE *f, const char *s)
{
    for (; *s; s++) {
        char c = *s;
        if (c == '"' || c == '\\') fputc('\\', f), fputc(c, f);
        else if ((tu8)c < 0x20) fprintf(f, "\\u%04X", c);
        else fputc(c, f);
    }
}

int tri_engine_run(TriContext *ctx)
{
    printf("\n[*] TRITON engine: post-dump symbolic trace & stub emulation\n");
    printf("[*] TRITON: dump=%s\n", ctx->dump_path);

    TriState *S = (TriState *)tri_xcalloc(1, sizeof(TriState));
    S->ctx = ctx;
    S->exprs = (TriExpr *)tri_xcalloc(TRI_MAX_EXPRS, sizeof(TriExpr));
    memset(S->hc_table, -1, sizeof(S->hc_table));
    S->rdtsc_fake = 0x10000;
    S->total_instr_count = 0;
    S->collatz_bypasses = 0;
    S->loop_bombs = 0;

    if (!tri_load_dump_image(S)) {
        printf("[-] TRITON: dump image load failed, engine skipped\n");
        free(S->exprs);
        free(S);
        return -1;
    }

    tri_cpu_reset(S, (ctx->machine == 0x8664));
    tri_populate_teb_peb(S);
    tri_find_api_hooks(S);
    printf("[*] TRITON: catalog=%d exports | GPA=0x%llX LLA=0x%llX LLW=0x%llX\n",
           ctx->catalog_count,
           (unsigned long long)S->gpa_addr,
           (unsigned long long)S->lla_addr,
           (unsigned long long)S->llw_addr);

    char trace_path[TRI_MAX_PATH], handlers_path[TRI_MAX_PATH], json_path[TRI_MAX_PATH];
    snprintf(trace_path, sizeof(trace_path), TRI_PATH_FMT "triton_trace.txt", ctx->output_dir);
    snprintf(handlers_path, sizeof(handlers_path), TRI_PATH_FMT "triton_handlers.txt", ctx->output_dir);
    snprintf(json_path, sizeof(json_path), TRI_PATH_FMT "triton_iat.json", ctx->output_dir);

    S->trace = NULL;
    S->handlers_file = NULL;
    if (ctx->trace_enabled) {
        S->trace = fopen(trace_path, "w");
        if (S->trace) {
            fprintf(S->trace, "TRITON automatic trace (capped at %d lines)\n", TRI_TRACE_CAP);
            fprintf(S->trace, "target=%s image_base=0x%llX\n",
                    ctx->target_name, (unsigned long long)ctx->image_base);
        }
    }

    int resolved = 0, already_real = 0, unresolved = 0;
    static TriSlotFix fixes[TRI_MAX_SLOT_FIXES];
    int fix_count = 0;

    FILE *jf = fopen(json_path, "w");
    if (jf) {
        fprintf(jf, "{\n  \"target\": \"");
        tri_json_escape(jf, ctx->target_name);
        fprintf(jf, "\",\n  \"image_base\": \"0x%llX\",\n", (unsigned long long)ctx->image_base);
        fprintf(jf, "  \"machine\": \"%s\",\n", (ctx->machine == 0x8664) ? "x64" : "x86");
        fprintf(jf, "  \"stubs\": [\n");
    }

    for (int i = 0; i < ctx->slot_count; i++) {
        tu32 slot_rva = ctx->slot_rvas[i];
        tu64 slot_addr = ctx->image_base + (tu64)slot_rva;
        tu64 val = tri_mem_read(S, slot_addr, (ctx->machine == 0x8664) ? 8 : 4);

        tu64 val_raw = val;
        if (val != 0 && val < (tu64)ctx->image_size)
            val += ctx->image_base;

        tu64 in_img = (val >= ctx->image_base &&
                       val < ctx->image_base + (tu64)ctx->image_size);

        char name[256];
        int stop = 0;
        tu64 resolved_addr = 0;
        const char *status = "unresolved";
        tu64 ninstr = 0;

        if (val == 0) {
            status = "null";
            name[0] = 0;
        } else if (!in_img) {
            int ci = tri_cat_by_addr(S, val);
            if (ci >= 0) {
                snprintf(name, sizeof(name), "%s!%s",
                         ctx->catalog[ci].module, ctx->catalog[ci].function);
                status = "already_real";
            } else {
                snprintf(name, sizeof(name), "unknown_addr_0x%llX", (unsigned long long)val);
                status = "already_real_unnamed";
            }
            already_real++;
        } else {
            ninstr = S->instr_count;
            char hint_name[64];
            int has_hint = 0;
            if (tri_read_import_name(S, val, hint_name, sizeof(hint_name))) {
                tu64 name_addr = tri_cat_find(S, NULL, hint_name);
                if (!name_addr) {
                    strncpy(name, hint_name, sizeof(name) - 1);
                    name[sizeof(name) - 1] = 0;
                    status = "lazy_name_no_export";
                    unresolved++;
                    has_hint = 1;
                    ninstr = 0;
                    stop = 0;
                    resolved_addr = 0;
                    printf("    [triton] lazy import name '%s' read from RVA-form slot, but no loaded\n"
                           "             module exports it on this host (wine limitation?) - left unresolved\n",
                           hint_name);
                }
                if (name_addr) {
                    for (int c2 = 0; c2 < ctx->catalog_count; c2++) {
                        if (_stricmp_null_safe(ctx->catalog[c2].function, hint_name) == 0) {
                            snprintf(name, sizeof(name), "%s!%s",
                                     ctx->catalog[c2].module, ctx->catalog[c2].function);
                            break;
                        }
                    }
                    status = "resolved_lazy_name";
                    resolved++;
                    resolved_addr = name_addr;
                    has_hint = 1;
                    ninstr = 0;
                    stop = 0;
                    if (fix_count < TRI_MAX_SLOT_FIXES) {
                        fixes[fix_count].slot_rva = slot_rva;
                        fixes[fix_count].resolved_addr = name_addr;
                        strncpy(fixes[fix_count].name, name, sizeof(fixes[fix_count].name) - 1);
                        fixes[fix_count].name[sizeof(fixes[fix_count].name) - 1] = 0;
                        fixes[fix_count].how = 1;
                        fix_count++;
                    }
                }
            }
            if (!has_hint) {
            tri_run_stub(S, val, &resolved_addr, name, sizeof(name), &stop);
            ninstr = S->instr_count - ninstr;
            int ci = -1;
            if (resolved_addr) {
                ci = tri_cat_by_addr(S, resolved_addr);
                if (ci >= 0) {
                    snprintf(name, sizeof(name), "%s!%s",
                             ctx->catalog[ci].module, ctx->catalog[ci].function);
                    status = "resolved_stub_emu";
                    resolved++;
                    if (fix_count < TRI_MAX_SLOT_FIXES) {
                        fixes[fix_count].slot_rva = slot_rva;
                        fixes[fix_count].resolved_addr = resolved_addr;
                        strncpy(fixes[fix_count].name, name, sizeof(fixes[fix_count].name) - 1);
                        fixes[fix_count].name[sizeof(fixes[fix_count].name) - 1] = 0;
                        fixes[fix_count].how = 2;
                        fix_count++;
                    }
                } else {
                    status = "returned_unknown_addr";
                    unresolved++;
                }
            } else {
                name[0] = 0;
                status = (stop == TRI_RUN_CAP) ? "unresolved_cap" :
                         (stop == TRI_RUN_DECODE) ? "unresolved_decode" :
                         (stop == TRI_RUN_DIV) ? "unresolved_div" : "unresolved";
                unresolved++;
            }
            if (S->indirect_count >= 6)
                tri_emit_handlers(S, val);
            }
        }

        printf("%s TRITON: slot RVA 0x%08lX val=0x%llX%s -> %s%s%s (%llu instr, %s)\n",
               (resolved_addr || status[0] == 'a') ? "[+]" : "[!]",
               (unsigned long)slot_rva, (unsigned long long)val,
               (val_raw != val) ? " (rva-form)" : "",
               name[0] ? name : "(no name)",
               (stop && status[0] == 'u' && S->abort_reason[0]) ? " | " : "",
               (stop && status[0] == 'u' && S->abort_reason[0]) ? S->abort_reason : "",
               (unsigned long long)ninstr, tri_stop_name(stop));

        if (jf) {
            fprintf(jf, "    {\"slot_rva\": \"0x%08lX\", \"value\": \"0x%llX\", \"status\": \"%s\", ",
                    (unsigned long)slot_rva, (unsigned long long)val, status);
            if (name[0]) {
                fprintf(jf, "\"name\": \"");
                tri_json_escape(jf, name);
                fprintf(jf, "\", ");
            }
            if (resolved_addr) fprintf(jf, "\"addr\": \"0x%llX\", ", (unsigned long long)resolved_addr);
            fprintf(jf, "\"instructions\": %llu, \"stop\": \"%s\"}%s\n",
                    (unsigned long long)ninstr, tri_stop_name(stop),
                    (i < ctx->slot_count - 1) ? "," : "");
        }
    }

    if (ctx->ep_rva) {
        tu64 ep = ctx->image_base + ctx->ep_rva;
        printf("[*] TRITON: VM entry trace from original EP 0x%llX (capped %llu instr)...\n",
               (unsigned long long)ep, (unsigned long long)TRI_EP_INSTR_CAP);
        S->fast_mode = 0;
        S->instr_cap = TRI_EP_INSTR_CAP;
        S->ep_mode = 1;
        tri_cpu_reset(S, (ctx->machine == 0x8664));
        tri_populate_teb_peb(S);
        int sp_sz = S->cpu.mode64 ? 8 : 4;
        S->cpu.r[4] = TRI_STACK_TOP - (tu64)sp_sz;
        tri_mem_write(S, S->cpu.r[4], sp_sz, TRI_RET_MAGIC);
        S->cpu.rip = ep;
        if (S->trace && S->trace_lines < TRI_TRACE_CAP) {
            fprintf(S->trace, "\n===== VM ENTRY TRACE 0x%llX =====\n", (unsigned long long)ep);
            S->trace_lines++;
        }
        int stop = 0;
        for (;;) {
            stop = tri_exec_step(S);
            if (stop) break;
        }
        printf("[*] TRITON: VM entry trace: %llu instr, %d indirect targets, stop=%s%s%s\n",
               (unsigned long long)S->instr_count, S->indirect_count,
               tri_stop_name(stop),
               S->abort_reason[0] ? " | " : "", S->abort_reason);
        if (S->indirect_count >= 6) {
            if (!S->handlers_file) S->handlers_file = fopen(handlers_path, "w");
            if (S->handlers_file)
                fprintf(S->handlers_file, "TRITON handler extraction: VM entry 0x%llX\n",
                        (unsigned long long)ep);
            tri_emit_handlers(S, ep);
            printf("[+] TRITON: VM dispatcher suspected: %d handler targets -> %s\n",
                   S->indirect_count, handlers_path);
        }
    }

    if (jf) {
        fprintf(jf, "  ],\n  \"summary\": {\n");
        fprintf(jf, "    \"resolved\": %d,\n", resolved);
        fprintf(jf, "    \"already_real\": %d,\n", already_real);
        fprintf(jf, "    \"unresolved\": %d,\n", unresolved);
        fprintf(jf, "    \"collatz_bypasses\": %d,\n", S->collatz_bypasses);
        fprintf(jf, "    \"loop_bombs\": %d,\n", S->loop_bombs);
        fprintf(jf, "    \"total_instructions\": %llu,\n", (unsigned long long)S->total_instr_count);
        fprintf(jf, "    \"trace_lines\": %llu\n", (unsigned long long)S->trace_lines);
        fprintf(jf, "  }\n}\n");
        fclose(jf);
        printf("[+] TRITON: JSON report -> %s\n", json_path);
    }

    if (S->handlers_file) fclose(S->handlers_file);
    if (S->trace) fclose(S->trace);

    ctx->fixes = fixes;
    ctx->fix_count = fix_count;
    printf("[*] TRITON: summary: resolved=%d already_real=%d unresolved=%d | collatz_bypasses=%d loop_bombs=%d | total_instr=%llu\n",
           resolved, already_real, unresolved,
           S->collatz_bypasses, S->loop_bombs,
           (unsigned long long)S->total_instr_count);

    free(S->exprs);
    free(S);
    return resolved;
}

void triton_run(const char *target_name)
{
    if (g_no_triton) {
        printf("[*] TRITON disabled (--no-triton)\n");
        return;
    }

    const char *bn = get_basename(target_name);
    char dump_path[MAX_PATH];
    snprintf(dump_path, sizeof(dump_path), "%s\\%s_dumped.bin", g_output_dir, bn);

    DWORD attr = GetFileAttributesA(dump_path);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        printf("[-] TRITON: dump file not found, engine skipped\n");
        return;
    }

    static TriCatalogEntry tri_catalog[MAX_IMPORTS];
    int cat_count = 0;
    LONG ic = g_import_count;
    if (ic > MAX_IMPORTS) ic = MAX_IMPORTS;
    for (LONG i = 0; i < ic; i++) {
        if (!g_imports[i].resolved_addr) continue;
        strncpy(tri_catalog[cat_count].module, g_imports[i].module, 63);
        tri_catalog[cat_count].module[63] = 0;
        strncpy(tri_catalog[cat_count].function, g_imports[i].function, 191);
        tri_catalog[cat_count].function[191] = 0;
        tri_catalog[cat_count].addr = g_imports[i].resolved_addr;
        cat_count++;
    }

    static tu32 tri_slots[MAX_IAT_SLOTS];
    int slot_count = 0;
    for (int i = 0; i < g_iat_slot_count && slot_count < MAX_IAT_SLOTS; i++)
        tri_slots[slot_count++] = g_iat_slots[i].slot_rva;

    int added_stubs = 0;
    for (int i = 0; i < g_resolved_iat_count && slot_count < MAX_IAT_SLOTS; i++) {
        if (g_resolved_iat[i].import_idx >= 0) continue;
        tu64 thunk = g_resolved_iat[i].thunk_addr;
        int in_slot = ((thunk >= g_image_base && thunk < g_image_base + (tu64)g_size_of_image) ||
                       (thunk != 0 && thunk < (tu64)g_size_of_image));
        int in_dump_val = 0;
        {
            FILE *df = fopen(dump_path, "rb");
            if (df) {
                BYTE sv[8];
                if (g_machine == 0x8664) {
                    if (!fseek(df, (long)g_resolved_iat[i].iat_rva, SEEK_SET) &&
                        fread(sv, 1, 8, df) == 8) {
                        tu64 v = 0;
                        for (int k = 7; k >= 0; k--) v = (v << 8) | sv[k];
                        if ((v >= g_image_base && v < g_image_base + (tu64)g_size_of_image) ||
                            (v != 0 && v < (tu64)g_size_of_image))
                            in_dump_val = 1;
                    }
                } else {
                    if (!fseek(df, (long)g_resolved_iat[i].iat_rva, SEEK_SET) &&
                        fread(sv, 1, 4, df) == 4) {
                        tu64 v = 0;
                        for (int k = 3; k >= 0; k--) v = (v << 8) | sv[k];
                        if ((v >= g_image_base && v < g_image_base + (tu64)g_size_of_image) ||
                            (v != 0 && v < (tu64)g_size_of_image))
                            in_dump_val = 1;
                    }
                }
                fclose(df);
            }
        }
        int dup = 0;
        for (int k = 0; k < slot_count; k++)
            if (tri_slots[k] == g_resolved_iat[i].iat_rva) { dup = 1; break; }
        if (dup) continue;
        if (in_dump_val || in_slot) {
            tri_slots[slot_count++] = g_resolved_iat[i].iat_rva;
            added_stubs++;
            printf("[*] TRITON: VM stub slot RVA 0x%08lX queued for emulation (unresolved live-phase)\n",
                   (unsigned long)g_resolved_iat[i].iat_rva);
        } else {
            printf("[*] TRITON: slot RVA 0x%08lX skipped (thunk=0x%llX not resolvable in-image)\n",
                   (unsigned long)g_resolved_iat[i].iat_rva, (unsigned long long)thunk);
        }
    }
    if (added_stubs)
        printf("[*] TRITON: %d VM stub slot(s) added to emulation queue\n", added_stubs);

    tu64 orig_ep = 0;
    {
        FILE *tf = fopen(target_name, "rb");
        if (tf) {
            BYTE th[4096];
            if (fread(th, 1, sizeof(th), tf) == sizeof(th)) {
                DWORD pe_off = *(DWORD *)(th + 0x3C);
                if (pe_off + 256 < sizeof(th) && th[pe_off] == 'P' && th[pe_off + 1] == 'E') {
                    orig_ep = *(DWORD *)(th + pe_off + 24 + 16);
                }
            }
            fclose(tf);
        }
    }

    static TriContext tctx;
    memset(&tctx, 0, sizeof(tctx));
    tctx.image_base = g_image_base;
    tctx.image_size = g_size_of_image;
    tctx.machine = g_machine;
    tctx.ep_rva = orig_ep;
    strncpy(tctx.dump_path, dump_path, TRI_MAX_PATH - 1);
    strncpy(tctx.output_dir, g_output_dir, TRI_MAX_PATH - 1);
    strncpy(tctx.target_name, bn, sizeof(tctx.target_name) - 1);
    tctx.catalog = tri_catalog;
    tctx.catalog_count = cat_count;
    tctx.slot_rvas = tri_slots;
    tctx.slot_count = slot_count;
    tctx.trace_enabled = 1;

    int n = tri_engine_run(&tctx);
    if (n >= 0) {
        g_triton_resolved = n;
        if (tctx.fix_count > 0) {
            FILE *pf = fopen(dump_path, "r+b");
            if (pf) {
                int applied = 0;
                for (int i = 0; i < tctx.fix_count; i++) {
                    BYTE pb[8];
                    tu64 a = tctx.fixes[i].resolved_addr;
                    int w = (g_machine == 0x8664) ? 8 : 4;
                    for (int k = 0; k < w; k++) pb[k] = (BYTE)((a >> (8 * k)) & 0xFF);
                    if (!fseek(pf, (long)tctx.fixes[i].slot_rva, SEEK_SET) &&
                        fwrite(pb, 1, w, pf) == (size_t)w) {
                        applied++;
                        printf("[+] TRITON: patched dump IAT slot RVA 0x%08lX -> %s\n",
                               (unsigned long)tctx.fixes[i].slot_rva,
                               tctx.fixes[i].name[0] ? tctx.fixes[i].name : "resolved");
                        for (int r = 0; r < g_resolved_iat_count; r++) {
                            if (g_resolved_iat[r].iat_rva == tctx.fixes[i].slot_rva) {
                                const char *bang = strchr(tctx.fixes[i].name, '!');
                                if (bang && bang > tctx.fixes[i].name) {
                                    size_t ml = (size_t)(bang - tctx.fixes[i].name);
                                    if (ml >= sizeof(g_resolved_iat[r].module)) ml = sizeof(g_resolved_iat[r].module) - 1;
                                    memcpy(g_resolved_iat[r].module, tctx.fixes[i].name, ml);
                                    g_resolved_iat[r].module[ml] = '\0';
                                    strncpy(g_resolved_iat[r].function, bang + 1, sizeof(g_resolved_iat[r].function) - 1);
                                    g_resolved_iat[r].function[sizeof(g_resolved_iat[r].function) - 1] = '\0';
                                }
                                break;
                            }
                        }
                    }
                }
                fclose(pf);
                printf("[*] TRITON: %d/%d lazy-import fixes applied to dump\n",
                       applied, tctx.fix_count);
                rewrite_resolved_imports_report();
            } else {
                printf("[!] TRITON: cannot reopen dump for IAT fixes (write)\n");
            }
        }
        FILE *jf = NULL;
        char jp[MAX_PATH];
        snprintf(jp, sizeof(jp), "%s\\triton_iat.json", g_output_dir);
        jf = fopen(jp, "r");
        if (jf) {
            char buf[8192];
            size_t nr = fread(buf, 1, sizeof(buf) - 1, jf);
            buf[nr] = 0;
            fclose(jf);
            char *p = strstr(buf, "\"summary\"");
            if (p) {
                char *v;
                if ((v = strstr(p, "\"unresolved\": ")) != NULL)
                    g_triton_unresolved = atol(v + 14);
                if ((v = strstr(p, "\"already_real\": ")) != NULL)
                    g_triton_already_real = atol(v + 16);
                if ((v = strstr(p, "\"collatz_bypasses\": ")) != NULL)
                    g_triton_collatz = atol(v + 20);
                if ((v = strstr(p, "\"loop_bombs\": ")) != NULL)
                    g_triton_bombs = atol(v + 14);
                if ((v = strstr(p, "\"total_instructions\": ")) != NULL)
                    g_triton_instr = strtoull(v + 21, NULL, 10);
            }
        }
    }
}

