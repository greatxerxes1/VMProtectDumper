#include "vmpd.h"
#include "triton_engine.h"

static int tri_fetch8(TriState *S, tu64 ip, tu8 *b)
{
    tu8 *pg = tri_page_find(&S->mem, ip);
    if (pg) { *b = pg[ip % TRI_PAGE_SIZE]; return 1; }
    pg = tri_page_get(&S->mem, ip);
    *b = pg[ip % TRI_PAGE_SIZE];
    return 1;
}


static int tri_modrm_decode(TriState *S, tu64 ip, int pos, int len, tu8 modrm,
                            tu8 rex, int asize64, TriOperand *rm,
                            int *reg_field, int *high8_reg)
{
    tu8 mod = (modrm >> 6) & 3;
    tu8 rg  = (modrm >> 3) & 7;
    tu8 rmb = modrm & 7;
    int ridx = rg | ((rex & 4) ? 8 : 0);
    *reg_field = ridx;
    *high8_reg = 0;

    if (S->cpu.mode64 && mod == 3) {
        int rr = rmb | ((rex & 1) ? 8 : 0);
        rm->type = TRI_REG;
        rm->reg = (tu8)rr;
        return pos;
    }
    if (!S->cpu.mode64 && mod == 3) {
        rm->type = TRI_REG;
        rm->reg = rmb;
        return pos;
    }

    rm->type = TRI_MEM;
    rm->size = (tu8)0;
    tu8 seg = 0;

    if (S->cpu.mode64) {
        tu8 b = rmb;
        if (b == 4) {
            if (pos + 1 >= len) return -1;
            tu8 sib = 0;
            tri_fetch8(S, ip + (tu64)pos, &sib);
            pos++;
            tu8 scale = sib >> 6;
            tu8 idx = ((sib >> 3) & 7) | ((rex & 2) ? 8 : 0);
            tu8 base = (sib & 7) | ((rex & 1) ? 8 : 0);
            rm->scale = (tu8)(1 << scale);
            rm->index = (idx == 4 && (sib >> 3 & 7) == 4) ? 0xFF : idx;
            if (base == 5 && mod == 0) {
                rm->base = 0xFF;
                tu32 d = 0;
                for (int i = 0; i < 4; i++) {
                    tu8 bb = 0;
                    tri_fetch8(S, ip + (tu64)(pos + i), &bb);
                    d |= (tu32)bb << (i * 8);
                }
                pos += 4;
                rm->disp = d;
                rm->riprel = 1;
            } else {
                rm->base = base;
                if (mod == 1) {
                    tu8 d8 = 0;
                    tri_fetch8(S, ip + (tu64)pos, &d8);
                    pos++;
                    rm->disp = (tu32)(ts64)(signed char)d8;
                } else if (mod == 2) {
                    tu32 d = 0;
                    for (int i = 0; i < 4; i++) {
                        tu8 bb = 0;
                        tri_fetch8(S, ip + (tu64)(pos + i), &bb);
                        d |= (tu32)bb << (i * 8);
                    }
                    pos += 4;
                    rm->disp = d;
                }
            }
        } else if (b == 5 && mod == 0) {
            rm->base = 0xFF;
            tu32 d = 0;
            for (int i = 0; i < 4; i++) {
                tu8 bb = 0;
                tri_fetch8(S, ip + (tu64)(pos + i), &bb);
                d |= (tu32)bb << (i * 8);
            }
            pos += 4;
            rm->disp = d;
            rm->riprel = 1;
        } else {
            rm->base = (tu8)(b | ((rex & 1) ? 8 : 0));
            if (mod == 1) {
                tu8 d8 = 0;
                tri_fetch8(S, ip + (tu64)pos, &d8);
                pos++;
                rm->disp = (tu32)(ts64)(signed char)d8;
            } else if (mod == 2) {
                tu32 d = 0;
                for (int i = 0; i < 4; i++) {
                    tu8 bb = 0;
                    tri_fetch8(S, ip + (tu64)(pos + i), &bb);
                    d |= (tu32)bb << (i * 8);
                }
                pos += 4;
                rm->disp = d;
            }
        }
        (void)asize64;
        (void)seg;
        return pos;
    }

    if (asize64 == 0) {
        tu8 b = rmb;
        if (b == 4) {
            if (pos + 1 >= len) return -1;
            tu8 sib = 0;
            tri_fetch8(S, ip + (tu64)pos, &sib);
            pos++;
            tu8 scale = sib >> 6;
            tu8 idx = (sib >> 3) & 7;
            tu8 base = sib & 7;
            rm->scale = (tu8)(1 << scale);
            rm->index = (idx == 4) ? 0xFF : idx;
            if (base == 5 && mod == 0) {
                rm->base = 0xFF;
                tu32 d = 0;
                for (int i = 0; i < 4; i++) {
                    tu8 bb = 0;
                    tri_fetch8(S, ip + (tu64)(pos + i), &bb);
                    d |= (tu32)bb << (i * 8);
                }
                pos += 4;
                rm->disp = d;
            } else {
                rm->base = base;
                if (mod == 1) {
                    tu8 d8 = 0;
                    tri_fetch8(S, ip + (tu64)pos, &d8);
                    pos++;
                    rm->disp = (tu32)(ts64)(signed char)d8;
                } else if (mod == 2) {
                    tu32 d = 0;
                    for (int i = 0; i < 4; i++) {
                        tu8 bb = 0;
                        tri_fetch8(S, ip + (tu64)(pos + i), &bb);
                        d |= (tu32)bb << (i * 8);
                    }
                    pos += 4;
                    rm->disp = d;
                }
            }
            return pos;
        }
        rm->base = b;
        switch (b) {
        case 5:
            if (mod == 0) {
                tu32 d = 0;
                for (int i = 0; i < 4; i++) {
                    tu8 bb = 0;
                    tri_fetch8(S, ip + (tu64)(pos + i), &bb);
                    d |= (tu32)bb << (i * 8);
                }
                pos += 4;
                rm->disp = d;
            } else {
                if (mod == 1) { tu8 d8 = 0; tri_fetch8(S, ip + (tu64)pos, &d8); pos++;
                                rm->disp = (tu32)(ts64)(signed char)d8; }
                else { tu32 d = 0;
                       for (int i = 0; i < 4; i++) { tu8 bb = 0;
                             tri_fetch8(S, ip + (tu64)(pos + i), &bb);
                             d |= (tu32)bb << (i * 8); }
                       pos += 4; rm->disp = d; }
            }
            break;
        case 3: case 6: case 7:
            if (mod == 1) { tu8 d8 = 0; tri_fetch8(S, ip + (tu64)pos, &d8); pos++;
                            rm->disp = (tu32)(ts64)(signed char)d8; }
            else if (mod == 2) { tu32 d = 0;
                                 for (int i = 0; i < 4; i++) { tu8 bb = 0;
                                       tri_fetch8(S, ip + (tu64)(pos + i), &bb);
                                       d |= (tu32)bb << (i * 8); }
                                 pos += 4; rm->disp = d; }
            break;
        default:
            if (mod == 1) { tu8 d8 = 0; tri_fetch8(S, ip + (tu64)pos, &d8); pos++;
                            rm->disp = (tu32)(ts64)(signed char)d8; }
            else if (mod == 2) { tu32 d = 0;
                                 for (int i = 0; i < 4; i++) { tu8 bb = 0;
                                       tri_fetch8(S, ip + (tu64)(pos + i), &bb);
                                       d |= (tu32)bb << (i * 8); }
                                 pos += 4; rm->disp = d; }
            break;
        }
        return pos;
    }

    (void)seg;
    return -1;
}

const char *tri_mnemonic(TriInsn *ins)
{
    static char buf[48];
    const char *op = tri_op_names[ins->op];
    switch (ins->op) {
    case TRI_OP_JCC:
        snprintf(buf, sizeof(buf), "j%s", tri_cc_names[ins->cond]);
        return buf;
    case TRI_OP_SETCC:
        snprintf(buf, sizeof(buf), "set%s", tri_cc_names[ins->cond]);
        return buf;
    case TRI_OP_CMOVCC:
        snprintf(buf, sizeof(buf), "cmov%s", tri_cc_names[ins->cond]);
        return buf;
    default:
        return op;
    }
}

int tri_decode(TriState *S, tu64 ip, TriInsn *ins)
{
    tu8 buf[TRI_MAX_INSN_LEN];
    memset(ins, 0, sizeof(*ins));
    ins->ip = ip;
    ins->dst.type = TRI_NONE;
    ins->src.type = TRI_NONE;

    for (int i = 0; i < TRI_MAX_INSN_LEN; i++)
        tri_fetch8(S, ip + (tu64)i, &buf[i]);

    int p = 0;
    tu8 rex = 0;
    int osize16 = 0, asize16 = 0, f2f3 = 0, seg = 0, has_rex = 0;
    (void)asize16;
    int osize = 4;
    int ssz = S->cpu.mode64 ? 8 : 4;

    for (;;) {
        tu8 b = buf[p];
        if (b == 0x66) { osize16 = 1; p++; }
        else if (b == 0x67) { asize16 = 1; p++; }
        else if (b == 0xF0) { p++; }
        else if (b == 0xF2 || b == 0xF3) { f2f3 = b; p++; }
        else if (b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26) { p++; }
        else if (b == 0x64) { seg = 0x64; p++; }
        else if (b == 0x65) { seg = 0x65; p++; }
        else if (S->cpu.mode64 && b >= 0x40 && b <= 0x4F) { rex = b; has_rex = 1; p++; }
        else break;
        if (p >= TRI_MAX_INSN_LEN) goto fail;
    }
    if (osize16) { osize = 2; ssz = 2; }
    if (has_rex && (rex & 8)) osize = 8;

    tu8 op = buf[p++];

    if (!S->cpu.mode64 && op >= 0x40 && op <= 0x4F) {
        ins->op = (op & 8) ? TRI_OP_DEC : TRI_OP_INC;
        ins->osize = (tu8)osize;
        ins->dst.type = TRI_REG;
        ins->dst.reg = (tu8)(op & 7);
        ins->dst.size = (tu8)osize;
        ins->len = (tu8)p;
        return p;
    }

    if (op < 0x40 && (op & 7) <= 5 && (op >> 3) <= 7 && (op & 7) != 6 && (op & 7) != 7) {
        static const tu8 grp[8] = {
            TRI_OP_ADD, TRI_OP_OR, TRI_OP_ADC, TRI_OP_SBB,
            TRI_OP_AND, TRI_OP_SUB, TRI_OP_XOR, TRI_OP_CMP
        };
        tu8 g = grp[op >> 3];
        tu8 lo = op & 7;
        if (lo == 0 || lo == 1 || lo == 2 || lo == 3) {
            int sz = (lo == 0 || lo == 2) ? 1 : osize;
            if (p >= TRI_MAX_INSN_LEN) goto fail;
            tu8 modrm = buf[p++];
            TriOperand *rmop = (lo == 0 || lo == 1) ? &ins->dst : &ins->src;
            TriOperand *rop = (lo == 0 || lo == 1) ? &ins->src : &ins->dst;
            int regf = 0, h8 = 0;
            rmop->size = (tu8)sz;
            int np = tri_modrm_decode(S, ip, p, TRI_MAX_INSN_LEN, modrm, rex,
                                      0, rmop, &regf, &h8);
            if (np < 0) goto fail;
            p = np;
            rop->type = TRI_REG;
            rop->reg = (tu8)regf;
            rop->size = (tu8)sz;
            if (sz == 1 && lo >= 2 && regf < 4 && !(rex & 4) && !S->cpu.mode64)
                { }
            ins->op = g;
            ins->osize = (tu8)sz;
            ins->len = (tu8)p;
            return p;
        } else {
            int sz = (lo == 4) ? 1 : osize;
            ins->dst.type = TRI_REG;
            ins->dst.reg = 0;
            ins->dst.size = (tu8)sz;
            ins->src.type = TRI_IMM;
            ins->src.size = (tu8)sz;
            if (lo == 4) {
                ins->src.imm = buf[p++];
            } else if (osize == 2) {
                tu16 v = 0;
                v = (tu16)(buf[p] | (buf[p + 1] << 8));
                p += 2;
                ins->src.imm = v;
            } else {
                tu32 v = 0;
                for (int i = 0; i < 4 && p + i < TRI_MAX_INSN_LEN; i++)
                    v |= (tu32)buf[p + i] << (i * 8);
                p += 4;
                if (osize == 8) ins->src.imm = (tu64)(ts64)(int)v;
                else ins->src.imm = v;
            }
            (void)ssz;
            ins->op = g;
            ins->osize = (tu8)sz;
            ins->len = (tu8)p;
            return p;
        }
    }

    switch (op) {
    case 0x0F: {
        if (p >= TRI_MAX_INSN_LEN) goto fail;
        tu8 c = buf[p++];
        if (c == 0x1E) {
            if (p >= TRI_MAX_INSN_LEN) goto fail;
            tu8 modrm = buf[p++];
            if (f2f3 && (modrm & 0xF8) == 0xF8) {
                ins->op = TRI_OP_ENDBR;
                ins->len = (tu8)p;
                return p;
            }
            goto fail;
        }
        if (c == 0x1F) {
            if (p >= TRI_MAX_INSN_LEN) goto fail;
            tu8 modrm = buf[p++];
            TriOperand rm; memset(&rm, 0, sizeof(rm));
            int regf = 0, h8 = 0;
            int np = tri_modrm_decode(S, ip, p, TRI_MAX_INSN_LEN, modrm, rex, 0, &rm, &regf, &h8);
            if (np < 0) goto fail;
            ins->op = TRI_OP_NOP;
            ins->len = (tu8)np;
            return np;
        }
        if (c == 0x05 || c == 0x0B || c == 0xA2 || c == 0x34 || c == 0x35) {
            ins->op = TRI_OP_ABORT;
            ins->len = (tu8)p;
            return p;
        }
        if (c == 0x31) {
            ins->op = TRI_OP_RDTSC;
            ins->len = (tu8)p;
            return p;
        }
        if ((c >= 0x18 && c <= 0x1D) || c == 0x0D || c == 0x0D + 1) {
            if (p >= TRI_MAX_INSN_LEN) goto fail;
            tu8 modrm = buf[p++];
            TriOperand rm; memset(&rm, 0, sizeof(rm));
            int regf = 0, h8 = 0;
            int np = tri_modrm_decode(S, ip, p, TRI_MAX_INSN_LEN, modrm, rex, 0, &rm, &regf, &h8);
            if (np < 0) goto fail;
            ins->op = TRI_OP_NOP;
            ins->len = (tu8)np;
            return np;
        }
        if (c >= 0x80 && c <= 0x8F) {
            ins->op = TRI_OP_JCC;
            ins->cond = (tu8)(c & 0xF);
            ins->osize = (tu8)osize;
            tu32 v = 0;
            for (int i = 0; i < 4 && p + i < TRI_MAX_INSN_LEN; i++)
                v |= (tu32)buf[p + i] << (i * 8);
            p += 4;
            ins->rel = (tu64)(ts64)(int)v;
            ins->len = (tu8)p;
            return p;
        }
        if (c >= 0x90 && c <= 0x9F) {
            if (p >= TRI_MAX_INSN_LEN) goto fail;
            tu8 modrm = buf[p++];
            int regf = 0, h8 = 0;
            ins->op = TRI_OP_SETCC;
            ins->cond = (tu8)(c & 0xF);
            ins->osize = 1;
            int np = tri_modrm_decode(S, ip, p, TRI_MAX_INSN_LEN, modrm, rex, 0,
                                      &ins->dst, &regf, &h8);
            if (np < 0) goto fail;
            ins->dst.size = 1;
            ins->len = (tu8)np;
            return np;
        }
        if (c == 0xA3 || c == 0xAB || c == 0xB3 || c == 0xBB || c == 0xBC || c == 0xBD) {
            if (p >= TRI_MAX_INSN_LEN) goto fail;
            tu8 modrm = buf[p++];
            int regf = 0, h8 = 0;
            ins->osize = (tu8)osize;
            int np = tri_modrm_decode(S, ip, p, TRI_MAX_INSN_LEN, modrm, rex, osize,
                                      &ins->dst, &regf, &h8);
            if (np < 0) goto fail;
            ins->src.type = TRI_REG;
            ins->src.reg = (rex & 4) ? (regf | 8) : regf;
            ins->src.size = (tu8)osize;
            switch (c) {
            case 0xA3: ins->op = TRI_OP_BT;  break;
            case 0xAB: ins->op = TRI_OP_BTS; break;
            case 0xB3: ins->op = TRI_OP_BTR; break;
            case 0xBB: ins->op = TRI_OP_BTC; break;
            case 0xBC: ins->op = TRI_OP_BSF; break;
            case 0xBD: ins->op = TRI_OP_BSR; break;
            }
            if (c == 0xBC || c == 0xBD) {
                TriOperand t = ins->dst;
                ins->dst = ins->src;
                ins->src = t;
            }
            ins->len = (tu8)np;
            return np;
        }
        if (c >= 0x40 && c <= 0x4F) {
            if (p >= TRI_MAX_INSN_LEN) goto fail;
            tu8 modrm = buf[p++];
            int regf = 0, h8 = 0;
            ins->op = TRI_OP_CMOVCC;
            ins->cond = (tu8)(c & 0xF);
            ins->osize = (tu8)osize;
            int np = tri_modrm_decode(S, ip, p, TRI_MAX_INSN_LEN, modrm, rex, 0,
                                      &ins->src, &regf, &h8);
            if (np < 0) goto fail;
            ins->src.size = (tu8)osize;
            ins->dst.type = TRI_REG;
            ins->dst.reg = (tu8)regf;
            ins->dst.size = (tu8)osize;
            ins->len = (tu8)np;
            return np;
        }
        if (c == 0xAF) {
            if (p >= TRI_MAX_INSN_LEN) goto fail;
            tu8 modrm = buf[p++];
            int regf = 0, h8 = 0;
            int np = tri_modrm_decode(S, ip, p, TRI_MAX_INSN_LEN, modrm, rex, 0,
                                      &ins->src, &regf, &h8);
            if (np < 0) goto fail;
            ins->src.size = (tu8)osize;
            ins->dst.type = TRI_REG;
            ins->dst.reg = (tu8)regf;
            ins->dst.size = (tu8)osize;
            ins->op = TRI_OP_IMUL2;
            ins->osize = (tu8)osize;
            ins->len = (tu8)np;
            return np;
        }
        if (c == 0xB6 || c == 0xB7 || c == 0xBE || c == 0xBF) {
            if (p >= TRI_MAX_INSN_LEN) goto fail;
            tu8 modrm = buf[p++];
            int regf = 0, h8 = 0;
            int np = tri_modrm_decode(S, ip, p, TRI_MAX_INSN_LEN, modrm, rex, 0,
                                      &ins->src, &regf, &h8);
            if (np < 0) goto fail;
            ins->src.size = (c == 0xB6 || c == 0xBE) ? 1 : 2;
            ins->dst.type = TRI_REG;
            ins->dst.reg = (tu8)regf;
            ins->dst.size = (tu8)osize;
            ins->op = (c == 0xB6 || c == 0xB7) ? TRI_OP_MOVZX : TRI_OP_MOVSX;
            ins->osize = (tu8)osize;
            ins->len = (tu8)np;
            return np;
        }
        if (c >= 0xC8 && c <= 0xCF) {
            ins->op = TRI_OP_BSWAP;
            ins->osize = (tu8)osize;
            ins->dst.type = TRI_REG;
            ins->dst.reg = (tu8)((c & 7) | ((rex & 1) ? 8 : 0));
            ins->dst.size = (tu8)osize;
            ins->len = (tu8)p;
            return p;
        }
        ins->op = TRI_OP_ABORT;
        ins->len = (tu8)p;
        return p;
    }
    case 0x50: case 0x51: case 0x52: case 0x53:
    case 0x54: case 0x55: case 0x56: case 0x57: {
        ins->op = TRI_OP_PUSH;
        ins->osize = (tu8)ssz;
        ins->dst.type = TRI_REG;
        ins->dst.reg = (tu8)((op & 7) | ((rex & 1) ? 8 : 0));
        ins->dst.size = (tu8)ssz;
        ins->len = (tu8)p;
        return p;
    }
    case 0x58: case 0x59: case 0x5A: case 0x5B:
    case 0x5C: case 0x5D: case 0x5E: case 0x5F: {
        ins->op = TRI_OP_POP;
        ins->osize = (tu8)ssz;
        ins->dst.type = TRI_REG;
        ins->dst.reg = (tu8)((op & 7) | ((rex & 1) ? 8 : 0));
        ins->dst.size = (tu8)ssz;
        ins->len = (tu8)p;
        return p;
    }
    case 0x63: {
        if (!S->cpu.mode64) { ins->op = TRI_OP_ABORT; ins->len = (tu8)p; return p; }
        if (p >= TRI_MAX_INSN_LEN) goto fail;
        tu8 modrm = buf[p++];
        int regf = 0, h8 = 0;
        int np = tri_modrm_decode(S, ip, p, TRI_MAX_INSN_LEN, modrm, rex, 0,
                                  &ins->src, &regf, &h8);
        if (np < 0) goto fail;
        ins->src.size = 4;
        ins->dst.type = TRI_REG;
        ins->dst.reg = (tu8)regf;
        ins->dst.size = (tu8)osize;
        ins->op = TRI_OP_MOVSXD;
        ins->osize = (tu8)osize;
        ins->len = (tu8)np;
        return np;
    }
    case 0x68: {
        ins->op = TRI_OP_PUSH;
        ins->osize = (tu8)ssz;
        ins->dst.type = TRI_IMM;
        ins->dst.size = (tu8)ssz;
        if (osize16) { ins->dst.imm = (tu16)(buf[p] | (buf[p+1] << 8)); p += 2; }
        else {
            tu32 v = 0;
            for (int i = 0; i < 4; i++) v |= (tu32)buf[p + i] << (i * 8);
            p += 4;
            ins->dst.imm = (tu64)(ts64)(int)v;
        }
        ins->len = (tu8)p;
        return p;
    }
    case 0x6A: {
        ins->op = TRI_OP_PUSH;
        ins->osize = (tu8)ssz;
        ins->dst.type = TRI_IMM;
        ins->dst.size = (tu8)ssz;
        ins->dst.imm = (tu64)(ts64)(signed char)buf[p];
        p += 1;
        ins->len = (tu8)p;
        return p;
    }
    case 0x69: case 0x6B: {
        if (p >= TRI_MAX_INSN_LEN) goto fail;
        tu8 modrm = buf[p++];
        int regf = 0, h8 = 0;
        int np = tri_modrm_decode(S, ip, p, TRI_MAX_INSN_LEN, modrm, rex, 0,
                                  &ins->src, &regf, &h8);
        if (np < 0) goto fail;
        p = np;
        ins->src.size = (tu8)osize;
        ins->third.type = TRI_IMM;
        ins->third.size = (tu8)osize;
        if (op == 0x69) {
            if (osize == 2) { ins->third.imm = (tu16)(buf[p] | (buf[p + 1] << 8)); p += 2; }
            else {
                tu32 v = 0;
                for (int i = 0; i < 4; i++) v |= (tu32)buf[p + i] << (i * 8);
                p += 4;
                ins->third.imm = (osize == 8) ? (tu64)(ts64)(int)v : v;
            }
        } else {
            ins->third.imm = (tu64)(ts64)(signed char)buf[p];
            p += 1;
        }
        ins->dst.type = TRI_REG;
        ins->dst.reg = (tu8)regf;
        ins->dst.size = (tu8)osize;
        ins->op = TRI_OP_IMUL3;
        ins->osize = (tu8)osize;
        ins->len = (tu8)p;
        return p;
    }
    case 0x70: case 0x71: case 0x72: case 0x73:
    case 0x74: case 0x75: case 0x76: case 0x77:
    case 0x78: case 0x79: case 0x7A: case 0x7B:
    case 0x7C: case 0x7D: case 0x7E: case 0x7F: {
        ins->op = TRI_OP_JCC;
        ins->cond = (tu8)(op & 0xF);
        ins->osize = (tu8)osize;
        ins->rel = (tu64)(ts64)(signed char)buf[p];
        p += 1;
        ins->len = (tu8)p;
        return p;
    }
    case 0x80: case 0x81: case 0x83: {
        if (p >= TRI_MAX_INSN_LEN) goto fail;
        tu8 modrm = buf[p++];
        tu8 g = (modrm >> 3) & 7;
        static const tu8 gg[8] = {
            TRI_OP_ADD, TRI_OP_OR, TRI_OP_ADC, TRI_OP_SBB,
            TRI_OP_AND, TRI_OP_SUB, TRI_OP_XOR, TRI_OP_CMP
        };
        int regf = 0, h8 = 0;
        int sz = (op == 0x80) ? 1 : osize;
        int np = tri_modrm_decode(S, ip, p, TRI_MAX_INSN_LEN, modrm, rex, 0,
                                  &ins->dst, &regf, &h8);
        if (np < 0) goto fail;
        p = np;
        ins->dst.size = (tu8)sz;
        ins->src.type = TRI_IMM;
        ins->src.size = (tu8)sz;
        if (op == 0x80) {
            ins->src.imm = buf[p++];
        } else if (op == 0x81) {
            if (osize == 2) { ins->src.imm = (tu16)(buf[p] | (buf[p+1] << 8)); p += 2; }
            else {
                tu32 v = 0;
                for (int i = 0; i < 4; i++) v |= (tu32)buf[p + i] << (i * 8);
                p += 4;
                ins->src.imm = (osize == 8) ? (tu64)(ts64)(int)v : v;
            }
        } else {
            ins->src.imm = (tu64)(ts64)(signed char)buf[p++];
        }
        ins->op = gg[g];
        ins->osize = (tu8)sz;
        ins->len = (tu8)p;
        return p;
    }
    case 0x84: case 0x85: {
        if (p >= TRI_MAX_INSN_LEN) goto fail;
        tu8 modrm = buf[p++];
        int regf = 0, h8 = 0;
        int sz = (op == 0x84) ? 1 : osize;
        int np = tri_modrm_decode(S, ip, p, TRI_MAX_INSN_LEN, modrm, rex, 0,
                                  &ins->dst, &regf, &h8);
        if (np < 0) goto fail;
        p = np;
        ins->dst.size = (tu8)sz;
        ins->src.type = TRI_REG;
        ins->src.reg = (tu8)regf;
        ins->src.size = (tu8)sz;
        ins->op = TRI_OP_TEST;
        ins->osize = (tu8)sz;
        ins->len = (tu8)np;
        return np;
    }
    case 0x86: case 0x87: {
        if (p >= TRI_MAX_INSN_LEN) goto fail;
        tu8 modrm = buf[p++];
        int regf = 0, h8 = 0;
        int sz = (op == 0x86) ? 1 : osize;
        int np = tri_modrm_decode(S, ip, p, TRI_MAX_INSN_LEN, modrm, rex, 0,
                                  &ins->dst, &regf, &h8);
        if (np < 0) goto fail;
        p = np;
        ins->dst.size = (tu8)sz;
        ins->src.type = TRI_REG;
        ins->src.reg = (tu8)regf;
        ins->src.size = (tu8)sz;
        ins->op = TRI_OP_XCHG;
        ins->osize = (tu8)sz;
        ins->len = (tu8)np;
        return np;
    }
    case 0x88: case 0x89: case 0x8A: case 0x8B: {
        if (p >= TRI_MAX_INSN_LEN) goto fail;
        tu8 modrm = buf[p++];
        int regf = 0, h8 = 0;
        int sz = ((op == 0x88) || (op == 0x8A)) ? 1 : osize;
        int np = tri_modrm_decode(S, ip, p, TRI_MAX_INSN_LEN, modrm, rex, 0,
                                  (op == 0x88 || op == 0x89) ? &ins->dst : &ins->src,
                                  &regf, &h8);
        if (np < 0) goto fail;
        p = np;
        if (op == 0x88 || op == 0x89) {
            ins->src.type = TRI_REG;
            ins->src.reg = (tu8)regf;
        } else {
            ins->dst.type = TRI_REG;
            ins->dst.reg = (tu8)regf;
        }
        ins->dst.size = (tu8)sz;
        ins->src.size = (tu8)sz;
        ins->op = TRI_OP_MOV;
        ins->osize = (tu8)sz;
        ins->len = (tu8)np;
        return np;
    }
    case 0x8D: {
        if (p >= TRI_MAX_INSN_LEN) goto fail;
        tu8 modrm = buf[p++];
        int regf = 0, h8 = 0;
        int np = tri_modrm_decode(S, ip, p, TRI_MAX_INSN_LEN, modrm, rex, 0,
                                  &ins->src, &regf, &h8);
        if (np < 0) goto fail;
        p = np;
        ins->dst.type = TRI_REG;
        ins->dst.reg = (tu8)regf;
        ins->dst.size = (tu8)osize;
        ins->src.size = (tu8)osize;
        ins->op = TRI_OP_LEA;
        ins->osize = (tu8)osize;
        ins->len = (tu8)np;
        return np;
    }
    case 0x8F: {
        if (p >= TRI_MAX_INSN_LEN) goto fail;
        tu8 modrm = buf[p++];
        int regf = 0, h8 = 0;
        int np = tri_modrm_decode(S, ip, p, TRI_MAX_INSN_LEN, modrm, rex, 0,
                                  &ins->dst, &regf, &h8);
        if (np < 0) goto fail;
        p = np;
        ins->dst.size = (tu8)ssz;
        ins->op = TRI_OP_POP;
        ins->osize = (tu8)ssz;
        ins->len = (tu8)np;
        return np;
    }
    case 0x90: {
        if (f2f3 == 0xF3) { ins->op = TRI_OP_PAUSE; ins->len = (tu8)p; return p; }
        if (rex) {
            ins->op = TRI_OP_XCHG;
            ins->osize = (tu8)osize;
            ins->dst.type = TRI_REG;
            ins->dst.reg = 0;
            ins->dst.size = (tu8)osize;
            ins->src.type = TRI_REG;
            ins->src.reg = (tu8)((rex & 1) ? 8 : 0);
            ins->src.size = (tu8)osize;
            ins->len = (tu8)p;
            return p;
        }
        ins->op = TRI_OP_NOP;
        ins->len = (tu8)p;
        return p;
    }
    case 0x91: case 0x92: case 0x93: case 0x94:
    case 0x95: case 0x96: case 0x97: {
        ins->op = TRI_OP_XCHG;
        ins->osize = (tu8)osize;
        ins->dst.type = TRI_REG;
        ins->dst.reg = 0;
        ins->dst.size = (tu8)osize;
        ins->src.type = TRI_REG;
        ins->src.reg = (tu8)((op & 7) | ((rex & 1) ? 8 : 0));
        ins->src.size = (tu8)osize;
        ins->len = (tu8)p;
        return p;
    }
    case 0x98: {
        ins->op = TRI_OP_CWDE;
        ins->osize = (tu8)osize;
        ins->len = (tu8)p;
        return p;
    }
    case 0x99: {
        ins->op = TRI_OP_CDQ;
        ins->osize = (tu8)osize;
        ins->len = (tu8)p;
        return p;
    }
    case 0x9C: {
        ins->op = TRI_OP_PUSHF;
        ins->osize = (tu8)ssz;
        ins->len = (tu8)p;
        return p;
    }
    case 0x9D: {
        ins->op = TRI_OP_POPF;
        ins->osize = (tu8)ssz;
        ins->len = (tu8)p;
        return p;
    }
    case 0xA8: {
        ins->op = TRI_OP_TEST;
        ins->osize = 1;
        ins->dst.type = TRI_REG;
        ins->dst.reg = 0;
        ins->dst.size = 1;
        ins->src.type = TRI_IMM;
        ins->src.imm = buf[p++];
        ins->src.size = 1;
        ins->len = (tu8)p;
        return p;
    }
    case 0xA9: {
        ins->op = TRI_OP_TEST;
        ins->osize = (tu8)osize;
        ins->dst.type = TRI_REG;
        ins->dst.reg = 0;
        ins->dst.size = (tu8)osize;
        ins->src.type = TRI_IMM;
        if (osize == 2) { ins->src.imm = (tu16)(buf[p] | (buf[p+1] << 8)); p += 2; }
        else { tu32 v = 0;
               for (int i = 0; i < 4; i++) v |= (tu32)buf[p + i] << (i * 8);
               p += 4;
               ins->src.imm = (osize == 8) ? (tu64)(ts64)(int)v : v; }
        ins->src.size = (tu8)osize;
        ins->len = (tu8)p;
        return p;
    }
    case 0xB0: case 0xB1: case 0xB2: case 0xB3:
    case 0xB4: case 0xB5: case 0xB6: case 0xB7: {
        ins->op = TRI_OP_MOV;
        ins->osize = 1;
        ins->dst.type = TRI_REG;
        int rr = op & 7;
        ins->dst.reg = (tu8)rr;
        ins->dst.size = 1;
        ins->src.type = TRI_IMM;
        ins->src.imm = buf[p++];
        ins->src.size = 1;
        ins->len = (tu8)p;
        return p;
    }
    case 0xB8: case 0xB9: case 0xBA: case 0xBB:
    case 0xBC: case 0xBD: case 0xBE: case 0xBF: {
        ins->op = TRI_OP_MOV;
        ins->osize = (tu8)osize;
        ins->dst.type = TRI_REG;
        ins->dst.reg = (tu8)((op & 7) | ((rex & 1) ? 8 : 0));
        ins->dst.size = (tu8)osize;
        ins->src.type = TRI_IMM;
        ins->src.size = (tu8)osize;
        if (osize == 8) {
            tu64 v = 0;
            for (int i = 0; i < 8; i++) v |= (tu64)buf[p + i] << (i * 8);
            p += 8;
            ins->src.imm = v;
        } else if (osize == 2) {
            ins->src.imm = (tu16)(buf[p] | (buf[p+1] << 8));
            p += 2;
        } else {
            tu32 v = 0;
            for (int i = 0; i < 4; i++) v |= (tu32)buf[p + i] << (i * 8);
            p += 4;
            ins->src.imm = v;
        }
        ins->len = (tu8)p;
        return p;
    }
    case 0xC0: case 0xC1: {
        if (p >= TRI_MAX_INSN_LEN) goto fail;
        tu8 modrm = buf[p++];
        tu8 g = (modrm >> 3) & 7;
        int regf = 0, h8 = 0;
        int sz = (op == 0xC0) ? 1 : osize;
        int np = tri_modrm_decode(S, ip, p, TRI_MAX_INSN_LEN, modrm, rex, 0,
                                  &ins->dst, &regf, &h8);
        if (np < 0) goto fail;
        p = np;
        ins->dst.size = (tu8)sz;
        ins->src.type = TRI_IMM;
        ins->src.imm = buf[p++];
        ins->src.size = 1;
        if (g == 2 || g == 3) goto fail;
        ins->op = (g == 0) ? TRI_OP_ROL : (g == 1) ? TRI_OP_ROR :
                  (g == 4 || g == 6) ? TRI_OP_SHL : (g == 5) ? TRI_OP_SHR : TRI_OP_SAR;
        ins->osize = (tu8)sz;
        ins->len = (tu8)p;
        return p;
    }
    case 0xC2: {
        tu16 v = (tu16)(buf[p] | (buf[p + 1] << 8));
        p += 2;
        ins->op = TRI_OP_RET;
        ins->osize = (tu8)osize;
        ins->src.type = TRI_IMM;
        ins->src.imm = v;
        ins->src.size = 2;
        ins->len = (tu8)p;
        return p;
    }
    case 0xC3: {
        ins->op = TRI_OP_RET;
        ins->osize = (tu8)osize;
        ins->len = (tu8)p;
        return p;
    }
    case 0xC6: case 0xC7: {
        if (p >= TRI_MAX_INSN_LEN) goto fail;
        tu8 modrm = buf[p++];
        if (((modrm >> 3) & 7) != 0) goto fail;
        int regf = 0, h8 = 0;
        int sz = (op == 0xC6) ? 1 : osize;
        int np = tri_modrm_decode(S, ip, p, TRI_MAX_INSN_LEN, modrm, rex, 0,
                                  &ins->dst, &regf, &h8);
        if (np < 0) goto fail;
        p = np;
        ins->dst.size = (tu8)sz;
        ins->src.type = TRI_IMM;
        ins->src.size = (tu8)sz;
        if (op == 0xC6) {
            ins->src.imm = buf[p++];
        } else if (osize == 2) {
            ins->src.imm = (tu16)(buf[p] | (buf[p+1] << 8));
            p += 2;
        } else {
            tu32 v = 0;
            for (int i = 0; i < 4; i++) v |= (tu32)buf[p + i] << (i * 8);
            p += 4;
            ins->src.imm = (osize == 8) ? (tu64)(ts64)(int)v : v;
        }
        ins->op = TRI_OP_MOV;
        ins->osize = (tu8)sz;
        ins->len = (tu8)p;
        return p;
    }
    case 0xD0: case 0xD1: case 0xD2: case 0xD3: {
        if (p >= TRI_MAX_INSN_LEN) goto fail;
        tu8 modrm = buf[p++];
        tu8 g = (modrm >> 3) & 7;
        int regf = 0, h8 = 0;
        int sz = (op == 0xD0 || op == 0xD2) ? 1 : osize;
        int np = tri_modrm_decode(S, ip, p, TRI_MAX_INSN_LEN, modrm, rex, 0,
                                  &ins->dst, &regf, &h8);
        if (np < 0) goto fail;
        p = np;
        ins->dst.size = (tu8)sz;
        if (op == 0xD0 || op == 0xD1) {
            ins->src.type = TRI_IMM;
            ins->src.imm = 1;
            ins->src.size = 1;
        } else {
            ins->src.type = TRI_REG;
            ins->src.reg = 1;
            ins->src.size = 1;
        }
        if (g == 2 || g == 3) goto fail;
        ins->op = (g == 0) ? TRI_OP_ROL : (g == 1) ? TRI_OP_ROR :
                  (g == 4 || g == 6) ? TRI_OP_SHL : (g == 5) ? TRI_OP_SHR : TRI_OP_SAR;
        ins->osize = (tu8)sz;
        ins->len = (tu8)np;
        return np;
    }
    case 0xE8: {
        tu32 v = 0;
        for (int i = 0; i < 4; i++) v |= (tu32)buf[p + i] << (i * 8);
        p += 4;
        ins->op = TRI_OP_CALL;
        ins->osize = (tu8)osize;
        ins->rel = (tu64)(ts64)(int)v;
        ins->len = (tu8)p;
        return p;
    }
    case 0xE9: {
        tu32 v = 0;
        for (int i = 0; i < 4; i++) v |= (tu32)buf[p + i] << (i * 8);
        p += 4;
        ins->op = TRI_OP_JMP;
        ins->osize = (tu8)osize;
        ins->rel = (tu64)(ts64)(int)v;
        ins->len = (tu8)p;
        return p;
    }
    case 0xEB: {
        ins->op = TRI_OP_JMP;
        ins->osize = (tu8)osize;
        ins->rel = (tu64)(ts64)(signed char)buf[p];
        p += 1;
        ins->len = (tu8)p;
        return p;
    }
    case 0xF5: {
        ins->op = TRI_OP_NOP;
        S->cpu.cf ^= 1;
        ins->len = (tu8)p;
        return p;
    }
    case 0xF8: {
        ins->op = TRI_OP_NOP;
        S->cpu.cf = 0;
        ins->len = (tu8)p;
        return p;
    }
    case 0xF9: {
        ins->op = TRI_OP_NOP;
        S->cpu.cf = 1;
        ins->len = (tu8)p;
        return p;
    }
    case 0xFC: {
        ins->op = TRI_OP_NOP;
        S->cpu.df = 0;
        ins->len = (tu8)p;
        return p;
    }
    case 0xFD: {
        ins->op = TRI_OP_NOP;
        S->cpu.df = 1;
        ins->len = (tu8)p;
        return p;
    }
    case 0xF6: case 0xF7: {
        if (p >= TRI_MAX_INSN_LEN) goto fail;
        tu8 modrm = buf[p++];
        tu8 g = (modrm >> 3) & 7;
        int regf = 0, h8 = 0;
        int sz = (op == 0xF6) ? 1 : osize;
        int np = tri_modrm_decode(S, ip, p, TRI_MAX_INSN_LEN, modrm, rex, 0,
                                  &ins->dst, &regf, &h8);
        if (np < 0) goto fail;
        p = np;
        ins->dst.size = (tu8)sz;
        ins->src.type = TRI_IMM;
        ins->src.size = (tu8)sz;
        if (g == 0 || g == 1) {
            if (op == 0xF6) { ins->src.imm = buf[p++]; }
            else if (osize == 2) { ins->src.imm = (tu16)(buf[p] | (buf[p+1] << 8)); p += 2; }
            else { tu32 v = 0;
                   for (int i = 0; i < 4; i++) v |= (tu32)buf[p + i] << (i * 8);
                   p += 4;
                   ins->src.imm = (osize == 8) ? (tu64)(ts64)(int)v : v; }
            ins->op = TRI_OP_TEST;
        } else if (g == 2) ins->op = TRI_OP_NOT;
        else if (g == 3) ins->op = TRI_OP_NEG;
        else if (g == 4) ins->op = TRI_OP_MUL;
        else if (g == 5) ins->op = TRI_OP_IMUL2;
        else if (g == 6) ins->op = TRI_OP_DIV;
        else ins->op = TRI_OP_IDIV;
        ins->osize = (tu8)sz;
        ins->len = (tu8)p;
        return p;
    }
    case 0xFE: {
        if (p >= TRI_MAX_INSN_LEN) goto fail;
        tu8 modrm = buf[p++];
        tu8 g = (modrm >> 3) & 7;
        int regf = 0, h8 = 0;
        int np = tri_modrm_decode(S, ip, p, TRI_MAX_INSN_LEN, modrm, rex, 0,
                                  &ins->dst, &regf, &h8);
        if (np < 0) goto fail;
        p = np;
        if (g > 1) goto fail;
        ins->dst.size = 1;
        ins->op = (g == 0) ? TRI_OP_INC : TRI_OP_DEC;
        ins->osize = 1;
        ins->len = (tu8)np;
        return np;
    }
    case 0xFF: {
        if (p >= TRI_MAX_INSN_LEN) goto fail;
        tu8 modrm = buf[p++];
        tu8 g = (modrm >> 3) & 7;
        int regf = 0, h8 = 0;
        int np = tri_modrm_decode(S, ip, p, TRI_MAX_INSN_LEN, modrm, rex, 0,
                                  &ins->dst, &regf, &h8);
        if (np < 0) goto fail;
        p = np;
        ins->dst.size = (tu8)osize;
        ins->osize = (tu8)osize;
        switch (g) {
        case 0: ins->op = TRI_OP_INC; break;
        case 1: ins->op = TRI_OP_DEC; break;
        case 2: ins->op = TRI_OP_CALL; break;
        case 4: ins->op = TRI_OP_JMP; break;
        case 6: ins->op = TRI_OP_PUSH; break;
        default: goto fail;
        }
        ins->len = (tu8)np;
        return np;
    }
    default:
        goto fail;
    }

fail:
    ins->op = TRI_OP_ABORT;
    ins->len = (tu8)(p ? p : 1);
    return ins->len;
}

