#include "smtsolver.h"

static su64 smt_mask(su32 w)
{
    return (w >= 64) ? ~0ULL : ((1ULL << w) - 1);
}

static int smt_inv(int l)
{
    return l ^ 1;
}

void smt_init(SmtCtx *C)
{
    memset(C, 0, sizeof(*C));
    C->cap = 4096;
    C->n = (SmtNode *)malloc(C->cap * sizeof(SmtNode));
    if (!C->n) abort();
}

void smt_free(SmtCtx *C)
{
    free(C->n);
    memset(C, 0, sizeof(*C));
}

static su32 smt_push(SmtCtx *C, int op, su8 w, su32 a, su32 b, su64 val, su32 var_id)
{
    if (C->count >= C->cap) {
        C->cap *= 2;
        C->n = (SmtNode *)realloc(C->n, C->cap * sizeof(SmtNode));
        if (!C->n) abort();
    }
    SmtNode *e = &C->n[C->count];
    e->op = (su8)op;
    e->w = w;
    e->a = a;
    e->b = b;
    e->val = val;
    e->var_id = var_id;
    return C->count++;
}

su32 smt_const(SmtCtx *C, su32 w, su64 v)
{
    if (w < 64) v &= smt_mask(w);
    return smt_push(C, SM_CONST, (su8)w, SM_NONE, SM_NONE, v, 0);
}

su32 smt_var(SmtCtx *C, su32 w)
{
    return smt_push(C, SM_VAR, (su8)w, SM_NONE, SM_NONE, 0, C->nvars++);
}

su32 smt_bin(SmtCtx *C, int op, su32 a, su32 b)
{
    su8 w = C->n[a].w;
    switch (op) {
    case SM_EQ: case SM_ULT: case SM_ULE: case SM_UGT: case SM_UGE:
    case SM_SLT: case SM_SLE: case SM_SGT: case SM_SGE:
    case SM_LAND: case SM_LOR: case SM_LXOR:
        w = 1;
        break;
    default:
        break;
    }
    return smt_push(C, op, w, a, b, 0, 0);
}

su32 smt_un(SmtCtx *C, int op, su32 a)
{
    su8 w = C->n[a].w;
    if (op == SM_LNOT) w = 1;
    return smt_push(C, op, w, a, SM_NONE, 0, 0);
}

su32 smt_extract(SmtCtx *C, su32 a, su32 low, su32 w)
{
    return smt_push(C, SM_EXTRACT, (su8)w, a, SM_NONE, (su64)low, 0);
}

su32 smt_concat(SmtCtx *C, su32 hi, su32 lo)
{
    su8 w = (su8)(C->n[hi].w + C->n[lo].w);
    return smt_push(C, SM_CONCAT, w, hi, lo, 0, 0);
}

su32 smt_ite(SmtCtx *C, su32 cond, su32 t, su32 e)
{
    su8 w = C->n[t].w;
    su32 id = smt_push(C, SM_ITE, w, cond, e, 0, 0);
    C->n[id].val = (su64)t;
    return id;
}

su32 smt_zext(SmtCtx *C, su32 a, su32 w)
{
    return smt_push(C, SM_ZEXT, (su8)w, a, SM_NONE, 0, 0);
}

su32 smt_sext(SmtCtx *C, su32 a, su32 w)
{
    return smt_push(C, SM_SEXT, (su8)w, a, SM_NONE, 0, 0);
}

su32 smt_lnot(SmtCtx *C, su32 a)
{
    if (C->n[a].op == SM_LNOT) return C->n[a].a;
    return smt_un(C, SM_LNOT, a);
}

int smt_is_const(SmtCtx *C, su32 id, su64 *out)
{
    if (C->n[id].op == SM_CONST) { *out = C->n[id].val; return 1; }
    return 0;
}

static int smt_has_var_rec(SmtCtx *C, su32 id, su8 *seen)
{
    if (id == SM_NONE || seen[id]) return 0;
    seen[id] = 1;
    SmtNode *e = &C->n[id];
    if (e->op == SM_VAR) return 1;
    if (e->a != SM_NONE && smt_has_var_rec(C, e->a, seen)) return 1;
    if (e->op == SM_ITE && smt_has_var_rec(C, (su32)e->val, seen)) return 1;
    if (e->b != SM_NONE && smt_has_var_rec(C, e->b, seen)) return 1;
    return 0;
}

int smt_has_var(SmtCtx *C, su32 id)
{
    if (id == SM_NONE) return 0;
    su8 *seen = (su8 *)calloc(C->cap, 1);
    if (!seen) return 0;
    int r = smt_has_var_rec(C, id, seen);
    free(seen);
    return r;
}

static int smt_eval_rec(SmtCtx *C, su32 id, const su64 *model, su64 *out)
{
    SmtNode *e = &C->n[id];
    su64 a = 0, b = 0, c = 0;
    su64 m = smt_mask(e->w);
    switch (e->op) {
    case SM_CONST: *out = e->val & m; return 1;
    case SM_VAR:
        if (!model) return 0;
        *out = model[e->var_id] & m;
        return 1;
    case SM_ITE:
        if (!smt_eval_rec(C, e->a, model, &c)) return 0;
        if (!smt_eval_rec(C, (su32)e->val, model, &a)) return 0;
        if (!smt_eval_rec(C, e->b, model, &b)) return 0;
        *out = c ? a : b;
        return 1;
    default:
        break;
    }
    if (e->a != SM_NONE && !smt_eval_rec(C, e->a, model, &a)) return 0;
    if (e->b != SM_NONE && !smt_eval_rec(C, e->b, model, &b)) return 0;
    switch (e->op) {
    case SM_ADD:  *out = (a + b) & m; return 1;
    case SM_SUB:  *out = (a - b) & m; return 1;
    case SM_MUL:  *out = (a * b) & m; return 1;
    case SM_AND:  *out = a & b; return 1;
    case SM_OR:   *out = a | b; return 1;
    case SM_XOR:  *out = a ^ b; return 1;
    case SM_NOT:  *out = (~a) & m; return 1;
    case SM_NEG:  *out = (0 - a) & m; return 1;
    case SM_SHL:  *out = (b >= e->w) ? 0 : (a << b) & m; return 1;
    case SM_LSHR: *out = (b >= e->w) ? 0 : (a >> b); return 1;
    case SM_ASHR: {
        su64 sh = (b >= e->w) ? (e->w ? e->w - 1 : 0) : b;
        if (e->w < 64 && ((a >> (e->w - 1)) & 1)) a |= ~smt_mask(e->w);
        *out = (su64)(((ts64)a) >> sh) & m;
        return 1;
    }
    case SM_ROL: {
        su32 bits = e->w;
        su32 sh = (su32)(b % (bits ? bits : 1));
        *out = sh ? (((a << sh) | (a >> (bits - sh))) & m) : (a & m);
        return 1;
    }
    case SM_ROR: {
        su32 bits = e->w;
        su32 sh = (su32)(b % (bits ? bits : 1));
        *out = sh ? (((a >> sh) | (a << (bits - sh))) & m) : (a & m);
        return 1;
    }
    case SM_ZEXT: *out = a & m; return 1;
    case SM_SEXT: {
        su32 sw = C->n[e->a].w;
        su64 sgn = 1ULL << (sw - 1);
        *out = (a & (sgn - 1)) - (a & sgn);
        *out &= m;
        return 1;
    }
    case SM_EXTRACT: {
        su32 low = (su32)e->val;
        *out = (a >> low) & m;
        return 1;
    }
    case SM_CONCAT: {
        su32 lw = C->n[e->b].w;
        *out = ((a << lw) | (b & smt_mask(lw))) & m;
        return 1;
    }
    case SM_EQ:  *out = (a == b); return 1;
    case SM_ULT: *out = (a < b); return 1;
    case SM_ULE: *out = (a <= b); return 1;
    case SM_UGT: *out = (a > b); return 1;
    case SM_UGE: *out = (a >= b); return 1;
    case SM_SLT: {
        su32 bw = C->n[e->a].w;
        su64 sgn = 1ULL << (bw - 1);
        *out = (su64)((ts64)((a ^ sgn) & smt_mask(bw)) < (ts64)((b ^ sgn) & smt_mask(bw)));
        return 1;
    }
    case SM_SLE: {
        su32 bw = C->n[e->a].w;
        su64 sgn = 1ULL << (bw - 1);
        *out = (su64)((ts64)((a ^ sgn) & smt_mask(bw)) <= (ts64)((b ^ sgn) & smt_mask(bw)));
        return 1;
    }
    case SM_SGT: {
        su32 bw = C->n[e->a].w;
        su64 sgn = 1ULL << (bw - 1);
        *out = (su64)((ts64)((a ^ sgn) & smt_mask(bw)) > (ts64)((b ^ sgn) & smt_mask(bw)));
        return 1;
    }
    case SM_SGE: {
        su32 bw = C->n[e->a].w;
        su64 sgn = 1ULL << (bw - 1);
        *out = (su64)((ts64)((a ^ sgn) & smt_mask(bw)) >= (ts64)((b ^ sgn) & smt_mask(bw)));
        return 1;
    }
    case SM_LAND: *out = (a && b); return 1;
    case SM_LOR:  *out = (a || b); return 1;
    case SM_LXOR: *out = ((a != 0) != (b != 0)); return 1;
    case SM_LNOT: *out = (a == 0); return 1;
    default: return 0;
    }
}

int smt_eval(SmtCtx *C, su32 id, const su64 *model, su64 *out)
{
    return smt_eval_rec(C, id, model, out);
}

typedef struct {
    int *arena;
    int arena_n, arena_cap;
    int *off, *len;
    int cl_n, cl_cap;
    int nvars;
} Circuit;

static void cir_init(Circuit *k, int nvars)
{
    memset(k, 0, sizeof(*k));
    k->arena_cap = 262144;
    k->arena = (int *)malloc((size_t)k->arena_cap * sizeof(int));
    k->cl_cap = 262144;
    k->off = (int *)malloc((size_t)k->cl_cap * sizeof(int));
    k->len = (int *)malloc((size_t)k->cl_cap * sizeof(int));
    k->nvars = nvars > 0 ? nvars : 1;
    if (!k->arena || !k->off || !k->len) abort();
}

static void cir_free(Circuit *k)
{
    free(k->arena);
    free(k->off);
    free(k->len);
}

static void cir_push_lit(Circuit *k, int l)
{
    if (k->arena_n >= k->arena_cap) {
        k->arena_cap *= 2;
        k->arena = (int *)realloc(k->arena, (size_t)k->arena_cap * sizeof(int));
        if (!k->arena) abort();
    }
    k->arena[k->arena_n++] = l;
}

static void cir_end_clause(Circuit *k, int start)
{
    int sz = k->arena_n - start;
    if (sz == 0) return;
    int w = start;
    for (int i = start; i < k->arena_n; i++) {
        int dup = 0;
        for (int j = start; j < w && !dup; j++)
            if (k->arena[i] == k->arena[j]) dup = 1;
        if (!dup) k->arena[w++] = k->arena[i];
    }
    k->arena_n = w;
    sz = k->arena_n - start;
    for (int i = start; i < k->arena_n; i++)
        for (int j = i + 1; j < k->arena_n; j++)
            if (k->arena[i] == (k->arena[j] ^ 1)) {
                k->arena_n = start;
                return;
            }
    if (k->cl_n >= k->cl_cap) {
        k->cl_cap *= 2;
        k->off = (int *)realloc(k->off, (size_t)k->cl_cap * sizeof(int));
        k->len = (int *)realloc(k->len, (size_t)k->cl_cap * sizeof(int));
        if (!k->off || !k->len) abort();
    }
    k->off[k->cl_n] = start;
    k->len[k->cl_n] = sz;
    k->cl_n++;
}

static int cir_var(Circuit *k)
{
    return k->nvars++;
}

static int cir_and(Circuit *k, int a, int b)
{
    if (a == 0) return b;
    if (b == 0) return a;
    if (a == 1 || b == 1) return 1;
    int c = cir_var(k) * 2;
    cir_push_lit(k, a ^ 1); cir_push_lit(k, b ^ 1); cir_push_lit(k, c);
    cir_end_clause(k, k->arena_n - 3);
    cir_push_lit(k, a); cir_push_lit(k, c ^ 1);
    cir_end_clause(k, k->arena_n - 2);
    cir_push_lit(k, b); cir_push_lit(k, c ^ 1);
    cir_end_clause(k, k->arena_n - 2);
    return c;
}

static int cir_or(Circuit *k, int a, int b)
{
    if (a == 0 || b == 0) return 0;
    if (a == 1) return b;
    if (b == 1) return a;
    int c = cir_var(k) * 2;
    cir_push_lit(k, a); cir_push_lit(k, b); cir_push_lit(k, c ^ 1);
    cir_end_clause(k, k->arena_n - 3);
    cir_push_lit(k, a ^ 1); cir_push_lit(k, c);
    cir_end_clause(k, k->arena_n - 2);
    cir_push_lit(k, b ^ 1); cir_push_lit(k, c);
    cir_end_clause(k, k->arena_n - 2);
    return c;
}

static int cir_xor(Circuit *k, int a, int b)
{
    if (a == 0) return smt_inv(b);
    if (b == 0) return smt_inv(a);
    if (a == 1) return b;
    if (b == 1) return a;
    int c = cir_var(k) * 2;
    cir_push_lit(k, a); cir_push_lit(k, b); cir_push_lit(k, c ^ 1);
    cir_end_clause(k, k->arena_n - 3);
    cir_push_lit(k, a ^ 1); cir_push_lit(k, b ^ 1); cir_push_lit(k, c ^ 1);
    cir_end_clause(k, k->arena_n - 3);
    cir_push_lit(k, a); cir_push_lit(k, b ^ 1); cir_push_lit(k, c);
    cir_end_clause(k, k->arena_n - 3);
    cir_push_lit(k, a ^ 1); cir_push_lit(k, b); cir_push_lit(k, c);
    cir_end_clause(k, k->arena_n - 3);
    return c;
}

static int cir_mux(Circuit *k, int s, int t, int e)
{
    if (s == 0) return t;
    if (s == 1) return e;
    if (t == e) return t;
    int c = cir_var(k) * 2;
    cir_push_lit(k, s ^ 1); cir_push_lit(k, t ^ 1); cir_push_lit(k, c);
    cir_end_clause(k, k->arena_n - 3);
    cir_push_lit(k, s ^ 1); cir_push_lit(k, t); cir_push_lit(k, c ^ 1);
    cir_end_clause(k, k->arena_n - 3);
    cir_push_lit(k, s); cir_push_lit(k, e ^ 1); cir_push_lit(k, c);
    cir_end_clause(k, k->arena_n - 3);
    cir_push_lit(k, s); cir_push_lit(k, e); cir_push_lit(k, c ^ 1);
    cir_end_clause(k, k->arena_n - 3);
    cir_push_lit(k, t ^ 1); cir_push_lit(k, e ^ 1); cir_push_lit(k, c);
    cir_end_clause(k, k->arena_n - 3);
    cir_push_lit(k, t); cir_push_lit(k, e); cir_push_lit(k, c ^ 1);
    cir_end_clause(k, k->arena_n - 3);
    return c;
}

static int cir_c(int v)
{
    return v ? 0 : 1;
}

typedef struct {
    Circuit *k;
    int **bits;
    su32 bits_cap;
} Blaster;

static int *bl_bits(Blaster *B, su32 id, su32 w)
{
    if (id >= B->bits_cap) {
        su32 nc = B->bits_cap ? B->bits_cap : 4096;
        while (nc <= id) nc *= 2;
        B->bits = (int **)realloc(B->bits, nc * sizeof(int *));
        if (!B->bits) abort();
        memset(B->bits + B->bits_cap, 0, (nc - B->bits_cap) * sizeof(int *));
        B->bits_cap = nc;
    }
    if (!B->bits[id]) {
        B->bits[id] = (int *)malloc(w * sizeof(int));
        if (!B->bits[id]) abort();
        for (su32 i = 0; i < w; i++) B->bits[id][i] = -1;
    }
    return B->bits[id];
}

static void blast(SmtCtx *C, Blaster *B, su32 id);

static int blast_ult(SmtCtx *C, Blaster *B, su32 a_id, su32 b_id);

static void blast_adder(SmtCtx *C, Blaster *B, su32 id)
{
    SmtNode *e = &C->n[id];
    su32 w = e->w;
    int *out = bl_bits(B, id, w);
    blast(C, B, e->a);
    int *A = B->bits[e->a];
    int carry;

    if (e->op == SM_SUB) {
        blast(C, B, e->b);
        int *Bv = B->bits[e->b];
        carry = cir_c(1);
        for (su32 i = 0; i < w; i++) {
            int nb = smt_inv(Bv[i]);
            int x1 = cir_xor(B->k, A[i], nb);
            int c1 = cir_and(B->k, A[i], nb);
            int c2 = cir_and(B->k, x1, carry);
            out[i] = cir_xor(B->k, x1, carry);
            carry = cir_or(B->k, c1, c2);
        }
        return;
    }
    if (e->op == SM_NEG) {
        carry = cir_c(1);
        for (su32 i = 0; i < w; i++) {
            int nb = smt_inv(A[i]);
            int x1 = cir_xor(B->k, nb, carry);
            int c1 = cir_and(B->k, nb, carry);
            out[i] = x1;
            carry = c1;
        }
        return;
    }

    blast(C, B, e->b);
    int *Bv = B->bits[e->b];
    carry = cir_c(0);
    for (su32 i = 0; i < w; i++) {
        int x1 = cir_xor(B->k, A[i], Bv[i]);
        int c1 = cir_and(B->k, A[i], Bv[i]);
        out[i] = cir_xor(B->k, x1, carry);
        int c2 = cir_and(B->k, x1, carry);
        carry = cir_or(B->k, c1, c2);
    }
}

static void blast_mul(SmtCtx *C, Blaster *B, su32 id)
{
    SmtNode *e = &C->n[id];
    su32 w = e->w;
    int *out = bl_bits(B, id, w);
    blast(C, B, e->a);
    blast(C, B, e->b);
    int *A = B->bits[e->a];
    int *Bv = B->bits[e->b];

    for (su32 i = 0; i < w; i++) out[i] = cir_c(0);

    for (su32 i = 0; i < w; i++) {
        int carry = cir_c(0);
        for (su32 j = 0; i + j < w; j++) {
            int old = out[i + j];
            int p = cir_and(B->k, A[j], Bv[i]);
            int s1 = cir_xor(B->k, old, p);
            out[i + j] = cir_xor(B->k, s1, carry);
            int c1 = cir_and(B->k, old, p);
            int c2 = cir_and(B->k, old, carry);
            int c3 = cir_and(B->k, p, carry);
            carry = cir_or(B->k, c1, cir_or(B->k, c2, c3));
        }
    }
}

static void blast_shift(SmtCtx *C, Blaster *B, su32 id)
{
    SmtNode *e = &C->n[id];
    su32 w = e->w;
    int *out = bl_bits(B, id, w);
    blast(C, B, e->a);
    blast(C, B, e->b);
    int *A = B->bits[e->a];
    int *Bv = B->bits[e->b];

    int *cur = (int *)malloc(w * sizeof(int));
    for (su32 i = 0; i < w; i++) cur[i] = A[i];

    su32 sel_bits = 0;
    while ((1u << sel_bits) < w) sel_bits++;
    if (sel_bits == 0) sel_bits = 1;

    for (su32 k2 = 0; k2 < sel_bits; k2++) {
        su32 sh = 1u << k2;
        if (sh >= w) break;
        int sel = Bv[k2];
        if (sel == 1) continue;
        int *nxt = (int *)malloc(w * sizeof(int));
        for (su32 j = 0; j < w; j++) {
            int other;
            switch (e->op) {
            case SM_SHL:  other = (j >= sh) ? cur[j - sh] : cir_c(0); break;
            case SM_LSHR: other = (j + sh < w) ? cur[j + sh] : cir_c(0); break;
            case SM_ASHR: other = (j + sh < w) ? cur[j + sh] : cur[w - 1]; break;
            case SM_ROL:  other = cur[(j + w - (sh % w)) % w]; break;
            case SM_ROR:  other = cur[(j + sh) % w]; break;
            default:      other = cur[j]; break;
            }
            nxt[j] = cir_mux(B->k, sel, other, cur[j]);
        }
        memcpy(cur, nxt, w * sizeof(int));
        free(nxt);
    }

    if (e->op == SM_SHL || e->op == SM_LSHR || e->op == SM_ASHR) {
        int ovr = cir_c(0);
        for (su32 k2 = sel_bits; k2 < w; k2++) {
            int hb = (k2 < w) ? Bv[k2] : cir_c(0);
            ovr = cir_or(B->k, ovr, hb);
        }
        if (ovr != 1) {
            for (su32 j = 0; j < w; j++) {
                int fill = (e->op == SM_ASHR) ? A[w - 1] : cir_c(0);
                cur[j] = cir_mux(B->k, ovr, fill, cur[j]);
            }
        }
    }

    for (su32 i = 0; i < w; i++) out[i] = cur[i];
    free(cur);
}
static int blast_ult(SmtCtx *C, Blaster *B, su32 a_id, su32 b_id)
{
    su32 w = C->n[a_id].w;
    blast(C, B, a_id);
    blast(C, B, b_id);
    int *A = B->bits[a_id];
    int *Bv = B->bits[b_id];
    int carry = cir_c(1);
    for (su32 i = 0; i < w; i++) {
        int nb = smt_inv(Bv[i]);
        int x1 = cir_xor(B->k, A[i], nb);
        int c1 = cir_and(B->k, A[i], nb);
        int c2 = cir_and(B->k, x1, carry);
        carry = cir_or(B->k, c1, c2);
    }
    return smt_inv(carry);
}

static int blast_slt(SmtCtx *C, Blaster *B, su32 a_id, su32 b_id)
{
    su32 w = C->n[a_id].w;
    blast(C, B, a_id);
    blast(C, B, b_id);
    int *A = B->bits[a_id];
    int *Bv = B->bits[b_id];
    int ult = blast_ult(C, B, a_id, b_id);
    int sign_diff = cir_xor(B->k, A[w - 1], Bv[w - 1]);
    return cir_mux(B->k, sign_diff, A[w - 1], ult);
}

static void blast_bits(SmtCtx *C, Blaster *B, su32 id)
{
    SmtNode *e = &C->n[id];
    su32 w = e->w;
    int *out = bl_bits(B, id, w);
    blast(C, B, e->a);
    blast(C, B, e->b);
    int *A = B->bits[e->a];
    int *Bv = B->bits[e->b];

    switch (e->op) {
    case SM_AND:
        for (su32 i = 0; i < w; i++) out[i] = cir_and(B->k, A[i], Bv[i]);
        break;
    case SM_OR:
        for (su32 i = 0; i < w; i++) out[i] = cir_or(B->k, A[i], Bv[i]);
        break;
    case SM_XOR:
        for (su32 i = 0; i < w; i++) out[i] = cir_xor(B->k, A[i], Bv[i]);
        break;
    case SM_EQ: {
        su32 cw = C->n[e->a].w;
        int acc = cir_c(1);
        for (su32 i = 0; i < cw; i++) {
            int eqi = cir_xor(B->k, cir_xor(B->k, A[i], Bv[i]), cir_c(1));
            acc = cir_and(B->k, acc, eqi);
        }
        out[0] = acc;
        break;
    }
    case SM_ULT:
        out[0] = blast_ult(C, B, e->a, e->b);
        break;
    case SM_ULE:
        out[0] = smt_inv(blast_ult(C, B, e->b, e->a));
        break;
    case SM_UGT:
        out[0] = blast_ult(C, B, e->b, e->a);
        break;
    case SM_UGE:
        out[0] = smt_inv(blast_ult(C, B, e->a, e->b));
        break;
    case SM_SLT:
        out[0] = blast_slt(C, B, e->a, e->b);
        break;
    case SM_SLE:
        out[0] = smt_inv(blast_slt(C, B, e->b, e->a));
        break;
    case SM_SGT:
        out[0] = blast_slt(C, B, e->b, e->a);
        break;
    case SM_SGE:
        out[0] = smt_inv(blast_slt(C, B, e->a, e->b));
        break;
    case SM_LAND:
        out[0] = cir_and(B->k, A[0], Bv[0]);
        break;
    case SM_LOR:
        out[0] = cir_or(B->k, A[0], Bv[0]);
        break;
    case SM_LXOR:
        out[0] = cir_xor(B->k, A[0], Bv[0]);
        break;
    default:
        for (su32 i = 0; i < w; i++) out[i] = cir_c(0);
        break;
    }
}

static void blast(SmtCtx *C, Blaster *B, su32 id)
{
    SmtNode *e = &C->n[id];
    su32 w = e->w;
    if (id < B->bits_cap && B->bits[id]) {
        int *bt = B->bits[id];
        int ready = 1;
        for (su32 i = 0; i < w; i++)
            if (bt[i] == -1) { ready = 0; break; }
        if (ready) return;
    }
    int *out = bl_bits(B, id, w);

    switch (e->op) {    case SM_CONST:
        for (su32 i = 0; i < w; i++)
            out[i] = ((e->val >> i) & 1) ? 0 : 1;
        break;
    case SM_VAR:
        for (su32 i = 0; i < w; i++)
            out[i] = cir_var(B->k) * 2;
        break;
    case SM_NOT: {
        blast(C, B, e->a);
        int *A = B->bits[e->a];
        for (su32 i = 0; i < w; i++) out[i] = smt_inv(A[i]);
        break;
    }
    case SM_EXTRACT: {
        blast(C, B, e->a);
        int *A = B->bits[e->a];
        su32 low = (su32)e->val;
        for (su32 i = 0; i < w; i++) out[i] = A[low + i];
        break;
    }
    case SM_ZEXT: {
        blast(C, B, e->a);
        int *A = B->bits[e->a];
        su32 sw = C->n[e->a].w;
        for (su32 i = 0; i < sw; i++) out[i] = A[i];
        for (su32 i = sw; i < w; i++) out[i] = cir_c(0);
        break;
    }
    case SM_SEXT: {
        blast(C, B, e->a);
        int *A = B->bits[e->a];
        su32 sw = C->n[e->a].w;
        for (su32 i = 0; i < sw; i++) out[i] = A[i];
        for (su32 i = sw; i < w; i++) out[i] = A[sw - 1];
        break;
    }
    case SM_CONCAT: {
        blast(C, B, e->a);
        blast(C, B, e->b);
        int *A = B->bits[e->a];
        int *Bv = B->bits[e->b];
        su32 lw = C->n[e->b].w;
        for (su32 i = 0; i < lw; i++) out[i] = Bv[i];
        for (su32 i = lw; i < w; i++) out[i] = A[i - lw];
        break;
    }
    case SM_ITE: {
        su32 then_id = (su32)e->val;
        su32 else_id = e->b;
        blast(C, B, e->a);
        blast(C, B, then_id);
        blast(C, B, else_id);
        int *Cd = B->bits[e->a];
        int *T = B->bits[then_id];
        int *E = B->bits[else_id];
        for (su32 i = 0; i < w; i++)
            out[i] = cir_mux(B->k, Cd[0], T[i], E[i]);
        break;
    }
    case SM_LNOT: {
        blast(C, B, e->a);
        int *A = B->bits[e->a];
        out[0] = smt_inv(A[0]);
        break;
    }
    case SM_ADD: case SM_SUB: case SM_NEG:
        blast_adder(C, B, id);
        break;
    case SM_MUL:
        blast_mul(C, B, id);
        break;
    case SM_SHL: case SM_LSHR: case SM_ASHR: case SM_ROL: case SM_ROR:
        blast_shift(C, B, id);
        break;
    default:
        blast_bits(C, B, id);
        break;
    }
}

static void blaster_free(Blaster *B)
{
    for (su32 i = 0; i < B->bits_cap; i++) free(B->bits[i]);
    free(B->bits);
}

typedef struct {
    Circuit *k;
    signed char *assign;
    int *level;
    int *reason;
    int *trail;
    int trail_n, trail_cap;
    int *trail_lim;
    int trail_lim_n, trail_lim_cap;
    double *activity;
    double var_inc;
    int *heap;
    int heap_n;
    signed char *phase;
    int **watches;
    int *watch_n, *watch_cap;
    int qhead;
    int conflicts;
    int *scratch;
    int scratch_cap;
} Sat;

static int sat_val(Sat *S, int lit)
{
    int v = lit >> 1;
    signed char a = S->assign[v];
    if (a == 0) return 0;
    return (lit & 1) ? -a : a;
}

static void sat_watch_push(Sat *S, int lit, int cl)
{
    if (S->watch_n[lit] >= S->watch_cap[lit]) {
        S->watch_cap[lit] = S->watch_cap[lit] ? S->watch_cap[lit] * 2 : 4;
        S->watches[lit] = (int *)realloc(S->watches[lit],
                                         (size_t)S->watch_cap[lit] * sizeof(int));
        if (!S->watches[lit]) abort();
    }
    S->watches[lit][S->watch_n[lit]++] = cl;
}

static void sat_enqueue(Sat *S, int lit, int reason_cl);

static int sat_attach(Sat *S, int cl)
{
    Circuit *k = S->k;
    int *c = k->arena + k->off[cl];
    int n = k->len[cl];
    int w = 0;
    for (int i = 0; i < n && w < 2; i++) {
        if (sat_val(S, c[i]) != -1) {
            int t = c[w]; c[w] = c[i]; c[i] = t;
            w++;
        }
    }
    if (w == 0) return 1;
    if (w == 1) {
        sat_enqueue(S, c[0], cl);
        return 0;
    }
    sat_watch_push(S, c[0], cl);
    sat_watch_push(S, c[1], cl);
    return 0;
}

static void sat_enqueue(Sat *S, int lit, int reason_cl)
{
    int v = lit >> 1;
    S->assign[v] = (lit & 1) ? -1 : 1;
    S->phase[v] = (lit & 1) ? -1 : 1;
    S->level[v] = S->trail_lim_n;
    S->reason[v] = reason_cl;
    if (S->trail_n >= S->trail_cap) {
        S->trail_cap *= 2;
        S->trail = (int *)realloc(S->trail, (size_t)S->trail_cap * sizeof(int));
        if (!S->trail) abort();
    }
    S->trail[S->trail_n++] = lit;
}

static void sat_heap_swim(Sat *S, int i)
{
    int v = S->heap[i];
    double key = S->activity[v];
    while (i > 0) {
        int p = (i - 1) / 2;
        if (S->activity[S->heap[p]] >= key) break;
        S->heap[i] = S->heap[p];
        i = p;
    }
    S->heap[i] = v;
}

static void sat_heap_sink(Sat *S, int i)
{
    int v = S->heap[i];
    double key = S->activity[v];
    for (;;) {
        int l = 2 * i + 1, r = 2 * i + 2;
        if (l >= S->heap_n) break;
        int b = l;
        if (r < S->heap_n && S->activity[S->heap[r]] > S->activity[S->heap[l]]) b = r;
        if (S->activity[S->heap[b]] <= key) break;
        S->heap[i] = S->heap[b];
        i = b;
    }
    S->heap[i] = v;
}

static void sat_heap_insert(Sat *S, int v)
{
    for (int i = 0; i < S->heap_n; i++)
        if (S->heap[i] == v) return;
    if (S->heap_n >= S->k->nvars + 1) return;
    S->heap[S->heap_n++] = v;
    sat_heap_swim(S, S->heap_n - 1);
}

static void sat_bump(Sat *S, int v)
{
    S->activity[v] += S->var_inc;
    if (S->activity[v] > 1e100) {
        for (int i = 1; i < S->k->nvars; i++) S->activity[i] *= 1e-100;
        S->var_inc *= 1e-100;
    }
    int i = -1;
    for (int j = 0; j < S->heap_n; j++)
        if (S->heap[j] == v) { i = j; break; }
    if (i >= 0) {
        sat_heap_swim(S, i);
        sat_heap_sink(S, i);
    }
}

static void sat_decay(Sat *S)
{
    S->var_inc /= 0.95;
}

static int sat_propagate(Sat *S)
{
    Circuit *k = S->k;
    while (S->qhead < S->trail_n) {
        int p = S->trail[S->qhead++];
        int neg = p ^ 1;
        if (S->watch_n[neg] == 0) continue;

        int wn = S->watch_n[neg];
        if (wn > S->scratch_cap) {
            S->scratch_cap = wn * 2;
            S->scratch = (int *)realloc(S->scratch, (size_t)S->scratch_cap * sizeof(int));
            if (!S->scratch) abort();
        }
        int *wl = S->scratch;
        memcpy(wl, S->watches[neg], (size_t)wn * sizeof(int));
        S->watch_n[neg] = 0;

        int conflict = -1;
        for (int i = 0; i < wn; i++) {
            int cl = wl[i];
            int *c = k->arena + k->off[cl];
            if (c[0] == neg) { int t = c[0]; c[0] = c[1]; c[1] = t; }
            int v0 = sat_val(S, c[0]);
            if (v0 == 1) {
                sat_watch_push(S, neg, cl);
                continue;
            }
            int found = 0;
            for (int j = 2; j < k->len[cl]; j++) {
                if (sat_val(S, c[j]) != -1) {
                    int t = c[1];
                    c[1] = c[j];
                    c[j] = t;
                    sat_watch_push(S, c[1], cl);
                    found = 1;
                    break;
                }
            }
            if (found) {
                if (v0 == -1 && sat_val(S, c[1]) == 0) {
                    sat_enqueue(S, c[1], cl);
                    int t2 = c[0]; c[0] = c[1]; c[1] = t2;
                }
                continue;
            }
            sat_watch_push(S, neg, cl);
            if (v0 == 0) {
                sat_enqueue(S, c[0], cl);
            } else {
                conflict = cl;
                for (int j = i + 1; j < wn; j++)
                    sat_watch_push(S, neg, wl[j]);
                break;
            }
        }
        if (conflict >= 0) {
            S->conflicts++;
            return conflict;
        }
    }
    return -1;
}

static void sat_backtrack(Sat *S, int lvl)
{
    if (S->trail_lim_n <= lvl) return;
    int lim = S->trail_lim[lvl];
    for (int i = S->trail_n - 1; i >= lim; i--) {
        int v = S->trail[i] >> 1;
        S->assign[v] = 0;
        S->reason[v] = -1;
        if (v != 0) sat_heap_insert(S, v);
    }
    S->trail_n = lim;
    S->trail_lim_n = lvl;
    S->qhead = lim;
}

static void sat_analyze(Sat *S, int confl, int *learnt, int *learnt_n, int *btlevel)
{
    Circuit *k = S->k;
    int cur_level = S->trail_lim_n;
    char *seen = (char *)calloc((size_t)k->nvars, 1);
    int pathC = 0;
    int p = -1;
    int idx = S->trail_n - 1;
    int cap = k->nvars + 2;
    int *tmp = (int *)malloc((size_t)cap * sizeof(int));
    int tmp_n = 0;

    do {
        int cl = (p == -1) ? confl : S->reason[p >> 1];
        int *c = k->arena + k->off[cl];
        int clen = k->len[cl];
        int start = (p == -1) ? 0 : 1;
        for (int i = start; i < clen; i++) {
            int q = c[i];
            int v = q >> 1;
            if (!seen[v] && S->level[v] > 0) {
                seen[v] = 1;
                sat_bump(S, v);
                if (S->level[v] >= cur_level) pathC++;
                else if (tmp_n < cap) tmp[tmp_n++] = q;
            }
        }
        while (!seen[S->trail[idx] >> 1]) idx--;
        p = S->trail[idx];
        idx--;
        seen[p >> 1] = 0;
        pathC--;
    } while (pathC > 0);

    learnt[0] = p ^ 1;
    *learnt_n = tmp_n + 1;
    for (int i = 0; i < tmp_n; i++) learnt[1 + i] = tmp[i];
    int maxl = 0;
    for (int i = 1; i < *learnt_n; i++) {
        int v = learnt[i] >> 1;
        if (S->level[v] > maxl) maxl = S->level[v];
    }
    *btlevel = maxl;
    free(seen);
    free(tmp);
}

static void sat_add_learnt(Sat *S, int *lits, int n, int btlevel)
{
    Circuit *k = S->k;
    int best = 1;
    for (int i = 2; i < n; i++)
        if (S->level[lits[i] >> 1] > S->level[lits[best] >> 1]) best = i;
    if (best != 1) { int t = lits[1]; lits[1] = lits[best]; lits[best] = t; }
    int start = k->arena_n;
    for (int i = 0; i < n; i++) cir_push_lit(k, lits[i]);
    cir_end_clause(k, start);
    int cl = k->cl_n - 1;
    sat_backtrack(S, btlevel);
    sat_attach(S, cl);
    if (S->assign[lits[0] >> 1] == 0) sat_enqueue(S, lits[0], cl);
}

static int sat_decide(Sat *S)
{
    while (S->heap_n > 0) {
        int v = S->heap[0];
        S->heap[0] = S->heap[--S->heap_n];
        sat_heap_sink(S, 0);
        if (S->assign[v] == 0) {
            if (S->trail_lim_cap <= S->trail_lim_n) {
                S->trail_lim_cap = S->trail_lim_cap ? S->trail_lim_cap * 2 : 64;
                S->trail_lim = (int *)realloc(S->trail_lim,
                                              (size_t)S->trail_lim_cap * sizeof(int));
                if (!S->trail_lim) abort();
            }
            S->trail_lim[S->trail_lim_n++] = S->trail_n;
            int lit = (S->phase[v] >= 0) ? (v << 1) : (v << 1 | 1);
            sat_enqueue(S, lit, -1);
            return 1;
        }
    }
    for (int v = 1; v < S->k->nvars; v++) {
        if (S->assign[v] == 0) {
            sat_heap_insert(S, v);
            return sat_decide(S);
        }
    }
    return 0;
}

static int sat_search(Sat *S)
{
    Circuit *k = S->k;
    int *learnt = (int *)malloc((size_t)(k->nvars + 2) * sizeof(int));
    if (!learnt) abort();
    double restart_limit = 100;
    int since_restart = 0;

    for (;;) {
        int confl = sat_propagate(S);
        if (confl >= 0) {
            sat_decay(S);
            since_restart++;
            if (S->trail_lim_n == 0) { free(learnt); return 0; }
            int ln = 0, btl = 0;
            sat_analyze(S, confl, learnt, &ln, &btl);
            if (ln == 1) {
                sat_backtrack(S, 0);
                int start = k->arena_n;
                cir_push_lit(k, learnt[0]);
                cir_end_clause(k, start);
                sat_enqueue(S, learnt[0], k->cl_n - 1);
            } else {
                sat_add_learnt(S, learnt, ln, btl);
            }
            if (since_restart >= (int)restart_limit) {
                restart_limit *= 1.5;
                since_restart = 0;
                sat_backtrack(S, 0);
            }
        } else {
            if (!sat_decide(S)) { free(learnt); return 1; }
        }
    }
}

int smt_solve(SmtCtx *C, const su32 *asserts, su32 n_asserts,
              const su32 *vars, su32 n_vars, su64 *out_model)
{
    su32 const_only = 1;
    for (su32 i = 0; i < n_asserts; i++)
        if (smt_has_var(C, asserts[i])) { const_only = 0; break; }

    if (const_only) {
        int ok = 1;
        for (su32 i = 0; i < n_asserts; i++) {
            su64 v = 0;
            if (!smt_eval_rec(C, asserts[i], NULL, &v) || !v) { ok = 0; break; }
        }
        if (ok && out_model)
            for (su32 i = 0; i < n_vars; i++) out_model[i] = 0;
        return ok ? 1 : 0;
    }

    Circuit k;
    cir_init(&k, C->nvars + 1);
    k.nvars = C->nvars + 1;
    cir_push_lit(&k, 0);
    cir_end_clause(&k, k.arena_n - 1);

    Blaster B;
    memset(&B, 0, sizeof(B));
    B.k = &k;

    int **var_bits = (int **)malloc((n_vars ? n_vars : 1) * sizeof(int *));

    for (su32 i = 0; i < n_asserts; i++) {
        su32 a = asserts[i];
        SmtNode *e = &C->n[a];
        blast(C, &B, a);
        int *bt = B.bits[a];
        if (e->w == 1) {
            cir_push_lit(&k, bt[0]);
            cir_end_clause(&k, k.arena_n - 1);
        } else {
            int start = k.arena_n;
            for (su32 j = 0; j < e->w; j++) cir_push_lit(&k, bt[j]);
            cir_end_clause(&k, start);
        }
    }

    for (su32 i = 0; i < n_vars; i++) {
        blast(C, &B, vars[i]);
        var_bits[i] = B.bits[vars[i]];
    }

    Sat S;
    memset(&S, 0, sizeof(S));
    S.k = &k;
    S.assign = (signed char *)calloc((size_t)k.nvars, 1);
    S.level = (int *)calloc((size_t)k.nvars, sizeof(int));
    S.reason = (int *)malloc((size_t)k.nvars * sizeof(int));
    for (int i = 0; i < k.nvars; i++) S.reason[i] = -1;
    S.trail_cap = k.nvars + 8;
    S.trail = (int *)malloc((size_t)S.trail_cap * sizeof(int));
    S.trail_lim_cap = 64;
    S.trail_lim = (int *)malloc((size_t)S.trail_lim_cap * sizeof(int));
    S.activity = (double *)calloc((size_t)k.nvars, sizeof(double));
    S.heap = (int *)malloc((size_t)(k.nvars + 1) * sizeof(int));
    S.phase = (signed char *)calloc((size_t)k.nvars, 1);
    S.var_inc = 1.0;
    for (int i = 0; i < k.nvars; i++) S.phase[i] = -1;

    if (k.nvars <= 0 || k.nvars > (1 << 24)) return 2;

    int nlits = 2 * k.nvars;
    S.watches = (int **)calloc((size_t)nlits, sizeof(int *));
    S.watch_n = (int *)calloc((size_t)nlits, sizeof(int));
    S.watch_cap = (int *)calloc((size_t)nlits, sizeof(int));

    for (int i = 1; i < k.nvars; i++) S.heap[S.heap_n++] = i;
    for (int i = k.nvars / 2; i >= 1; i--) {
        int j = i;
        int v = S.heap[j];
        double key = S.activity[v];
        for (;;) {
            int l = 2 * j + 1, r = 2 * j + 2;
            if (l >= S.heap_n) break;
            int b = l;
            if (r < S.heap_n && S.activity[S.heap[r]] > S.activity[S.heap[l]]) b = r;
            if (S.activity[S.heap[b]] <= key) break;
            S.heap[j] = S.heap[b];
            j = b;
        }
        S.heap[j] = v;
    }

    int early_unsat = 0;
    for (int c = 0; c < k.cl_n; c++) {
        if (k.len[c] == 1) {
            int lit = k.arena[k.off[c]];
            int v = sat_val(&S, lit);
            if (v == -1) { early_unsat = 1; break; }
            if (v == 0) sat_enqueue(&S, lit, -1);
        }
    }
    if (!early_unsat)
        for (int c = 0; c < k.cl_n; c++)
            if (k.len[c] >= 2 && sat_attach(&S, c)) { early_unsat = 1; break; }

    int res = early_unsat ? 0 : sat_search(&S);

    if (res == 1) {
        su64 *var_model = (su64 *)calloc((size_t)C->nvars + 1, sizeof(su64));
        if (var_model) {
            for (su32 n = 0; n < C->count; n++) {
                SmtNode *vn = &C->n[n];
                if (vn->op != SM_VAR) continue;
                int *bt = B.bits[n];
                if (!bt) continue;
                su64 val = 0;
                for (su32 j = 0; j < vn->w; j++) {
                    int v = bt[j] >> 1;
                    if (v < k.nvars && S.assign[v] == 1) val |= (1ULL << j);
                }
                var_model[vn->var_id] = val;
            }
            for (su32 i = 0; i < n_asserts; i++) {
                su64 out = 0;
                if (!smt_eval_rec(C, asserts[i], var_model, &out) || !out) {
                    res = -1;
                    break;
                }
            }
            if (res == 1) {
                for (su32 i = 0; i < n_vars; i++) {
                    SmtNode *vn = &C->n[vars[i]];
                    if (out_model) out_model[i] = var_model[vn->var_id];
                }
            }
        } else {
            res = -1;
        }
        free(var_model);
    }

    free(S.assign);
    free(S.level);
    free(S.reason);
    free(S.trail);
    free(S.trail_lim);
    free(S.activity);
    free(S.heap);
    free(S.phase);
    free(S.scratch);
    for (int i = 0; i < nlits; i++) free(S.watches[i]);
    free(S.watches);
    free(S.watch_n);
    free(S.watch_cap);
    free(var_bits);
    blaster_free(&B);
    cir_free(&k);
    return res;
}

void smt_print_smt2(SmtCtx *C, su32 id, FILE *f)
{
    SmtNode *e = &C->n[id];
    switch (e->op) {
    case SM_CONST:
        fprintf(f, "(_ bv%llu %u)", (unsigned long long)e->val, (unsigned)e->w);
        break;
    case SM_VAR:
        fprintf(f, "v%u", (unsigned)e->var_id);
        break;
    case SM_NOT: fputs("(bvnot ", f); smt_print_smt2(C, e->a, f); fputs(")", f); break;
    case SM_NEG: fputs("(bvneg ", f); smt_print_smt2(C, e->a, f); fputs(")", f); break;
    case SM_ZEXT:
        fprintf(f, "((_ zero_extend %u) ", (unsigned)(e->w - C->n[e->a].w));
        smt_print_smt2(C, e->a, f);
        fputs(")", f);
        break;
    case SM_SEXT:
        fprintf(f, "((_ sign_extend %u) ", (unsigned)(e->w - C->n[e->a].w));
        smt_print_smt2(C, e->a, f);
        fputs(")", f);
        break;
    case SM_EXTRACT:
        fprintf(f, "((_ extract %u %u) ", (unsigned)(e->val + e->w - 1), (unsigned)e->val);
        smt_print_smt2(C, e->a, f);
        fputs(")", f);
        break;
    case SM_CONCAT:
        fputs("(concat ", f);
        smt_print_smt2(C, e->a, f);
        fputs(" ", f);
        smt_print_smt2(C, e->b, f);
        fputs(")", f);
        break;
    case SM_ITE:
        fputs("(ite ", f);
        smt_print_smt2(C, e->a, f);
        fputs(" ", f);
        smt_print_smt2(C, (su32)e->val, f);
        fputs(" ", f);
        smt_print_smt2(C, e->b, f);
        fputs(")", f);
        break;
    case SM_LAND: fputs("(and ", f); smt_print_smt2(C, e->a, f); fputs(" ", f); smt_print_smt2(C, e->b, f); fputs(")", f); break;
    case SM_LOR:  fputs("(or ", f);  smt_print_smt2(C, e->a, f); fputs(" ", f); smt_print_smt2(C, e->b, f); fputs(")", f); break;
    case SM_LXOR: fputs("(xor ", f); smt_print_smt2(C, e->a, f); fputs(" ", f); smt_print_smt2(C, e->b, f); fputs(")", f); break;
    case SM_LNOT: fputs("(not ", f); smt_print_smt2(C, e->a, f); fputs(")", f); break;
    default: {
        static const char *names[] = {
            "?", "?", "bvadd", "bvsub", "bvmul", "bvand", "bvor", "bvxor",
            "?", "?", "bvshl", "bvlshr", "bvashr", "bvrol", "bvror",
            "?", "?", "?", "?", "?",
            "=", "bvult", "bvule", "bvugt", "bvuge", "bvslt", "bvsle", "bvsgt", "bvsge"
        };
        const char *nm = (e->op < sizeof(names) / sizeof(names[0])) ? names[e->op] : "?";
        fputs("(", f);
        fputs(nm, f);
        fputs(" ", f);
        smt_print_smt2(C, e->a, f);
        if (e->b != SM_NONE) {
            fputs(" ", f);
            smt_print_smt2(C, e->b, f);
        }
        fputs(")", f);
        break;
    }
    }
}

const char *sm_op_name(int op)
{
    switch (op) {
    case SM_CONST: return "const";
    case SM_VAR: return "var";
    case SM_ADD: return "+";
    case SM_SUB: return "-";
    case SM_MUL: return "*";
    case SM_AND: return "&";
    case SM_OR: return "|";
    case SM_XOR: return "^";
    case SM_NOT: return "~";
    case SM_NEG: return "neg";
    case SM_SHL: return "<<";
    case SM_LSHR: return ">>";
    case SM_ASHR: return ">>a";
    case SM_ROL: return "rotl";
    case SM_ROR: return "rotr";
    case SM_ZEXT: return "zext";
    case SM_SEXT: return "sext";
    case SM_EXTRACT: return "extract";
    case SM_CONCAT: return "concat";
    case SM_ITE: return "ite";
    case SM_EQ: return "==";
    case SM_ULT: return "<u";
    case SM_ULE: return "<=u";
    case SM_UGT: return ">u";
    case SM_UGE: return ">=u";
    case SM_SLT: return "<s";
    case SM_SLE: return "<=s";
    case SM_SGT: return ">s";
    case SM_SGE: return ">=s";
    case SM_LAND: return "&&";
    case SM_LOR: return "||";
    case SM_LXOR: return "lxor";
    case SM_LNOT: return "!";
    default: return "?";
    }
}
