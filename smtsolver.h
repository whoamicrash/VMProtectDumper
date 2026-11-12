#ifndef SMTSOLVER_H
#define SMTSOLVER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef long long ts64;

typedef unsigned char      su8;
typedef unsigned short     su16;
typedef unsigned int       su32;
typedef unsigned long long su64;

enum {
    SM_CONST = 0, SM_VAR, SM_ADD, SM_SUB, SM_MUL, SM_AND, SM_OR, SM_XOR,
    SM_NOT, SM_NEG, SM_SHL, SM_LSHR, SM_ASHR, SM_ROL, SM_ROR,
    SM_ZEXT, SM_SEXT, SM_EXTRACT, SM_CONCAT, SM_ITE,
    SM_EQ, SM_ULT, SM_ULE, SM_UGT, SM_UGE, SM_SLT, SM_SLE, SM_SGT, SM_SGE,
    SM_LAND, SM_LOR, SM_LXOR, SM_LNOT
};

typedef struct {
    su8  op;
    su8  w;
    su32 a;
    su32 b;
    su64 val;
    su32 var_id;
} SmtNode;

typedef struct {
    SmtNode *n;
    su32     count;
    su32     cap;
    su32     nvars;
} SmtCtx;

#define SM_NONE 0xFFFFFFFFu

void smt_init(SmtCtx *C);
void smt_free(SmtCtx *C);
su32 smt_const(SmtCtx *C, su32 w, su64 v);
su32 smt_var(SmtCtx *C, su32 w);
su32 smt_bin(SmtCtx *C, int op, su32 a, su32 b);
su32 smt_un(SmtCtx *C, int op, su32 a);
su32 smt_extract(SmtCtx *C, su32 a, su32 low, su32 w);
su32 smt_concat(SmtCtx *C, su32 hi, su32 lo);
su32 smt_ite(SmtCtx *C, su32 cond, su32 t, su32 e);
su32 smt_zext(SmtCtx *C, su32 a, su32 w);
su32 smt_sext(SmtCtx *C, su32 a, su32 w);
su32 smt_lnot(SmtCtx *C, su32 a);
int  smt_is_const(SmtCtx *C, su32 id, su64 *out);
int  smt_has_var(SmtCtx *C, su32 id);
int  smt_eval(SmtCtx *C, su32 id, const su64 *model, su64 *out);
void smt_print_smt2(SmtCtx *C, su32 id, FILE *f);

int  smt_solve(SmtCtx *C, const su32 *asserts, su32 n_asserts,
               const su32 *vars, su32 n_vars, su64 *out_model);

const char *sm_op_name(int op);

#endif
