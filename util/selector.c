// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * --selector label-expression parser and evaluator. Grammar:
 *   expr ::= term ('||' term)*
 *   term ::= atom ('&&' atom)*
 *   atom ::= '(' expr ')'
 *          | '!' key                     (non-existence)
 *          | key                         (existence)
 *          | key '=' value               (equality)
 *          | key '!=' value              (inequality; true if absent)
 * '&&' binds tighter than '||'.
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "remotes.h"
#include "selector.h"

enum node_op { OP_OR, OP_AND, OP_EQ, OP_NE, OP_EXISTS, OP_NEXISTS };

struct shirudo_selector {
	enum node_op		op;
	struct shirudo_selector	*l, *r;	/* OR/AND */
	char			*key;	/* leaf */
	char			*val;	/* EQ/NE */
};

/* ---- lexer ---- */
enum tok { T_KEY, T_EQ, T_NE, T_NOT, T_AND, T_OR, T_LP, T_RP, T_END, T_ERR };

struct lexer {
	const char	*p;
	enum tok	tok;
	char		text[256];	/* current T_KEY */
};

static int is_keychar(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	       (c >= '0' && c <= '9') ||
	       c == '.' || c == '-' || c == '_' || c == '/' || c == ':';
}

static void lex(struct lexer *lx)
{
	const char *p = lx->p;

	while (*p == ' ' || *p == '\t')
		p++;
	if (*p == '\0') {
		lx->tok = T_END;
		lx->p = p;
		return;
	}
	if (p[0] == '&' && p[1] == '&') {
		lx->tok = T_AND; lx->p = p + 2; return;
	}
	if (p[0] == '|' && p[1] == '|') {
		lx->tok = T_OR; lx->p = p + 2; return;
	}
	if (p[0] == '!' && p[1] == '=') {
		lx->tok = T_NE; lx->p = p + 2; return;
	}
	if (*p == '!') { lx->tok = T_NOT; lx->p = p + 1; return; }
	if (*p == '=') { lx->tok = T_EQ; lx->p = p + 1; return; }
	if (*p == '(') { lx->tok = T_LP; lx->p = p + 1; return; }
	if (*p == ')') { lx->tok = T_RP; lx->p = p + 1; return; }
	if (is_keychar(*p)) {
		size_t n = 0;

		while (is_keychar(*p) && n < sizeof(lx->text) - 1)
			lx->text[n++] = *p++;
		lx->text[n] = '\0';
		lx->tok = T_KEY;
		lx->p = p;
		return;
	}
	lx->tok = T_ERR;
	lx->p = p;
}

/* ---- parser ---- */
static struct shirudo_selector *parse_expr(struct lexer *lx);

static struct shirudo_selector *leaf(enum node_op op, const char *k,
				     const char *v)
{
	struct shirudo_selector *n = calloc(1, sizeof(*n));

	if (!n)
		return NULL;
	n->op = op;
	n->key = strdup(k);
	if (v)
		n->val = strdup(v);
	if (!n->key || (v && !n->val)) {
		shirudo_selector_free(n);
		return NULL;
	}
	return n;
}

static struct shirudo_selector *node2(enum node_op op,
				      struct shirudo_selector *l,
				      struct shirudo_selector *r)
{
	struct shirudo_selector *n = calloc(1, sizeof(*n));

	if (!n) {
		shirudo_selector_free(l);
		shirudo_selector_free(r);
		return NULL;
	}
	n->op = op;
	n->l = l;
	n->r = r;
	return n;
}

static struct shirudo_selector *parse_atom(struct lexer *lx)
{
	struct shirudo_selector *n;
	char key[256];

	if (lx->tok == T_LP) {
		lex(lx);
		n = parse_expr(lx);
		if (!n)
			return NULL;
		if (lx->tok != T_RP) {
			shirudo_selector_free(n);
			return NULL;
		}
		lex(lx);
		return n;
	}
	if (lx->tok == T_NOT) {
		lex(lx);
		if (lx->tok != T_KEY)
			return NULL;
		n = leaf(OP_NEXISTS, lx->text, NULL);
		lex(lx);
		return n;
	}
	if (lx->tok != T_KEY)
		return NULL;
	strncpy(key, lx->text, sizeof(key) - 1);
	key[sizeof(key) - 1] = '\0';
	lex(lx);
	if (lx->tok == T_EQ) {
		lex(lx);
		if (lx->tok != T_KEY)
			return NULL;
		n = leaf(OP_EQ, key, lx->text);
		lex(lx);
		return n;
	}
	if (lx->tok == T_NE) {
		lex(lx);
		if (lx->tok != T_KEY)
			return NULL;
		n = leaf(OP_NE, key, lx->text);
		lex(lx);
		return n;
	}
	return leaf(OP_EXISTS, key, NULL);
}

static struct shirudo_selector *parse_term(struct lexer *lx)
{
	struct shirudo_selector *l = parse_atom(lx);

	while (l && lx->tok == T_AND) {
		struct shirudo_selector *r;

		lex(lx);
		r = parse_atom(lx);
		if (!r) {
			shirudo_selector_free(l);
			return NULL;
		}
		l = node2(OP_AND, l, r);
	}
	return l;
}

static struct shirudo_selector *parse_expr(struct lexer *lx)
{
	struct shirudo_selector *l = parse_term(lx);

	while (l && lx->tok == T_OR) {
		struct shirudo_selector *r;

		lex(lx);
		r = parse_term(lx);
		if (!r) {
			shirudo_selector_free(l);
			return NULL;
		}
		l = node2(OP_OR, l, r);
	}
	return l;
}

struct shirudo_selector *shirudo_selector_parse(const char *expr)
{
	struct lexer lx = { .p = expr };
	struct shirudo_selector *n;

	if (!expr || !*expr)
		return NULL;
	lex(&lx);
	n = parse_expr(&lx);
	if (!n)
		return NULL;
	if (lx.tok != T_END) {		/* trailing garbage */
		shirudo_selector_free(n);
		return NULL;
	}
	return n;
}

bool shirudo_selector_match(const struct shirudo_selector *s,
			    const struct shirudo_labels *labels)
{
	const char *v;

	switch (s->op) {
	case OP_OR:
		return shirudo_selector_match(s->l, labels) ||
		       shirudo_selector_match(s->r, labels);
	case OP_AND:
		return shirudo_selector_match(s->l, labels) &&
		       shirudo_selector_match(s->r, labels);
	case OP_EQ:
		v = shirudo_labels_get(labels, s->key);
		return v && strcmp(v, s->val) == 0;
	case OP_NE:
		v = shirudo_labels_get(labels, s->key);
		return !v || strcmp(v, s->val) != 0;
	case OP_EXISTS:
		return shirudo_labels_get(labels, s->key) != NULL;
	case OP_NEXISTS:
		return shirudo_labels_get(labels, s->key) == NULL;
	}
	return false;
}

void shirudo_selector_free(struct shirudo_selector *s)
{
	if (!s)
		return;
	shirudo_selector_free(s->l);
	shirudo_selector_free(s->r);
	free(s->key);
	free(s->val);
	free(s);
}
