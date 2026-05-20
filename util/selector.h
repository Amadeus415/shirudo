/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * --selector label-expression parser and evaluator.
 *
 * Grammar:
 *   expr ::= term ('||' term)*
 *   term ::= atom ('&&' atom)*
 *   atom ::= key ('=' value | '!=' value
 *                 | <existence> | '!' <existence>)
 *          | '(' expr ')'
 */

#ifndef SHIRUDO_SELECTOR_H
#define SHIRUDO_SELECTOR_H

#include <stdbool.h>

struct shirudo_selector;
struct shirudo_labels;	/* {key -> value} map; provided by util/remotes.c */

struct shirudo_selector *shirudo_selector_parse(const char *expr);
bool shirudo_selector_match(const struct shirudo_selector *s,
			    const struct shirudo_labels *labels);
void shirudo_selector_free(struct shirudo_selector *s);

#endif /* SHIRUDO_SELECTOR_H */
