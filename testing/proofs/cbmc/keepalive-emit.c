// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * keepalive_emit() of util/keepalive.c for three bodies, each ending in
 * any number of up to LEN + 1 digits, in a buffer that holds LEN of them:
 * it writes inside the buffer alone, one JSON object of 22 members with
 * its terminator, or nothing with -E2BIG exactly when the number is too
 * long; a room cut short or a bad input leaves no body either.
 */

#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/string.c"
#include "../../../util/hex.c"
#include "../../../util/json.c"
#include "../../../util/keepalive.c"

#define HASH \
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define NOT_A_HASH	"sha256:0123456789abcdef"
#define MEMBERS		22
/* Past the longest of these bodies, and a room inside the shortest. */
#define ROOM		832
#define CUT_SHORT	(ROOM / 4)

enum state { START, KEY, STRING, COLON, VALUE, ELEMENT, ZERO, DIGITS, WORD,
	     NEXT, END };

static const __u64 counters[TAMPER_MAX];

/* keepalive_mask() is not reached: the mask comes in as text. */
int base64_encode(const __u8 *data, size_t len, char *out, size_t out_sz)
{
	__CPROVER_assert(false, "no base64 in the emitter");
	return -EINVAL;
}

static bool number_start(__u8 c, enum state *s)
{
	if (c < '0' || c > '9')
		return false;
	*s = c == '0' ? ZERO : DIGITS;
	return true;
}

/*
 * The members of one object of ECMA-404 without white space, whose values
 * are ASCII strings without escapes, null, unsigned integers and arrays
 * of those integers: a subset of the grammar, so what it takes is JSON.
 * -1 for any other text.
 */
static int json_members(const char *t, size_t n)
{
	bool key = false, array = false;
	enum state s = START;
	size_t i, word = 0;
	int members = 1;
	__u8 c;

	for (i = 0; i < n; i++) {
		c = t[i];
		switch (s) {
		case START:
			if (c != '{')
				return -1;
			s = KEY;
			continue;
		case KEY:
			if (c != '"')
				return -1;
			key = true;
			s = STRING;
			continue;
		case STRING:
			if (c == '"')
				s = key ? COLON : NEXT;
			else if (c < 0x20 || c == '\\' || c >= 0x80)
				return -1;
			continue;
		case COLON:
			if (c != ':')
				return -1;
			key = false;
			s = VALUE;
			continue;
		case WORD:
			if (c != "null"[word++])
				return -1;
			if (word == 4)
				s = NEXT;
			continue;
		case VALUE:
			if (c == '"') {
				s = STRING;
			} else if (c == 'n') {
				word = 1;
				s = WORD;
			} else if (c == '[') {
				array = true;
				s = ELEMENT;
			} else if (!number_start(c, &s)) {
				return -1;
			}
			continue;
		case ELEMENT:
			if (!number_start(c, &s))
				return -1;
			continue;
		case DIGITS:
			if (c >= '0' && c <= '9')
				continue;
			break;
		case END:
			return -1;
		default:
			break;
		}
		if (c == ',') {
			s = array ? ELEMENT : KEY;
			members += !array;
		} else if (c == ']' && array) {
			array = false;
			s = NEXT;
		} else if (c == '}' && !array) {
			s = END;
		} else {
			return -1;
		}
	}
	return s == END ? members : -1;
}

static struct keepalive_input without_a_tree(void)
{
	return (struct keepalive_input){
		.boot_id = "b",
		.version_id = HASH,
		.kernel_release = "k",
		.verdict = "init-pending",
		.flags = 8,
		.set_sha256 = HASH,
	};
}

static struct keepalive_input with_a_tree_alone(void)
{
	struct keepalive_input in = without_a_tree();

	in.config_root = "";
	in.image_id = "";
	in.tree = true;
	in.tree_id = "t";
	in.base_root = "";
	in.projection_root = HASH;
	in.mask = "";
	return in;
}

static struct keepalive_input with_every_value(void)
{
	return (struct keepalive_input){
		.boot_id = "b",
		.version_id = HASH,
		.config_root = HASH,
		.kernel_release = "k",
		.image_id = "i",
		.image_version = "v",
		.image_root = HASH,
		.verdict = "ok",
		.cond = 5461,
		.flags = 63,
		.tamper = counters,
		.tree = true,
		.tree_id = "t",
		.generation = 42,
		.last_seq = 12,
		.base_root = HASH,
		.projection_root = HASH,
		.mask = "WdlZAA==",
		.set_sha256 = HASH,
		.count = 7,
	};
}

static __u64 power_of_ten(size_t digits)
{
	__u64 power = 1;
	size_t i;

	for (i = 0; i < digits; i++)
		power *= 10;
	return power;
}

static __u64 any_number(void)
{
	__u64 number;

	__CPROVER_assume(number < power_of_ten(LEN + 1));
	return number;
}

static size_t body_len(const struct keepalive_input *in)
{
	char *buf = any_bytes(ROOM);
	size_t len;
	int ret;

	ret = keepalive_emit(in, buf, ROOM, &len);
	__CPROVER_assert(!ret, "the body fits the largest room");
	return len;
}

/*
 * The buffer ends where its room does, so that a write past it fails
 * the proof. The room is a constant, which keeps every offset before
 * the last number one too.
 */
static void emits(struct keepalive_input in)
{
	size_t cap, len;
	char *buf;
	int ret;

	cap = body_len(&in) + LEN;
	buf = any_bytes(cap);
	in.not_ok = any_number();
	ret = keepalive_emit(&in, buf, cap, &len);

	__CPROVER_assert((ret == -E2BIG) ==
			 (!LEN || in.not_ok >= power_of_ten(LEN)),
			 "-E2BIG exactly for a number too long");
	if (ret) {
		__CPROVER_assert(ret == -E2BIG && !len && !buf[0],
				 "a refusal leaves no body");
		return;
	}
	__CPROVER_assert(len < cap && !buf[len], "terminated in the buffer");
	__CPROVER_assert(json_members(buf, len) == MEMBERS,
			 "one JSON object of 22 members");
}

static void refuses(const struct keepalive_input *in, size_t cap, int want)
{
	char *buf = cap ? any_bytes(cap) : NULL;
	size_t len;
	int ret;

	ret = keepalive_emit(in, buf, cap, &len);
	__CPROVER_assert(ret == want,
			 "-E2BIG for the room, -EINVAL for the input");
	__CPROVER_assert(!len && (!cap || !buf[0]), "a refusal leaves no body");
}

void harness(void)
{
	struct keepalive_input in = without_a_tree();

	refuses(&in, 0, -E2BIG);
	refuses(&in, 1, -E2BIG);
	refuses(&in, CUT_SHORT, -E2BIG);
	in.boot_id = NULL;
	refuses(&in, ROOM, -EINVAL);
	in = with_a_tree_alone();
	in.projection_root = NOT_A_HASH;
	refuses(&in, ROOM, -EINVAL);

	emits(without_a_tree());
	emits(with_a_tree_alone());
	emits(with_every_value());
}
