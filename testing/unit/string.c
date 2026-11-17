// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <stdint.h>

#include <shirudo/string.h>

#include "malloc.h"
#include "unit.h"

/*
 * The span under test sits in a buffer of exactly its length, so a read
 * past it shows up under ASan.
 */
static char *span(const char *text, size_t len)
{
	char *buf = xmalloc(len ? len : 1);

	ASSERT_TRUE(buf);
	memcpy(buf, text, len);
	return buf;
}

static int u64_of(const char *text, size_t len, __u64 max, __u64 *v)
{
	char *buf = span(text, len);
	int ret;

	*v = 0;
	ret = parse_u64(buf, len, max, v);
	xfree(buf, len ? len : 1);
	return ret;
}

static int x64_of(const char *text, __u64 max, __u64 *v)
{
	size_t len = strlen(text);
	char *buf = span(text, len);
	int ret;

	*v = 0;
	ret = parse_x64(buf, len, max, v);
	xfree(buf, len ? len : 1);
	return ret;
}

static int s64_of(const char *text, __s64 min, __s64 max, __s64 *v)
{
	size_t len = strlen(text);
	char *buf = span(text, len);
	int ret;

	*v = 0;
	ret = parse_s64(buf, len, min, max, v);
	xfree(buf, len ? len : 1);
	return ret;
}

static int u64_str(const char *text, __u64 max, __u64 *v)
{
	return u64_of(text, strlen(text), max, v);
}

#define EXPECT_U64(text, max, ret, value)				\
	do {								\
		__u64 v_;						\
									\
		EXPECT_EQ(u64_str(text, max, &v_), ret);			\
		EXPECT_UEQ(v_, value);					\
	} while (0)

static void digits_counts_leading_digits(void)
{
	EXPECT_UEQ(digits("123abc", 6), 3);
	EXPECT_UEQ(digits("abc", 3), 0);
	EXPECT_UEQ(digits("", 0), 0);
}

static void decimal_fills_its_span(void)
{
	EXPECT_U64("0", UINT64_MAX, 0, 0);
	EXPECT_U64("007", UINT64_MAX, 0, 7);
	EXPECT_U64("18446744073709551615", UINT64_MAX, 0, UINT64_MAX);
}

static void nothing_past_the_span_is_read(void)
{
	__u64 v;

	EXPECT_EQ(u64_of("123456", 3, UINT64_MAX, &v), 0);
	EXPECT_UEQ(v, 123);
	EXPECT_EQ(u64_of("123", 0, UINT64_MAX, &v), -EINVAL);
	EXPECT_UEQ(v, 0);
}

static void sign_blank_or_prefix_is_no_number(void)
{
	static const char *const bad[] = {
		"", "-1", "+1", " 1", "1 ", "0x10", "1.5", "1e3", "12a",
	};

	for (size_t i = 0; i < ARRAY_SIZE(bad); i++)
		EXPECT_U64(bad[i], UINT64_MAX, -EINVAL, 0);
}

static void number_past_its_bound_is_out_of_range(void)
{
	EXPECT_U64("18446744073709551616", UINT64_MAX, -ERANGE, 0);
	EXPECT_U64("10", 10, 0, 10);
	EXPECT_U64("11", 10, -ERANGE, 0);
	EXPECT_U64("9", 5, -ERANGE, 0);
	EXPECT_U64("0", 0, 0, 0);
}

static void malformed_number_however_long(void)
{
	EXPECT_U64("99999999999999999999x", UINT64_MAX, -EINVAL, 0);
}

static void hex_takes_either_case_and_no_prefix(void)
{
	__u64 v;

	EXPECT_EQ(x64_of("ff", UINT64_MAX, &v), 0);
	EXPECT_UEQ(v, 255);
	EXPECT_EQ(x64_of("FF", UINT64_MAX, &v), 0);
	EXPECT_UEQ(v, 255);
	EXPECT_EQ(x64_of("ffffffffffffffff", UINT64_MAX, &v), 0);
	EXPECT_UEQ(v, UINT64_MAX);
	EXPECT_EQ(x64_of("10000000000000000", UINT64_MAX, &v), -ERANGE);
	EXPECT_UEQ(v, 0);
	EXPECT_EQ(x64_of("0x10", UINT64_MAX, &v), -EINVAL);
	EXPECT_UEQ(v, 0);
	EXPECT_EQ(x64_of("g", UINT64_MAX, &v), -EINVAL);
	EXPECT_UEQ(v, 0);
}

static void signed_number_spans_the_whole_range(void)
{
	__s64 v;

	EXPECT_EQ(s64_of("-9223372036854775808", INT64_MIN, INT64_MAX, &v), 0);
	EXPECT_EQ(v, INT64_MIN);
	EXPECT_EQ(s64_of("9223372036854775807", INT64_MIN, INT64_MAX, &v), 0);
	EXPECT_EQ(v, INT64_MAX);
	EXPECT_EQ(s64_of("-0", INT64_MIN, INT64_MAX, &v), 0);
	EXPECT_EQ(v, 0);
	EXPECT_EQ(s64_of("9223372036854775808", INT64_MIN, INT64_MAX, &v),
		  -ERANGE);
	EXPECT_EQ(v, 0);
	EXPECT_EQ(s64_of("-9223372036854775809", INT64_MIN, INT64_MAX, &v),
		  -ERANGE);
	EXPECT_EQ(v, 0);
}

static void signed_number_keeps_bounds_and_form(void)
{
	static const char *const bad[] = { "-", "--", "--1", "+1", " -1", "-x" };
	__s64 v;

	EXPECT_EQ(s64_of("0", 1, 10, &v), -ERANGE);
	EXPECT_EQ(v, 0);
	EXPECT_EQ(s64_of("-6", -5, 5, &v), -ERANGE);
	EXPECT_EQ(v, 0);
	EXPECT_EQ(s64_of("-5", -5, 5, &v), 0);
	EXPECT_EQ(v, -5);
	for (size_t i = 0; i < ARRAY_SIZE(bad); i++) {
		EXPECT_EQ(s64_of(bad[i], INT64_MIN, INT64_MAX, &v), -EINVAL);
		EXPECT_EQ(v, 0);
	}
}

static void strscpy_copies_what_fits_whole(void)
{
	char six[6], big[64], one[1];

	EXPECT_EQ(strscpy(six, "hello", sizeof(six)), 5);
	EXPECT_STREQ(six, "hello");
	EXPECT_EQ(strscpy(big, "hello", sizeof(big)), 5);
	EXPECT_STREQ(big, "hello");
	EXPECT_EQ(strscpy(one, "", sizeof(one)), 0);
	EXPECT_STREQ(one, "");
}

static void strscpy_cuts_and_says_so(void)
{
	char five[5], one[1], none[1] = { 'x' };

	EXPECT_EQ(strscpy(five, "hello", sizeof(five)), -E2BIG);
	EXPECT_STREQ(five, "hell");
	EXPECT_EQ(strscpy(one, "hello", sizeof(one)), -E2BIG);
	EXPECT_STREQ(one, "");
	EXPECT_EQ(strscpy(none, "hello", 0), -E2BIG);
	EXPECT_EQ(none[0], 'x');
}

static void dns_name_is_ldh_labels_and_no_address(void)
{
	char label[65], name[300];

	EXPECT_TRUE(dns_name_valid("registry.example.com"));
	EXPECT_TRUE(dns_name_valid("Reg-1.Example"));
	EXPECT_TRUE(dns_name_valid("localhost"));
	EXPECT_TRUE(dns_name_valid("1.2.3.example"));
	EXPECT_TRUE(dns_name_valid("0x.1"));
	EXPECT_FALSE(dns_name_valid(""));
	EXPECT_FALSE(dns_name_valid("."));
	EXPECT_FALSE(dns_name_valid("example..com"));
	EXPECT_FALSE(dns_name_valid("example.com."));
	EXPECT_FALSE(dns_name_valid("-example.com"));
	EXPECT_FALSE(dns_name_valid("example-.com"));
	EXPECT_FALSE(dns_name_valid("exa_mple.com"));
	EXPECT_FALSE(dns_name_valid("example.com:443"));
	EXPECT_FALSE(dns_name_valid("10.0.2.2"));
	EXPECT_FALSE(dns_name_valid("127.1"));
	EXPECT_FALSE(dns_name_valid("0x7f.1"));
	EXPECT_FALSE(dns_name_valid("2130706433"));

	memset(label, 'a', 63);
	label[63] = '\0';
	ASSERT_TRUE(snprintf(name, sizeof(name), "%s.example", label) > 0);
	EXPECT_TRUE(dns_name_valid(name));
	memset(label, 'a', 64);
	label[64] = '\0';
	ASSERT_TRUE(snprintf(name, sizeof(name), "%s.example", label) > 0);
	EXPECT_FALSE(dns_name_valid(name));

	memset(label, 'a', 63);
	label[63] = '\0';
	ASSERT_TRUE(snprintf(name, sizeof(name), "%s.%s.%s.%.61s", label,
			     label, label, label) == 253);
	EXPECT_TRUE(dns_name_valid(name));
	ASSERT_TRUE(snprintf(name, sizeof(name), "%s.%s.%s.%.62s", label,
			     label, label, label) == 254);
	EXPECT_FALSE(dns_name_valid(name));
}

static size_t width_of(const char *text, size_t len)
{
	char *buf = span(text, len);
	size_t width = utf8_width(buf, len);

	xfree(buf, len ? len : 1);
	return width;
}

static void utf8_width_takes_well_formed_characters_only(void)
{
	EXPECT_EQ(width_of("", 0), 0);
	EXPECT_EQ(width_of("a", 1), 1);
	EXPECT_EQ(width_of("\x7f", 1), 1);
	EXPECT_EQ(width_of("\xc2\x80", 2), 2);
	EXPECT_EQ(width_of("\xdf\xbf", 2), 2);
	EXPECT_EQ(width_of("\xe0\xa0\x80", 3), 3);
	EXPECT_EQ(width_of("\xed\x9f\xbf", 3), 3);
	EXPECT_EQ(width_of("\xee\x80\x80", 3), 3);
	EXPECT_EQ(width_of("\xef\xbf\xbf", 3), 3);
	EXPECT_EQ(width_of("\xf0\x90\x80\x80", 4), 4);
	EXPECT_EQ(width_of("\xf4\x8f\xbf\xbf", 4), 4);
	EXPECT_EQ(width_of("\xc3\xa9z", 3), 2);

	EXPECT_EQ(width_of("\x80", 1), 0);
	EXPECT_EQ(width_of("\xbf", 1), 0);
	EXPECT_EQ(width_of("\xc3", 1), 0);
	EXPECT_EQ(width_of("\xe2\x82", 2), 0);
	EXPECT_EQ(width_of("\xe2\x82z", 3), 0);
	EXPECT_EQ(width_of("\xc0\x80", 2), 0);
	EXPECT_EQ(width_of("\xc0\xaf", 2), 0);
	EXPECT_EQ(width_of("\xc1\xbf", 2), 0);
	EXPECT_EQ(width_of("\xe0\x80\xaf", 3), 0);
	EXPECT_EQ(width_of("\xe0\x9f\xbf", 3), 0);
	EXPECT_EQ(width_of("\xed\xa0\x80", 3), 0);
	EXPECT_EQ(width_of("\xed\xbf\xbf", 3), 0);
	EXPECT_EQ(width_of("\xf0\x8f\xbf\xbf", 4), 0);
	EXPECT_EQ(width_of("\xf4\x90\x80\x80", 4), 0);
	EXPECT_EQ(width_of("\xf5\x80\x80\x80", 4), 0);
	EXPECT_EQ(width_of("\xf8\x88\x80\x80\x80", 5), 0);
	EXPECT_EQ(width_of("\xff", 1), 0);
}

static size_t utf8_encode(__u32 cp, char *buf)
{
	if (cp < 0x80) {
		buf[0] = (char)cp;
		return 1;
	}
	if (cp < 0x800) {
		buf[0] = (char)(0xc0 | cp >> 6);
		buf[1] = (char)(0x80 | (cp & 0x3f));
		return 2;
	}
	if (cp < 0x10000) {
		buf[0] = (char)(0xe0 | cp >> 12);
		buf[1] = (char)(0x80 | (cp >> 6 & 0x3f));
		buf[2] = (char)(0x80 | (cp & 0x3f));
		return 3;
	}
	buf[0] = (char)(0xf0 | cp >> 18);
	buf[1] = (char)(0x80 | (cp >> 12 & 0x3f));
	buf[2] = (char)(0x80 | (cp >> 6 & 0x3f));
	buf[3] = (char)(0x80 | (cp & 0x3f));
	return 4;
}

/*
 * Every scalar value's encoding is taken, and there are no more 2-, 3-
 * and 4-byte sequences taken than scalar values of that length, so
 * those encodings are all there is.
 */
static void utf8_width_takes_the_scalar_values_alone(void)
{
	__u32 cp, i, wrong = 0, two = 0, three = 0, four = 0;
	char buf[4];

	for (cp = 0; cp <= 0x10ffff; cp++) {
		size_t len;

		if (cp >= 0xd800 && cp <= 0xdfff)
			continue;
		len = utf8_encode(cp, buf);
		if (utf8_width(buf, len) != len)
			wrong++;
	}
	EXPECT_EQ(wrong, 0);
	for (i = 0; i < 1u << 16; i++) {
		buf[0] = (char)(i >> 8);
		buf[1] = (char)i;
		two += utf8_width(buf, 2) == 2;
	}
	EXPECT_EQ(two, 0x780);
	for (i = 0; i < 1u << 24; i++) {
		buf[0] = (char)(i >> 16);
		buf[1] = (char)(i >> 8);
		buf[2] = (char)i;
		three += utf8_width(buf, 3) == 3;
	}
	EXPECT_EQ(three, 0xf000);
	for (i = 0; i < 1u << 22; i++) {
		buf[0] = (char)(0xf0 | i >> 18);
		buf[1] = (char)(0x80 | (i >> 12 & 0x3f));
		buf[2] = (char)(0x80 | (i >> 6 & 0x3f));
		buf[3] = (char)(0x80 | (i & 0x3f));
		four += utf8_width(buf, 4) == 4;
	}
	EXPECT_EQ(four, 0x100000);
}

static bool sanitized(const char *text, size_t len, bool lines,
		      const char *want)
{
	char *buf = span(text, len);
	bool same;

	text_sanitize(buf, len, lines);
	same = !memcmp(buf, want, len);
	xfree(buf, len ? len : 1);
	return same;
}

static void text_sanitize_replaces_controls_and_stray_bytes(void)
{
	EXPECT_TRUE(sanitized("", 0, false, ""));
	EXPECT_TRUE(sanitized("plain ~text", 11, false, "plain ~text"));
	EXPECT_TRUE(sanitized("\x1b[31mred", 8, false, "?[31mred"));
	EXPECT_TRUE(sanitized("a\0b\x7f", 4, false, "a?b?"));
	EXPECT_TRUE(sanitized("t\tl\n", 4, false, "t?l?"));
	EXPECT_TRUE(sanitized("t\tl\n", 4, true, "t\tl\n"));
	EXPECT_TRUE(sanitized("a\r\nb\rc\r", 7, true, "a\r\nb?c?"));
	EXPECT_TRUE(sanitized("\xc2\x9b\x33\x31m", 5, true, "??31m"));
	EXPECT_TRUE(sanitized("\xc2\x80\xc2\x9f\xc2\xa0", 6, false,
			      "????\xc2\xa0"));
	EXPECT_TRUE(sanitized("caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x90\x9d",
			      14, false,
			      "caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x90\x9d"));
	EXPECT_TRUE(sanitized("\xff\xc3z\xe2\x82", 5, false, "??z??"));
	EXPECT_TRUE(sanitized("\xed\xa0\x80", 3, false, "???"));
}

/* Every scalar value but the controls passes; a control leaves only '?'. */
static void text_sanitize_passes_all_but_the_controls(void)
{
	__u32 cp, wrong = 0;
	char buf[4];

	for (cp = 0; cp <= 0x10ffff; cp++) {
		bool control = cp < 0x20 || (cp >= 0x7f && cp <= 0x9f);
		size_t len, i, marks = 0;
		char copy[4];

		if (cp >= 0xd800 && cp <= 0xdfff)
			continue;
		len = utf8_encode(cp, buf);
		memcpy(copy, buf, len);
		text_sanitize(buf, len, false);
		for (i = 0; i < len; i++)
			marks += buf[i] == '?';
		if (control ? marks != len : memcmp(buf, copy, len))
			wrong++;
	}
	EXPECT_EQ(wrong, 0);
}

static void memzero_explicit_clears_its_span_only(void)
{
	__u8 want[16], buf[16];

	memset(buf, 0xa5, sizeof(buf));
	memset(want, 0xa5, sizeof(want));
	memset(want + 4, 0, 8);
	memzero_explicit(buf + 4, 8);
	EXPECT_MEMEQ(buf, want, sizeof(buf));
}

static void memneq_explicit_tells_every_bit_apart(void)
{
	__u8 a[33], b[33];
	size_t i;
	int bit;

	for (i = 0; i < sizeof(a); i++)
		a[i] = (__u8)(i * 37 + 1);
	memcpy(b, a, sizeof(b));
	EXPECT_EQ(memneq_explicit(a, b, sizeof(a)), 0);
	EXPECT_EQ(memneq_explicit(a, b, 0), 0);
	for (i = 0; i < sizeof(a); i++) {
		for (bit = 0; bit < 8; bit++) {
			b[i] ^= 1u << bit;
			EXPECT_EQ(memneq_explicit(a, b, sizeof(a)), 1);
			EXPECT_EQ(memneq_explicit(a, b, i), 0);
			b[i] ^= 1u << bit;
		}
	}
}

static void name_has_suffix_wants_a_stem(void)
{
	EXPECT_TRUE(name_has_suffix("a.upatch", 8, ".upatch"));
	EXPECT_TRUE(name_has_suffix("a.upatch.x", 8, ".upatch"));
	EXPECT_FALSE(name_has_suffix(".upatch", 7, ".upatch"));
	EXPECT_FALSE(name_has_suffix("a.upatch.bak", 12, ".upatch"));
	EXPECT_FALSE(name_has_suffix("a.UPATCH", 8, ".upatch"));
	EXPECT_FALSE(name_has_suffix("", 0, ""));
	EXPECT_TRUE(name_has_suffix("a", 1, ""));
}

static const struct unit_case cases[] = {
	UNIT_CASE(digits_counts_leading_digits),
	UNIT_CASE(decimal_fills_its_span),
	UNIT_CASE(nothing_past_the_span_is_read),
	UNIT_CASE(sign_blank_or_prefix_is_no_number),
	UNIT_CASE(number_past_its_bound_is_out_of_range),
	UNIT_CASE(malformed_number_however_long),
	UNIT_CASE(hex_takes_either_case_and_no_prefix),
	UNIT_CASE(signed_number_spans_the_whole_range),
	UNIT_CASE(signed_number_keeps_bounds_and_form),
	UNIT_CASE(strscpy_copies_what_fits_whole),
	UNIT_CASE(strscpy_cuts_and_says_so),
	UNIT_CASE(dns_name_is_ldh_labels_and_no_address),
	UNIT_CASE(utf8_width_takes_well_formed_characters_only),
	UNIT_CASE(utf8_width_takes_the_scalar_values_alone),
	UNIT_CASE(text_sanitize_replaces_controls_and_stray_bytes),
	UNIT_CASE(text_sanitize_passes_all_but_the_controls),
	UNIT_CASE(memzero_explicit_clears_its_span_only),
	UNIT_CASE(memneq_explicit_tells_every_bit_apart),
	UNIT_CASE(name_has_suffix_wants_a_stem),
	{}
};

UNIT_SUITE(string, cases);
