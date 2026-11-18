/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Helpers shared by every BPF program.
 */

#ifndef SHIRUDO_BPF_MISC_H
#define SHIRUDO_BPF_MISC_H

/* Token for token as in include/shirudo/compiler.h; see there. */
#define BUILD_BUG_ON_MSG(cond, msg)	_Static_assert(!(cond), msg)
#define BUILD_BUG_ON(cond)						\
	BUILD_BUG_ON_MSG(cond, "BUILD_BUG_ON failed: " #cond)
#define fallthrough	__attribute__((__fallthrough__))

/*
 * One access to x that the compiler neither tears nor repeats nor merges
 * with another, for memory that programs on other CPUs change meanwhile.
 */
#define READ_ONCE(x)		(*(const volatile typeof(x) *)&(x))
#define WRITE_ONCE(x, val)	(*(volatile typeof(x) *)&(x) = (val))

/* Token for token as in include/shirudo/misc.h; see there. */
#define __sign_use(x)							\
	((typeof(x))(-1) < 1 ? 2 : sizeof(x) < sizeof(int) ? 3 : 1)
#define __minmax_op_min		<
#define __minmax_op_max		>
#define __minmax_n(op, x, y, n) ({					\
	__auto_type __x##n = (x);					\
	__auto_type __y##n = (y);					\
	typeof(__x##n + __y##n) __a##n = __x##n;			\
	typeof(__x##n + __y##n) __b##n = __y##n;			\
	BUILD_BUG_ON_MSG(!(__sign_use(__x##n) & __sign_use(__y##n)),	\
			 #op "(" #x ", " #y ") mixes signed and unsigned"); \
	__a##n __minmax_op_##op __b##n ? __a##n : __b##n; })
#define __minmax(op, x, y, n)	__minmax_n(op, x, y, n)
#define min(x, y)		__minmax(min, x, y, __COUNTER__)
#define max(x, y)		__minmax(max, x, y, __COUNTER__)

#endif /* SHIRUDO_BPF_MISC_H */
