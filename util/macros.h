/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Project-wide macros. Boilerplate, uncopyrightable.
 */

#ifndef SHIRUDO_MACROS_H
#define SHIRUDO_MACROS_H

/*
 * Compile-time assertion: 0 if `e` is false, else a 1-bit signed
 * bitfield of width -1 -> compiler error.
 */
#define SHIRUDO_BUILD_BUG_ON_ZERO(e)	((int)(sizeof(struct { int:(-!!(e)); })))

/*
 * ARRAY_SIZE(arr) -- element count of a true C array, with a
 * compile-time gate that rejects a pointer that has decayed from an
 * array (the classic bug). GCC's __builtin_types_compatible_p (also
 * supported by clang) returns 1 when `arr` is a pointer (its type
 * matches typeof(&arr[0]) = T*) and 0 for a real array (T[N] vs T*
 * are not compatible). The bitfield trick then errors out on the
 * pointer case while leaving the value unchanged for the array case.
 */
#define ARRAY_SIZE(arr)							\
	(sizeof(arr) / sizeof((arr)[0]) +				\
	 SHIRUDO_BUILD_BUG_ON_ZERO(					\
		 __builtin_types_compatible_p(typeof(arr),		\
					      typeof(&(arr)[0]))))

#endif /* SHIRUDO_MACROS_H */
