/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Zeroing allocator: zero on alloc, scrub on free.
 */

#ifndef SHIRUDO_MALLOC_H
#define SHIRUDO_MALLOC_H

#include <stddef.h>

/*
 * Allocate size bytes, zero-initialised, returning NULL on failure --
 * callers must check and surface -ENOMEM the same way they do for
 * malloc(). Unlike git's xmalloc this deliberately does NOT die() on
 * OOM: shirudo's one-shot CLIs report the error up their normal path. A
 * zero size still returns a freeable non-NULL pointer, so a NULL return
 * unambiguously means out-of-memory.
 */
void *xmalloc(size_t size);

/*
 * Zeroed array allocation. Returns NULL if nmemb * size would overflow
 * size_t (checked explicitly, before allocating) or on allocation
 * failure; same zero-size handling as xmalloc(). Free the result with
 * xfree(ptr, nmemb * size).
 */
void *xcalloc(size_t nmemb, size_t size);

/*
 * Resize an array from old_nmemb to new_nmemb elements of `size`,
 * scrubbing the old block. Returns NULL -- leaving ptr untouched, the
 * way realloc does on failure -- if either old_nmemb * size or
 * new_nmemb * size would overflow size_t (both checked before
 * allocating), or on allocation failure.
 *
 * Unlike realloc this always allocates a fresh zero-initialised block,
 * copies the smaller of the two sizes, then explicit_bzero+free's the
 * old block -- so the old contents are scrubbed even where a plain
 * realloc would have shrunk in place or moved-and-freed without
 * clearing. The grown tail is zeroed. Pass ptr == NULL (old_nmemb 0)
 * for the initial allocation. Free the result with
 * xfree(ptr, nmemb * size).
 */
void *xreallocarray(void *ptr, size_t old_nmemb, size_t new_nmemb,
		    size_t size);

/*
 * strdup()/strndup() that return NULL on failure; free the result with
 * xstrfree(). The bytes are not pre-zeroed (the copy fills them).
 *
 * WARNING: xstrdup() calls strlen(s) and so MUST only ever be given a
 * trusted, definitely-NUL-terminated string. Never call it on user /
 * network / file input or any buffer whose termination you do not
 * control -- a missing NUL makes strlen run off the end (out-of-bounds
 * read, possible crash or info leak). For anything untrusted or
 * unbounded use xstrndup() with a hard upper bound instead; it caps the
 * read with strnlen().
 */
char *xstrdup(const char *s);
char *xstrndup(const char *s, size_t n);

/*
 * explicit_bzero(ptr, size) then free(ptr); a no-op when ptr is NULL.
 * Scrubs so secrets (key material, signatures, TPM auth, verifier logs)
 * do not linger in freed heap or a core dump. size is the size that was
 * passed to the matching xmalloc()/xcalloc() (nmemb * size for the
 * latter).
 */
void xfree(void *ptr, size_t size);

/*
 * Scrub strlen(s) + 1 bytes and free; a no-op when s is NULL. The
 * scrub-free companion to xstrdup()/xstrndup(): the length is recovered
 * with strlen, which matches the allocation as long as the string was
 * not shortened in place (its tail would then go unscrubbed).
 */
void xstrfree(char *s);

/*
 * Escape hatch to release memory the C library allocated for us
 * (scandir entry array and entries, getline buffer, realpath result,
 * etc.) -- a no-op on NULL. The only legitimate user of libc's free()
 * is util/malloc.c itself; everywhere else, code that needs to free
 * a libc-owned pointer goes through this wrapper. The poison pragma
 * below makes bare malloc/free/strdup a hard build error outside of
 * util/malloc.c, so this is the *only* permitted path.
 */
void shirudo_libc_free(void *p);

/*
 * Hard build-time ban on libc's own allocators outside util/malloc.c.
 * `#pragma GCC poison` rejects any subsequent token appearance of the
 * named identifiers, so `malloc(...)`, `free(...)`, etc. become syntax
 * errors -- the project must go through x...() / shirudo_libc_free instead.
 * util/malloc.c sets SHIRUDO_MALLOC_INTERNAL before including this
 * header to opt the implementations out (they're the ones that must
 * call the real libc allocators). The pragma sits at the end of the
 * header so that system declarations of malloc/free pulled in earlier
 * (from <stdlib.h>, <string.h>, ...) are processed before the poison
 * takes effect.
 */
#ifndef SHIRUDO_MALLOC_INTERNAL
# pragma GCC poison malloc calloc realloc reallocarray free strdup strndup asprintf vasprintf
#endif

#endif /* SHIRUDO_MALLOC_H */
