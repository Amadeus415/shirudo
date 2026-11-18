// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The attach metadata proof for kprobe and kretprobe sections: a symbol of
 * up to 127 bytes and an offset of up to 64 bits, decimal or hexadecimal,
 * read back as written, and the sections the writer must refuse.
 */

#define KPROBE_OBJECTS
#include "upatch-writer-prog-specs.c"
