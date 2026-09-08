/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_IO_H
#define SHIRUDO_IO_H

#include <stddef.h>

/* Write the complete buffer, retrying EINTR and short writes. */
int shirudo_write_all(int fd, const void *buf, size_t len);

#endif /* SHIRUDO_IO_H */
