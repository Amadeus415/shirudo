/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * syslog(3) wrappers under LOG_AUTHPRIV.
 */

#ifndef SHIRUDO_LOG_H
#define SHIRUDO_LOG_H

#include <stdarg.h>

#include <shirudo/compiler.h>

/* In rust/src/log.rs: opens syslog for the messages to come. */
void log_init(void);

#endif /* SHIRUDO_LOG_H */
