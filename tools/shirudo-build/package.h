/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * gen_loader + CMS sign + .upatch container writer.
 */

#ifndef SHIRUDO_BUILD_PACKAGE_H
#define SHIRUDO_BUILD_PACKAGE_H

int shirudo_build_package_load(const char *bpf_o, const char *src_path,
			       const char *out_upatch, const char *upatch_name,
			       const char *pkey_path, const char *cert_path);

int shirudo_build_package_unload(const char *name,
				 const unsigned char payload_sha256[32],
				 const char *out_upatch,
				 const char *pkey_path,
				 const char *cert_path);

#endif /* SHIRUDO_BUILD_PACKAGE_H */
