/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * BPF-side decoder manifest ABI. Include after vmlinux.h so __u16/__u32
 * are available.
 */

#ifndef SHIRUDO_DECODER_H
#define SHIRUDO_DECODER_H

#define SHIRUDO_DECODER_MANIFEST_MAGIC	0x44434544u	/* "DECD" le */
#define SHIRUDO_UPATCH_DECODER_VERSION	1u
#define SHIRUDO_UPATCH_DECODER_LANG_LUA	1u
#define SHIRUDO_UPATCH_DECODER_INPUT_MAP_V1 1u
#define SHIRUDO_UPATCH_DECODER_EXPORT_LOG 1u
#define SHIRUDO_UPATCH_DECODER_EXPORT_METRIC 2u

struct shirudo_decoder_manifest {
	__u32	magic;		/* SHIRUDO_DECODER_MANIFEST_MAGIC */
	__u16	version;		/* SHIRUDO_UPATCH_DECODER_VERSION */
	__u16	language;	/* SHIRUDO_UPATCH_DECODER_LANG_* */
	__u16	api_version;
	__u16	input_format;	/* SHIRUDO_UPATCH_DECODER_INPUT_MAP_V1 */
	__u16	export_signal;	/* SHIRUDO_UPATCH_DECODER_EXPORT_* */
	__u16	reserved;
	char	upatch[64];
	char	map[16];
	char	source[64];
	char	entrypoint[32];
};

#endif /* SHIRUDO_DECODER_H */
