// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * libpcap through dlopen(), for shirudo pwru alone: the helper links no
 * library for it, and the few calls it makes and struct bpf_program have
 * kept their ABI since libpcap 0.8.
 */

#include <dlfcn.h>
#include <errno.h>
#include <string.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "log.h"
#include "malloc.h"
#include "pcap.h"

/* PCAP_NETMASK_UNKNOWN: a filter on the broadcast address fails. */
#define PCAP_NETMASK_UNKNOWN	0xffffffffU
/* MAXIMUM_SNAPLEN, which a filter returns for a packet it accepts. */
#define PCAP_SNAPLEN		262144

/* struct bpf_program, whose instructions are struct sock_filter's. */
struct pcap_program {
	__u32			bf_len;
	struct sock_filter	*bf_insns;
};

struct pcap;

struct pcap_lib {
	void		*handle;
	struct pcap	*(*open_dead)(int linktype, int snaplen);
	int		(*compile)(struct pcap *p, struct pcap_program *prog,
				   const char *expr, int optimize,
				   __u32 netmask);
	void		(*freecode)(struct pcap_program *prog);
	char		*(*geterr)(struct pcap *p);
	void		(*close)(struct pcap *p);
};

/* Debian and Ubuntu name the library for its 0.8 ABI. */
static const char *const pcap_sonames[] = {
	"libpcap.so.1", "libpcap.so.0.8",
};

static void *pcap_sym(void *handle, const char *name, int *err)
{
	void *sym = dlsym(handle, name);

	if (!sym) {
		pr_err("libpcap has no %s()", name);
		*err = -ENOENT;
	}
	return sym;
}

static int pcap_lib_bind(struct pcap_lib *lib)
{
	int err = 0;

	lib->open_dead = pcap_sym(lib->handle, "pcap_open_dead", &err);
	lib->compile = pcap_sym(lib->handle, "pcap_compile", &err);
	lib->freecode = pcap_sym(lib->handle, "pcap_freecode", &err);
	lib->geterr = pcap_sym(lib->handle, "pcap_geterr", &err);
	lib->close = pcap_sym(lib->handle, "pcap_close", &err);
	return err;
}

int pcap_lib_open(struct pcap_lib **out)
{
	struct pcap_lib *lib;
	void *handle = NULL;
	size_t i;
	int ret;

	*out = NULL;
	for (i = 0; i < ARRAY_SIZE(pcap_sonames) && !handle; i++)
		handle = dlopen(pcap_sonames[i], RTLD_NOW | RTLD_LOCAL);
	if (!handle) {
		pr_err("libpcap not found as %s or %s; install the libpcap package",
		       pcap_sonames[0], pcap_sonames[1]);
		return -ENOENT;
	}
	lib = xcalloc(1, sizeof(*lib));
	if (!lib) {
		dlclose(handle);
		return -ENOMEM;
	}
	lib->handle = handle;
	ret = pcap_lib_bind(lib);
	if (ret) {
		pcap_lib_close(lib);
		return ret;
	}
	*out = lib;
	return 0;
}

void pcap_lib_close(struct pcap_lib *lib)
{
	if (!lib)
		return;
	dlclose(lib->handle);
	xfree(lib, sizeof(*lib));
}

static int pcap_filter_copy(const struct pcap_program *prog,
			    struct pcap_filter *out)
{
	size_t size = (size_t)prog->bf_len * sizeof(*prog->bf_insns);

	if (!prog->bf_len)
		return -EINVAL;
	out->insns = xmalloc(size);
	if (!out->insns)
		return -ENOMEM;
	memcpy(out->insns, prog->bf_insns, size);
	out->len = prog->bf_len;
	return 0;
}

int pcap_lib_compile(struct pcap_lib *lib, const char *expr, int linktype,
		     struct pcap_filter *out, char *msg, size_t msg_size)
{
	struct pcap_program prog = {};
	struct pcap *p;
	int ret;

	memset(out, 0, sizeof(*out));
	msg[0] = '\0';
	p = lib->open_dead(linktype, PCAP_SNAPLEN);
	if (!p)
		return -ENOMEM;
	if (lib->compile(p, &prog, expr, 1, PCAP_NETMASK_UNKNOWN) < 0) {
		strscpy(msg, lib->geterr(p), msg_size);
		ret = -EINVAL;
	} else {
		ret = pcap_filter_copy(&prog, out);
		lib->freecode(&prog);
	}
	lib->close(p);
	return ret;
}

void pcap_filter_free(struct pcap_filter *filter)
{
	xfree(filter->insns, (size_t)filter->len * sizeof(*filter->insns));
	memset(filter, 0, sizeof(*filter));
}
