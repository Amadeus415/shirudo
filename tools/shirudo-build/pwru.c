// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * shirudo pwru: the pwru upatch, carried built, with the pcap filter it
 * is given compiled by libpcap and translated into each of its probes,
 * signed without clang.
 */

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <linux/bpf.h>
#include <bpf/libbpf.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "bpm.h"
#include "cbpf.h"
#include "help.h"
#include "log.h"
#include "malloc.h"
#include "options.h"
#include "package.h"
#include "paths.h"
#include "pcap.h"
#include "pwru.h"
#include "upatches/pwru/pwru.h"

/* The name the decoder manifest of pwru.bpf.c gives. */
#define PWRU_UPATCH_NAME	"pwru"
#define PWRU_DECODER		"decoders/pwru.lua"

asm(".section .rodata, \"a\"\n"
	".balign 8\n"
	".global shirudo_pwru_bpf_o; shirudo_pwru_bpf_o:\n"
	".incbin \"upatches/pwru/pwru.bpf.o\"\n"
	".global shirudo_pwru_bpf_o_end; shirudo_pwru_bpf_o_end:\n"
	".global shirudo_pwru_lua; shirudo_pwru_lua:\n"
	".incbin \"upatches/pwru/" PWRU_DECODER "\"\n"
	".global shirudo_pwru_lua_end; shirudo_pwru_lua_end:\n"
	".previous\n");

enum pwru_opt {
	PWRU_OUTPUT,
	PWRU_KEYS_DIR,
};

static const struct opt_spec pwru_opts[] = {
	[PWRU_OUTPUT] = { "--output", 'o', 0, "<output.upatch>",
		"where to write the upatch instead of pwru.upatch in the "
		"current directory" },
	[PWRU_KEYS_DIR] = { "--keys-dir", 0, 0, "<dir>",
		"read signing_key.pem and cert.der from <dir>, where "
		KEYS_DIR_ENV " points otherwise" },
};

static const struct help_section pwru_sections[] = {
	HELP_OPTIONS("options:", pwru_opts),
};

static const struct help pwru_help = {
	.usage	    = "shirudo pwru [-o <output.upatch>] [--keys-dir <dir>] "
		      "[<pcap-filter>...]",
	.summary    = "Sign the pwru upatch, which records the packets the "
		      "pcap filter matches\nas they pass the kernel's network "
		      "stack. libpcap compiles the filter,\nand clang is not "
		      "needed. Without a filter, every packet is recorded.",
	.sections   = pwru_sections,
	.n_sections = ARRAY_SIZE(pwru_sections),
	.footer	    = "Load it with shirudo upatch load pwru.upatch on an "
		      "x86-64, arm64 or riscv64\ntarget, and read what it "
		      "records with shirudo upatch map pwru events.",
};

/* The probes of obj, which the first syscall program splices filter into. */
struct pwru_splice {
	const struct ebpf_prog	*filter;
	struct bpf_object	*obj;
	bool			done;
};

static struct pwru_splice *splice_of(long cookie)
{
	return (struct pwru_splice *)(__u64)cookie;
}

static bool prog_is_probe(const struct bpf_program *prog)
{
	const char *sec = bpf_program__section_name(prog);

	return str_has_prefix(sec, PWRU_FENTRY_PREFIX) ||
	       str_has_prefix(sec, PWRU_TP_PREFIX);
}

static bool prog_is_syscall(const struct bpf_program *prog)
{
	return strcmp(bpf_program__section_name(prog), "syscall") == 0;
}

static bool insn_is_stub(const struct bpf_insn *insn)
{
	return insn->code == (BPF_ALU64 | BPF_MOV | BPF_K) &&
	       insn->dst_reg == BPF_REG_0 && !insn->src_reg && !insn->off &&
	       insn->imm == PWRU_STUB_MAGIC;
}

/*
 * libbpf appends a probe's one subprogram, the stub, after its code,
 * where growing it moves no instruction the relocations and the BTF
 * line and function records name.
 */
static bool ends_in_stub(const struct bpf_insn *insns, size_t len)
{
	size_t i;

	if (len < 2 || !insn_is_stub(&insns[len - 2]) ||
	    insns[len - 1].code != (BPF_JMP | BPF_EXIT))
		return false;
	for (i = 0; i < len - 2; i++)
		if (insn_is_stub(&insns[i]))
			return false;
	return true;
}

/* The stub's two instructions at the end of a relocated probe become filter. */
static int probe_splice(struct bpf_program *prog,
			const struct ebpf_prog *filter)
{
	const struct bpf_insn *insns = bpf_program__insns(prog);
	size_t len = bpf_program__insn_cnt(prog);
	struct ebpf_prog spliced = {};
	int ret;

	if (!ends_in_stub(insns, len) || len > UINT32_MAX) {
		pr_err("pwru: probe %s does not end in the filter stub",
		       bpf_program__name(prog));
		return -EINVAL;
	}
	ret = ebpf_prog_append(&spliced, insns, (__u32)len - 2);
	if (!ret)
		ret = ebpf_prog_append(&spliced, filter->insns, filter->len);
	if (!ret)
		ret = bpf_program__set_insns(prog, spliced.insns, spliced.len);
	ebpf_prog_free(&spliced);
	return ret;
}

/*
 * The prepare callback of the syscall programs, in place of libbpf's,
 * which does nothing for them. A probe keeps libbpf's own, which has the
 * loader look up its BTF target on the target, so the splice happens
 * here: bpf_object__load() relocates every program before it loads the
 * first, and a syscall program loads before any probe.
 */
static int pwru_prepare(struct bpf_program *prog,
			struct bpf_prog_load_opts *opts, long cookie)
{
	struct pwru_splice *splice = splice_of(cookie);
	struct bpf_program *probe;
	int ret;

	if (splice->done)
		return 0;
	splice->done = true;
	bpf_object__for_each_program(probe, splice->obj) {
		if (!prog_is_probe(probe))
			continue;
		ret = probe_splice(probe, splice->filter);
		if (ret)
			return ret;
	}
	return 0;
}

/* What libbpf's own handler of the syscall section sets. */
static int pwru_setup(struct bpf_program *prog, long cookie)
{
	return bpf_program__set_flags(prog, bpf_program__flags(prog) |
				      BPF_F_SLEEPABLE);
}

/* libbpf loads programs in the order it iterates them. */
static int probes_load_late(struct bpf_object *obj)
{
	struct bpf_program *prog;

	bpf_object__for_each_program(prog, obj) {
		if (prog_is_syscall(prog))
			return 0;
		if (prog_is_probe(prog)) {
			pr_err("pwru: probe %s loads before every syscall program",
			       bpf_program__name(prog));
			return -EINVAL;
		}
	}
	pr_err("pwru: the object it carries has no syscall program");
	return -EINVAL;
}

static const char *link_name(int linktype)
{
	return linktype == PCAP_DLT_EN10MB ? "Ethernet frames" : "IP packets";
}

static int filter_translate(const struct sock_filter *insns, __u32 len,
			    int linktype, struct ebpf_prog *out)
{
	int ret = cbpf_translate(insns, len, out);

	if (ret)
		pr_err("pwru: the filter for %s cannot be translated: %s",
		       link_name(linktype), strerror(-ret));
	return ret;
}

/*
 * libpcap refuses to compile for IP packets a filter with any term on
 * what only a link-layer header carries, arp or ether host, even one
 * that an or joins to a term an IP packet can match: the filter then
 * refuses every IP packet, as pwru does.
 */
static int filter_add(struct pcap_lib *lib, const char *expr, int linktype,
		      struct ebpf_prog *out)
{
	static const struct sock_filter refuse_all[] = {
		{ BPF_RET | BPF_K, 0, 0, 0 },
	};
	char msg[PCAP_ERRBUF_SIZE];
	struct pcap_filter filter;
	int ret;

	ret = pcap_lib_compile(lib, expr, linktype, &filter, msg, sizeof(msg));
	if (ret == -EINVAL && linktype == PCAP_DLT_RAW) {
		pr_info("pwru: '%s' does not compile for IP packets, so none without a link-layer header is recorded: %s",
			expr, msg);
		return filter_translate(refuse_all, ARRAY_SIZE(refuse_all),
					linktype, out);
	}
	if (ret == -EINVAL)
		pr_err("pwru: '%s': %s", expr, msg);
	if (ret)
		return ret;
	ret = filter_translate(filter.insns, filter.len, linktype, out);
	pcap_filter_free(&filter);
	return ret;
}

/*
 * The body of the stub's subprogram, which takes data, data_end and l2:
 * if w3 == 0 goto ip; <the filter of Ethernet frames>; ip: <the filter
 * of IP packets>. Each part returns, so the first never runs into the
 * second.
 */
static int filter_compose(struct pcap_lib *lib, const char *expr,
			  struct ebpf_prog *out)
{
	static const struct bpf_insn branch = {
		.code = BPF_JMP32 | BPF_JEQ | BPF_K, .dst_reg = BPF_REG_3,
	};
	__u32 l2_len;
	int ret;

	ret = ebpf_prog_append(out, &branch, 1);
	if (!ret)
		ret = filter_add(lib, expr, PCAP_DLT_EN10MB, out);
	if (ret)
		return ret;
	l2_len = out->len - 1;
	if (l2_len > SHRT_MAX) {
		pr_err("pwru: the filter for %s is too long to jump over",
		       link_name(PCAP_DLT_EN10MB));
		return -E2BIG;
	}
	out->insns[0].off = (__s16)l2_len;
	return filter_add(lib, expr, PCAP_DLT_RAW, out);
}

static int filter_build(const char *expr, struct ebpf_prog *out)
{
	struct pcap_lib *lib;
	int ret;

	ret = pcap_lib_open(&lib);
	if (ret)
		return ret;
	ret = filter_compose(lib, expr, out);
	pcap_lib_close(lib);
	return ret;
}

/* The arguments joined by spaces, as tcpdump and pwru take a filter. */
static char *expr_join(const char *const *words, size_t n)
{
	size_t len = 0, off = 0, i, w;
	char *expr;

	for (i = 0; i < n; i++)
		len += strlen(words[i]) + 1;
	expr = xmalloc(len);
	if (!expr)
		return NULL;
	for (i = 0; i < n; i++) {
		w = strlen(words[i]);
		memcpy(expr + off, words[i], w);
		off += w;
		expr[off++] = i + 1 < n ? ' ' : '\0';
	}
	return expr;
}

static int pwru_sign_object(struct pwru_splice *splice, const char *output,
			    const char *pkey, const char *cert)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts,
		    .object_name = PWRU_UPATCH_NAME);
	const struct build_file decoders[] = {
		{ PWRU_DECODER, shirudo_pwru_lua,
		  (size_t)(shirudo_pwru_lua_end - shirudo_pwru_lua) },
	};
	struct bpf_object *obj;
	int ret;

	obj = bpf_object__open_mem(shirudo_pwru_bpf_o,
				   (size_t)(shirudo_pwru_bpf_o_end -
					    shirudo_pwru_bpf_o),
				   &open_opts);
	ret = libbpf_get_error(obj);
	if (ret) {
		pr_err("pwru: open the object it carries: %s", strerror(-ret));
		return ret;
	}
	ret = probes_load_late(obj);
	if (ret) {
		bpf_object__close(obj);
		return ret;
	}
	splice->obj = obj;
	return build_package_object(obj, output, PWRU_UPATCH_NAME, decoders,
				    ARRAY_SIZE(decoders), pkey, cert);
}

/* Without a filter, the stubs stay and libbpf's handlers do it all. */
static int pwru_sign(const struct ebpf_prog *filter, const char *output,
		     const char *pkey, const char *cert)
{
	LIBBPF_OPTS(libbpf_prog_handler_opts, handler_opts,
		    .prog_setup_fn = pwru_setup,
		    .prog_prepare_load_fn = pwru_prepare);
	struct pwru_splice splice = { .filter = filter };
	int handler = -1, ret;

	if (filter) {
		handler_opts.cookie = (long)ptr_to_u64(&splice);
		handler = libbpf_register_prog_handler("syscall",
						       BPF_PROG_TYPE_SYSCALL, 0,
						       &handler_opts);
		if (handler < 0)
			return handler;
	}
	ret = pwru_sign_object(&splice, output, pkey, cert);
	if (handler >= 0)
		libbpf_unregister_prog_handler(handler);
	return ret;
}

static int pwru_run(const char *const *words, size_t n_words,
		    const char *output, const char *keys_dir)
{
	struct ebpf_prog filter = {};
	char pkey[PATH_MAX], cert[PATH_MAX];
	char *expr = NULL;
	int ret;

	ret = key_paths(keys_dir_resolve(keys_dir), pkey, sizeof(pkey), cert,
			sizeof(cert));
	if (ret) {
		pr_err("pwru: invalid keys dir: %s", strerror(-ret));
		return 2;
	}
	if (build_check_keys(pkey, cert))
		return 1;
	if (n_words) {
		expr = expr_join(words, n_words);
		if (!expr)
			return 1;
		ret = filter_build(expr, &filter);
	}
	if (!ret)
		ret = pwru_sign(n_words ? &filter : NULL, output, pkey, cert);
	ebpf_prog_free(&filter);
	xstrfree(expr);
	return ret ? 1 : 0;
}

int build_pwru(int argc, const char **argv)
{
	const char *output = "pwru.upatch", *keys_dir = NULL;
	const char **words;
	struct opt_parser p;
	size_t n_words = 0;
	int ret, opt;

	words = xcalloc((size_t)argc, sizeof(*words));
	if (!words)
		return 1;
	OPT_INIT(&p, "pwru", pwru_opts, &pwru_help, argc, argv, 1);
	for (opt = opt_next(&p); opt != OPT_END; opt = opt_next(&p)) {
		switch (opt) {
		case PWRU_OUTPUT:
			output = p.value;
			break;
		case PWRU_KEYS_DIR:
			keys_dir = p.value;
			break;
		case OPT_ARG:
			words[n_words++] = p.value;
			break;
		case OPT_DONE:
			xfree(words, (size_t)argc * sizeof(*words));
			return 0;
		default:
			xfree(words, (size_t)argc * sizeof(*words));
			return EXIT_USAGE;
		}
	}
	ret = pwru_run(words, n_words, output, keys_dir);
	xfree(words, (size_t)argc * sizeof(*words));
	return ret;
}
