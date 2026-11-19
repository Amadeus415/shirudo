#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0006 -- .github/scripts/check-coccinelle.sh: a rule that matches fails the
# check with file, line, rule and message, one that does not passes it,
# a rule that can rewrite does with -D patch, a rule reads the headers
# its #spatch line asks for, on a throwaway repository, each rule taken
# from CERT C, each BPF hazard rule, each scrub rule and dead_store report
# a sample of what they refuse, a file a rule gives up on at its time
# limit is named rather than failed, and the tree itself.

cd "$(dirname "$0")/.."
. ./test-lib.sh
command -v git >/dev/null 2>&1 || test_skip_all "git not installed"
command -v spatch >/dev/null 2>&1 || test_skip_all "spatch not installed"
ROOT=$(cd .. && pwd)
S=$ROOT/.github/scripts/check-coccinelle.sh
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

R=$W/repo
mkdir -p "$R/testing/coccinelle" "$R/vendor"
git init -q "$R"
cp "$ROOT/testing/coccinelle/zero_init.cocci" \
	"$ROOT/testing/coccinelle/banned.cocci" "$R/testing/coccinelle/"
printf 'int f(void)\n{\n\tint a[4] = {0};\n\n\treturn a[0];\n}\n' >"$R/bad.c"
printf 'int g(void)\n{\n\tint a[4] = {};\n\n\treturn a[0];\n}\n' >"$R/good.c"
printf 'int h(void)\n{\n\treturn rand();\n}\n' >"$R/vendor/skip.c"

check() {
	(cd "$R" && git add -A && sh "$S" "$@") >"$W/out" 2>"$W/err"
}

test_expect_success 'a match fails the check and names file, line and rule' '
	! check &&
	grep -q "^zero_init: bad.c:3:" "$W/err" &&
	grep -q "1 of 2 rules matched" "$W/err"
'

test_expect_success 'the vendored sources are not checked' '
	! grep -q "skip.c" "$W/err"
'

test_expect_success 'a rule is named alone or by path' '
	check banned &&
	grep -q "1 rules, no match" "$W/out" &&
	! check testing/coccinelle/zero_init.cocci
'

test_expect_success 'a rule reads the headers its #spatch line asks for' '
	cp "$ROOT/testing/coccinelle/sizeof_ptr.cocci" "$R/testing/coccinelle/" &&
	mkdir -p "$R/include" &&
	printf "struct foo {\n\tchar *name;\n};\n" >"$R/include/foo.h" &&
	printf "#include \"foo.h\"\n\nvoid f(struct foo *x)\n{\n\tmemset(x->name, 0, sizeof(x->name));\n}\n" >"$R/member.c" &&
	! check sizeof_ptr &&
	grep -q "^sizeof_ptr: member.c:5:" "$W/err" &&
	rm -r "$R/testing/coccinelle/sizeof_ptr.cocci" "$R/include" "$R/member.c"
'

test_expect_success 'a rule rewrites what it finds with -D patch' '
	(cd "$R" && spatch -D patch --very-quiet --in-place \
		--sp-file testing/coccinelle/zero_init.cocci bad.c) &&
	grep -q "= {};" "$R/bad.c" &&
	check
'

# One case of what each rule taken from CERT C and ISO/IEC TS 17961
# refuses. A rule the tree gives no match proves nothing until it matches
# here.
CERT_RULES="errno_clobber positive_errno double_close wrong_test scaled_arith fclose_unchecked"
write_samples() {
	cat >"$1" <<'EOF'
int clobber_stored(const char *path, int other)
{
	int fd = open(path, O_RDONLY);

	close(other);
	if (fd < 0)
		return -errno;
	return fd;
}

int clobber_tested(int fd)
{
	if (fsync(fd)) {
		close(fd);
		return -errno;
	}
	return 0;
}

int positive(int x)
{
	if (x)
		return EINVAL;
	return 0;
}

int reuse(int fd)
{
	close(fd);
	return fsync(fd);
}

int untested(const char *path, int other)
{
	int fd;

	fd = open(path, O_RDONLY);
	if (other < 0)
		return -1;
	return fd;
}

unsigned int scaled(unsigned int *words)
{
	return *(words + sizeof(struct hdr));
}

int unflushed(const char *path)
{
	FILE *f = fopen(path, "w");

	if (!f)
		return -1;
	fputs("x", f);
	fclose(f);
	return 0;
}
EOF
}

test_expect_success 'each rule taken from CERT C reports its sample' '
	R2=$W/samples &&
	mkdir -p "$R2/testing/coccinelle" &&
	git init -q "$R2" &&
	for r in $CERT_RULES; do
		cp "$ROOT/testing/coccinelle/$r.cocci" "$R2/testing/coccinelle/" ||
			exit 1
	done &&
	write_samples "$R2/samples.c" &&
	! (cd "$R2" && git add -A && sh "$S") >"$W/out" 2>"$W/err" &&
	for r in $CERT_RULES; do
		grep -q "^$r: samples.c:" "$W/err" || exit 1
	done &&
	grep -q "6 of 6 rules matched" "$W/err"
'

# One case of each BPF hazard, and beside it the safe form, which no rule
# reports: the count of reports shows the safe forms stay quiet.
BPF_RULES="bpf_map_rmw bpf_cas_unchecked bpf_check_then_insert \
bpf_publish bpf_user_double_fetch bpf_map_use_after_delete"
write_bpf_samples() {
	cat >"$1" <<'EOF'
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} hits SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} cpu_hits SEC(".maps");

struct node {
	int filled;
};

static struct node *head;

void count_plain(void)
{
	__u32 zero = 0;
	__u64 *count;

	count = bpf_map_lookup_elem(&hits, &zero);
	if (count)
		(*count)++;
}

void count_percpu(void)
{
	__u32 zero = 0;
	__u64 *count;

	count = bpf_map_lookup_elem(&cpu_hits, &zero);
	if (count)
		(*count)++;
}

void count_atomic(void)
{
	__u32 zero = 0;
	__u64 *count;

	count = bpf_map_lookup_elem(&hits, &zero);
	if (count)
		__sync_fetch_and_add(count, 1);
}

void cas_ignored(__u32 *slot, __u32 old, __u32 new)
{
	__sync_val_compare_and_swap(slot, old, new);
}

int cas_checked(__u32 *slot, __u32 old, __u32 new)
{
	return __sync_val_compare_and_swap(slot, old, new) == old;
}

void insert_racy(__u32 *k, struct val *v)
{
	if (!bpf_map_lookup_elem(&vals, k)) {
		bpf_map_update_elem(&vals, k, v, BPF_ANY);
	}
}

void insert_exclusive(__u32 *k, struct val *v)
{
	if (!bpf_map_lookup_elem(&vals, k)) {
		bpf_map_update_elem(&vals, k, v, BPF_NOEXIST);
	}
}

void publish_once(struct node *n)
{
	n->filled = 1;
	WRITE_ONCE(head, n);
}

void publish_release(struct node *n)
{
	n->filled = 1;
	__atomic_store_n(&head, n, __ATOMIC_RELEASE);
	WRITE_ONCE(head, NULL);
}

int fetch_twice(const char *uptr)
{
	char a[16], b[16];

	bpf_copy_from_user_str(a, sizeof(a), uptr, 0);
	if (a[0] != 'x')
		return 0;
	bpf_probe_read_user(b, sizeof(b), uptr);
	return b[1];
}

int fetch_once(const char *uptr)
{
	char a[16];

	bpf_probe_read_user(a, sizeof(a), uptr);
	return a[0];
}

void count_decl(void)
{
	__u32 zero = 0;
	__u64 *count = bpf_map_lookup_elem(&hits, &zero);

	if (count)
		(*count)++;
}

void flags_task(struct task_struct *task)
{
	struct meta *m = bpf_task_storage_get(&tasks, task, 0, 0);

	if (m)
		m->flags |= 1;
}

__u64 read_after_delete(__u32 *k)
{
	struct val *v;

	v = bpf_map_lookup_elem(&vals, k);
	if (!v)
		return 0;
	bpf_map_delete_elem(&vals, k);
	return v->count;
}

__u64 read_before_delete(__u32 *k)
{
	struct val *v;
	__u64 n;

	v = bpf_map_lookup_elem(&vals, k);
	if (!v)
		return 0;
	n = v->count;
	bpf_map_delete_elem(&vals, k);
	if (!v)
		return 0;
	return n;
}

struct meta *flags_reassigned(struct sock *sk)
{
	struct meta *m = bpf_sk_storage_get(&socks, sk, 0, 0);

	if (m)
		return m;
	m = meta_create(sk);
	if (m)
		m->flags |= 1;
	return m;
}

void count_add(void)
{
	__u32 zero = 0;
	__u64 *count = bpf_map_lookup_elem(&hits, &zero);

	if (count)
		*count += 1;
}

void count_sum(void)
{
	__u32 zero = 0;
	__u64 *count = bpf_map_lookup_elem(&hits, &zero);

	if (count)
		*count = *count + 2;
}

void count_percpu_add(void)
{
	__u32 zero = 0;
	__u64 *count = bpf_map_lookup_elem(&cpu_hits, &zero);

	if (count)
		*count += 1;
}

void flags_inode(struct inode *inode)
{
	struct meta *m = bpf_inode_storage_get(&inodes, inode, 0, 0);

	if (m)
		m->flags = m->flags + 1;
}
EOF
}

test_expect_success 'each BPF rule reports its sample and spares the safe form' '
	R3=$W/bpf &&
	mkdir -p "$R3/testing/coccinelle" &&
	git init -q "$R3" &&
	cp "$ROOT/testing/coccinelle/bpf.macros" "$R3/testing/coccinelle/" &&
	for r in $BPF_RULES; do
		cp "$ROOT/testing/coccinelle/$r.cocci" "$R3/testing/coccinelle/" ||
			exit 1
	done &&
	write_bpf_samples "$R3/samples.bpf.c" &&
	! (cd "$R3" && git add -A && sh "$S") >"$W/out" 2>"$W/err" &&
	for r in $BPF_RULES; do
		grep -q "^$r: samples.bpf.c:" "$W/err" || exit 1
	done &&
	grep -q "6 of 6 rules matched" "$W/err" &&
	[ "$(grep -c "^bpf_[a-z_]*: samples.bpf.c:" "$W/err")" = 10 ]
'

# A secret left on the stack, and beside it the scrubbed form and a local
# that holds nothing secret, which no rule reports: one report for each
# return of the two that leave the secret.
write_scrub_samples() {
	cat >"$1" <<'EOF'
int kdf_left(const __u8 *seed)
{
	__u8 key[16];

	if (tpm_kdfa(seed, 32, "STORAGE", NULL, 0, NULL, 0, key, sizeof(key)))
		return -EIO;
	return use(key);
}

int kdf_scrubbed(const __u8 *seed)
{
	__u8 key[16];
	int ret = -EIO;

	if (tpm_kdfa(seed, 32, "STORAGE", NULL, 0, NULL, 0, key, sizeof(key)))
		goto out;
	ret = use(key);
out:
	memzero_explicit(key, sizeof(key));
	return ret;
}

int credential_left(const char *hex)
{
	__u8 cred[16];

	if (hex_decode(hex, cred, sizeof(cred)))
		return -EINVAL;
	return use(cred);
}

int digest_public(const char *hex)
{
	__u8 digest[32];

	if (hex_decode(hex, digest, sizeof(digest)))
		return -EINVAL;
	return use(digest);
}

int address_output(const char *hex)
{
	__u8 credential[16];

	if (getrandom(&credential, sizeof(credential), 0) < 0)
		return -EIO;
	return use(credential);
}

int partial_scrub(const char *hex)
{
	__u8 credential[16];

	if (hex_decode(hex, credential, sizeof(credential))) {
		memzero_explicit(credential, 1);
		return -EINVAL;
	}
	memzero_explicit(credential, 1);
	return 0;
}

void credential_fallthrough(void)
{
	__u8 credential[16];

	getrandom(credential, sizeof(credential), 0);
	use(credential);
}
EOF
}

test_expect_success 'each scrub rule reports its samples and spares the scrubbed forms' '
	R4=$W/scrub &&
	mkdir -p "$R4/testing/coccinelle" &&
	git init -q "$R4" &&
	cp "$ROOT/testing/coccinelle/scrub_missing.cocci" \
		"$R4/testing/coccinelle/" &&
	write_scrub_samples "$R4/samples.c" &&
	! (cd "$R4" && git add -A && sh "$S") >"$W/out" 2>"$W/err" &&
	grep -q "1 of 1 rules matched" "$W/err" &&
	[ "$(grep -c "^scrub_missing: samples.c:" "$W/err")" = 9 ] &&
	[ "$(grep -c "^[a-z_]*: " "$W/err")" = 9 ]
'

test_expect_success 'curl_slist_free reports lists freed without scrubbing' '
	R5=$W/curl-slist &&
	mkdir -p "$R5/testing/coccinelle" &&
	git init -q "$R5" &&
	cp "$ROOT/testing/coccinelle/curl_slist_free.cocci" \
		"$R5/testing/coccinelle/" &&
	printf "void headers_free(struct curl_slist *headers)\n{\n\tcurl_slist_free_all(headers);\n}\n" \
		>"$R5/samples.c" &&
	! (cd "$R5" && git add -A && sh "$S") >"$W/out" 2>"$W/err" &&
	[ "$(grep -c "^curl_slist_free: samples.c:" "$W/err")" = 1 ]
'

# The error of the first call is stored over before anything reads it;
# a value read on an error path, one read through its address and one
# the next store reads are all read first.
write_dead_store_samples() {
	cat >"$1" <<'EOF'
int lost(const char *buf)
{
	int ret;

	ret = parse_header(buf);
	ret = parse_body(buf);
	return ret;
}

int on_error_path(const char *buf)
{
	int ret;

	ret = -EBADMSG;
	if (!buf)
		goto out;
	ret = parse_body(buf);
out:
	return ret;
}

int through_address(int fd)
{
	int value;

	value = 0;
	read_into(fd, &value);
	value = 1;
	return value;
}

int accumulated(int n)
{
	int sum;

	sum = n;
	sum = sum + 1;
	return sum;
}
EOF
}

test_expect_success 'dead_store reports a store stored over and spares the reads' '
	R6=$W/dead-store &&
	mkdir -p "$R6/testing/coccinelle" &&
	git init -q "$R6" &&
	cp "$ROOT/testing/coccinelle/dead_store.cocci" "$R6/testing/coccinelle/" &&
	write_dead_store_samples "$R6/samples.c" &&
	! (cd "$R6" && git add -A && sh "$S") >"$W/out" 2>"$W/err" &&
	grep -q "^dead_store: samples.c:5:" "$W/err" &&
	[ "$(grep -c "^dead_store: samples.c:" "$W/err")" = 1 ]
'

# An option compared by hand, which option_by_hand reports, beside the
# standard output path "-", which is no option.
write_option_samples() {
	cat >"$1/samples.c" <<'EOF'
int by_hand(int argc, const char **argv)
{
	return argc > 1 && !strcmp(argv[1], "--json");
}

int to_stdout(const char *path)
{
	return !strcmp(path, "-");
}
EOF
}

test_expect_success 'option_by_hand reports an option compared outside the parser' '
	R7=$W/option &&
	mkdir -p "$R7/testing/coccinelle" &&
	git init -q "$R7" &&
	cp "$ROOT/testing/coccinelle/option_by_hand.cocci" \
		"$R7/testing/coccinelle/" &&
	write_option_samples "$R7" &&
	! (cd "$R7" && git add -A && sh "$S") >"$W/out" 2>"$W/err" &&
	grep -q "^option_by_hand: samples.c:3:" "$W/err" &&
	[ "$(grep -c "^option_by_hand:" "$W/err")" = 1 ]
'

# A spatch that gives up, as a rule with --timeout makes it: the file it
# gave up on is named and the check passes, while another failure fails.
write_fake_spatch() {
	cat >"$1" <<'EOF'
#!/bin/sh
for arg; do
	file=$arg
done
if [ -n "${FAKE_SPATCH_FAIL:-}" ]; then
	echo "parse error" >&2
else
	echo "timeout (we abort): $file" >&2
	echo "Fatal error: exception Coccinelle_modules.Common.Timeout" >&2
fi
exit 2
EOF
	chmod +x "$1"
}

test_expect_success 'a file a rule gives up on is named, not failed' '
	R7=$W/timeout &&
	mkdir -p "$R7/testing/coccinelle" "$W/bin" &&
	git init -q "$R7" &&
	cp "$ROOT/testing/coccinelle/dead_store.cocci" "$R7/testing/coccinelle/" &&
	printf "int x;\n" >"$R7/slow.c" &&
	write_fake_spatch "$W/bin/spatch" &&
	(cd "$R7" && git add -A && PATH="$W/bin:$PATH" sh "$S") \
		>"$W/out" 2>"$W/err" &&
	grep -q "dead_store: gave up on slow.c at its time limit" "$W/err" &&
	! (cd "$R7" && FAKE_SPATCH_FAIL=1 PATH="$W/bin:$PATH" sh "$S") \
		>"$W/out" 2>"$W/err" &&
	grep -q "dead_store: spatch failed" "$W/err"
'

test_expect_success 'the tree passes' '
	(cd "$ROOT" && sh "$S") >"$W/out" 2>"$W/err" &&
	grep -q "rules, no match" "$W/out"
'

test_done
