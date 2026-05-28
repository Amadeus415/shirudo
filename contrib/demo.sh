#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# contrib/demo.sh -- a narrated, screen-recordable walkthrough of shirudo,
# runnable straight from a bare git checkout. It plays BOTH roles (operator
# and target) on this one host and uses root@localhost over real SSH as the
# "remote target", so a newbie can watch the whole signed-BPF lifecycle:
# build + sign -> lock down the kernel -> prove unsigned BPF is refused ->
# roll out the signed mitigation -> observe -> roll back.
#
# Each step prints an explanation and the exact command FIRST, then runs it
# and shows the real output. Pauses between steps (Enter) let you pace a
# recording; pass --auto to run straight through.
#
# WARNING: this is NOT a dry run. It installs shirudo under /usr/local,
# writes keys + state under /var/lib/shirudo, mounts a private bpffs, and
# attaches BPF LSM programs that lock down bpf() on THIS host until reboot.
# Run it on a throwaway / lab machine, as root. See "Cleanup" at the end.

set -u

# ---------------------------------------------------------------------------
# Presentation primitives
# ---------------------------------------------------------------------------

AUTO=0			# --auto: no pauses, no typing effect
ASSUME_YES=0		# --yes:  skip the destructive-action confirmation
USE_COLOR=1		# --no-color
USE_TYPE=1		# --no-type: disable the typewriter effect
REMOTE="root@localhost"	# --remote=<dest>
FORCE_NO_TPM=0		# --no-tpm
DO_CLEANUP=0		# --cleanup
TYPE_DELAY=0.018

usage() {
	cat <<EOF
usage: contrib/demo.sh [options]

  -a, --auto         run without pausing between steps (also disables typing)
  -y, --yes          skip the "this modifies the system" confirmation
      --remote=DEST  ssh destination to use as the target (default: $REMOTE)
      --no-tpm       force degraded mode (do not use the TPM)
      --no-color     plain output
      --no-type      disable the typewriter effect, keep pauses
      --cleanup      undo demo state where possible, then exit
  -h, --help         this help

For a clean recording, run once first (to warm the build cache and accept
the localhost host key), then record the second run.
EOF
}

for arg in "$@"; do
	case "$arg" in
	-a|--auto)	AUTO=1 ;;
	-y|--yes)	ASSUME_YES=1 ;;
	--no-color)	USE_COLOR=0 ;;
	--no-type)	USE_TYPE=0 ;;
	--no-tpm)	FORCE_NO_TPM=1 ;;
	--cleanup)	DO_CLEANUP=1 ;;
	--remote=*)	REMOTE="${arg#*=}" ;;
	-h|--help)	usage; exit 0 ;;
	*)		printf 'unknown option: %s\n' "$arg" >&2; usage >&2; exit 2 ;;
	esac
done

[ "$AUTO" = 1 ] && USE_TYPE=0
# No terminal (piped, CI, 'tee') -> run unattended: no pauses, typing, colour.
[ -t 1 ] || { AUTO=1; USE_TYPE=0; USE_COLOR=0; }
[ -n "${NO_COLOR:-}" ] && USE_COLOR=0

if [ "$USE_COLOR" = 1 ] && command -v tput >/dev/null 2>&1 && tput setaf 1 >/dev/null 2>&1; then
	BOLD=$(tput bold); DIM=$(tput dim); RST=$(tput sgr0)
	RED=$(tput setaf 1); GRN=$(tput setaf 2); YEL=$(tput setaf 3)
	BLU=$(tput setaf 4); CYN=$(tput setaf 6)
else
	BOLD=; DIM=; RST=; RED=; GRN=; YEL=; BLU=; CYN=
fi

rule()  { printf '%s%s%s\n' "$DIM" "------------------------------------------------------------------------" "$RST"; }
say()   { printf '%s\n' "$*"; }
note()  { printf '%s    %s%s\n' "$YEL" "$*" "$RST"; }
good()  { printf '%s    %s%s\n' "$GRN" "$*" "$RST"; }
bad()   { printf '%s    %s%s\n' "$RED" "$*" "$RST"; }

banner() {
	printf '\n'
	printf '%s%s########################################################################%s\n' "$BOLD" "$BLU" "$RST"
	printf '%s%s##  %-66s##%s\n' "$BOLD" "$BLU" "$1" "$RST"
	printf '%s%s########################################################################%s\n' "$BOLD" "$BLU" "$RST"
}

step() {
	printf '\n'
	rule
	printf '%s%s  STEP %s  --  %s%s\n' "$BOLD" "$CYN" "$1" "$2" "$RST"
	rule
}

type_str() {
	local s=$1 i
	if [ "$USE_TYPE" = 1 ]; then
		for (( i = 0; i < ${#s}; i++ )); do
			printf '%s' "${s:i:1}"
			sleep "$TYPE_DELAY"
		done
		printf '\n'
	else
		printf '%s\n' "$s"
	fi
}

pause() {
	[ "$AUTO" = 1 ] && return 0
	printf '%s' "$DIM"
	# read from the terminal even when stdin is otherwise occupied
	read -r -p "      [Enter] " _ </dev/tty 2>/dev/null || true
	printf '%s' "$RST"
}

# tty_confirm <prompt> -- prompt on the controlling terminal; return 0 only on
# an affirmative answer. Returns 1 (without leaking an open error) when there
# is no usable tty, so non-interactive runs fall through to "declined".
tty_confirm() {
	local a=n

	if { true </dev/tty; } 2>/dev/null; then
		printf '%s' "$1"
		read -r a </dev/tty 2>/dev/null || a=n
	fi
	case "$a" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

# run "<command string>" -- show a green prompt + the command, pause, run it.
run() {
	local cmd=$1
	printf '\n'
	printf '%s%s  $ %s%s' "$BOLD" "$GRN" "$RST" "$BOLD"
	type_str "$cmd"
	printf '%s' "$RST"
	pause
	eval "$cmd"
	local rc=$?
	[ "$rc" -ne 0 ] && printf '%s    (exit %d)%s\n' "$DIM" "$rc" "$RST"
	return $rc
}

# ---------------------------------------------------------------------------
# Locate the repo and a scratch dir
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO" || { echo "cannot cd to repo root $REPO" >&2; exit 1; }

if [ ! -f examples/cve-2026-31431.bpf.c ]; then
	echo "this does not look like a shirudo checkout (no examples/cve-2026-31431.bpf.c)" >&2
	exit 1
fi

WORK="${TMPDIR:-/tmp}/shirudo-demo"
mkdir -p "$WORK"
UPATCH="$WORK/cve-2026-31431.upatch"
UNLOAD="$WORK/cve-2026-31431.unload.upatch"
NAME="cve-2026-31431"

# ---------------------------------------------------------------------------
# Reset to a clean slate (no reboot needed)
# ---------------------------------------------------------------------------

# True if a previous shirudo install/run left state that would taint a fresh
# demo run (a live LSM, the persisted keyring, or the on-disk tree).
prior_state() {
	mount 2>/dev/null | grep -q '/var/lib/shirudo/bpffs' && return 0
	[ -e /var/lib/shirudo ] && return 0
	command -v keyctl >/dev/null 2>&1 \
		&& keyctl show @u 2>/dev/null | grep -q 'keyring: shirudo' && return 0
	return 1
}

# Detach a live shirudo and wipe its state so 'genkey + init' start clean.
reset_state() {
	# Detaching the LSM = dropping its pinned links, which a PLAIN umount of
	# the private bpffs does. A LAZY umount does NOT detach (the links stay
	# alive and the seal keeps denying the rm below), so never use -l here.
	if mount 2>/dev/null | grep -q '/var/lib/shirudo/bpffs'; then
		run "umount /var/lib/shirudo/bpffs" \
			|| bad "could not unmount bpffs (an open fd holds it?); 'reboot' will reset it"
	fi
	# Drop the persisted kernel keyring: otherwise a fresh 'genkey' cert will
	# not match the keyring the old init populated, and loads fail (ENOKEY).
	if command -v keyctl >/dev/null 2>&1; then
		run "keyctl unlink %keyring:shirudo @u 2>/dev/null || true"
	else
		note "keyctl not found: cannot clear the 'shirudo' kernel keyring here."
		note "Install keyutils (or reboot) for a fully clean keyring -- otherwise a"
		note "fresh genkey + init may fail with ENOKEY against the stale keyring."
	fi
	# With the seal detached, the on-disk tree can be removed. The kernel's
	# link teardown after umount is asynchronous, so the seal can still deny
	# for a brief window -- retry rather than fail on a transient EPERM.
	if [ -e /var/lib/shirudo ]; then
		local tries=0
		printf '\n%s%s  $ %srm -rf /var/lib/shirudo%s\n' "$BOLD" "$GRN" "$RST$BOLD" "$RST"
		until rm -rf /var/lib/shirudo 2>/dev/null; do
			tries=$((tries + 1))
			if [ "$tries" -ge 20 ]; then
				bad "could not remove /var/lib/shirudo (reboot will reset it)"
				break
			fi
			sleep 0.3
		done
	fi
	rm -rf "$WORK" 2>/dev/null; mkdir -p "$WORK"
	note "The TPM NV measurement chain is append-only by design and is NOT reset"
	note "(neither does a reboot reset it); a later re-init continues the chain."
}

# ---------------------------------------------------------------------------
# Cleanup mode (reset only, then exit)
# ---------------------------------------------------------------------------

if [ "$DO_CLEANUP" = 1 ]; then
	banner "shirudo demo -- reset to a clean slate"
	say "This detaches the BPF LSM (drops its pinned links), clears the kernel"
	say "keyring, and removes /var/lib/shirudo plus the demo scratch dir. After"
	say "it, bpf() is unlocked and a fresh 'contrib/demo.sh' run starts clean --"
	say "no reboot required."
	if ! prior_state; then
		printf '\n'; good "Nothing to reset -- no shirudo state detected."
		exit 0
	fi
	if [ "$ASSUME_YES" != 1 ]; then
		tty_confirm "$(printf '\n%sProceed with reset? [y/N] %s' "$BOLD" "$RST")" \
			|| { echo "aborted (non-interactive? pass --yes)."; exit 0; }
	fi
	reset_state
	printf '\n'; good "Reset complete. bpf() is unlocked; re-run the demo for a clean slate."
	exit 0
fi

# ---------------------------------------------------------------------------
# Intro + the up-front walkthrough (commands shown before anything runs)
# ---------------------------------------------------------------------------

banner "shirudo -- secure BPF live-patching for the agentic era"

cat <<EOF

  ${BOLD}${CYN}shirudo${RST} ("shields") is a BPF-based security platform for a world where
  ${BOLD}AI agents find a threat and write the fix as code${RST} -- a small BPF live-patch
  like ${YEL}examples/${NAME}.bpf.c${RST} -- faster than a fleet can schedule a reboot.
  Servers, Kubernetes nodes, embedded and air-gapped devices all carry long
  patch/reboot cycles; shirudo closes that gap by deploying fixes ${BOLD}live${RST} --
  no reboot, and ${BOLD}no config DSL${RST} (agents work better with code).

  ${BOLD}Every live patch shirudo deploys is signed BPF${RST} -- whether it hardens the
  ${BOLD}Linux kernel${RST} (today) or a ${BOLD}userspace application${RST} (on the roadmap), it is the
  same signed artifact down one signature-gated path. There is no second way in.

  ${BOLD}${RED}The catch:${RST} live kernel patching is exactly what an attacker wants too.
  So once shirudo is active it locks down the bpf() syscall: ${BOLD}only signed BPF
  loads${RST} -- verified against a cert in shirudo's sealed kernel keyring --
  ${BOLD}even for root / CAP_SYS_ADMIN${RST}. The agent's signed fixes go in; an
  attacker's unsigned BPF does not. ${DIM}(threat T1 -- proven below.)${RST}

  ${BOLD}${YEL}The loop this demo walks:${RST}
    ${CYN}agent writes .bpf.c${RST} -> ${CYN}operator signs${RST} -> ${CYN}rollout to the fleet (SSH)${RST}
    -> ${CYN}observe${RST} -> ${CYN}agent decides${RST} -> ${CYN}signed rollback${RST}
    ${DIM}tight, auditable, reboot-free.${RST}

  ${BOLD}One binary, two roles${RST} -- like 'git push', signed artifacts flow outward:
    ${BOLD}${GRN}operator${RST}  the agent's side: holds the signing key; builds + signs
              .upatch artifacts; drives the fleet (rollout / nodes / status).
    ${BOLD}${GRN}target${RST}    holds only the PUBLIC cert (sealed keyring) + a TPM chain;
              ${BOLD}agentless${RST} -- one-shot CLI under sshd, no daemon, no socket.

  This demo plays ${BOLD}both roles${RST} on this host, with ${BOLD}${BLU}${REMOTE}${RST} as the
  remote target over real SSH.

  ${BOLD}${YEL}Commands, in order:${RST}
    ${YEL} 1.${RST} make ... && make install         -- build + install (operator+target)
    ${YEL} 2.${RST} ${CYN}shirudo genkey${RST}                  -- operator signing key + cert
    ${YEL} 3.${RST} ${CYN}shirudo build${RST} <agent's .bpf.c>  -- compile + sign the agent's fix
    ${YEL} 4.${RST} ${CYN}shirudo upatch info${RST}             -- review the fix offline (its source)
    ${YEL} 5.${RST} (load UNSIGNED BPF)             -- baseline: root can inject BPF today
    ${YEL} 6.${RST} ${CYN}shirudo init${RST}                    -- lock down bpf() (+ TPM chain)
    ${YEL} 7.${RST} (load UNSIGNED BPF)             -- now ${RED}DENIED${RST} -- attacker locked out
    ${YEL} 8.${RST} ${CYN}shirudo rollout${RST}                 -- deploy the SIGNED fix over SSH
    ${YEL} 9.${RST} ${CYN}shirudo status / list / get${RST}     -- observe loaded state + chain
    ${YEL}10.${RST} (open an AF_ALG socket)         -- the fix is enforcing
    ${YEL}11.${RST} ${CYN}shirudo build --unload / rollout${RST} -- signed rollback; loop closes

EOF

# ---------------------------------------------------------------------------
# Prerequisite probe
# ---------------------------------------------------------------------------

NO_TPM_FLAG=""
ROLLOUT_PRECHECK=""
PROBE_CC="${CC:-cc}"
command -v "$PROBE_CC" >/dev/null 2>&1 || PROBE_CC="clang"

say "${BOLD}Environment check:${RST}"
[ "$(id -u)" = 0 ] && good "root: yes" || { bad "root: NO -- shirudo init needs root. Re-run as root."; exit 1; }

if grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
	good "BPF LSM: present in /sys/kernel/security/lsm"
else
	bad  "BPF LSM: not listed -- needs a kernel with CONFIG_LSM including bpf."
	note "The demo will likely fail at 'shirudo init' on this kernel."
fi

if [ "$FORCE_NO_TPM" = 1 ]; then
	NO_TPM_FLAG=" --no-tpm"; ROLLOUT_PRECHECK=" --no-precheck"
	note "TPM: forced off (--no-tpm); the measurement chain will not be recorded."
elif [ -e /dev/tpmrm0 ]; then
	good "TPM: /dev/tpmrm0 present -- the NV measurement chain will be used if it can be defined"
else
	NO_TPM_FLAG=" --no-tpm"; ROLLOUT_PRECHECK=" --no-precheck"
	note "TPM: none -- running degraded (--no-tpm); LSM still enforces, chain not measured."
fi

USE_SSH=1
if ssh -o BatchMode=yes -o ConnectTimeout=5 "$REMOTE" true >/dev/null 2>&1; then
	good "SSH: $REMOTE reachable with key auth -- rollout will use real SSH"
else
	USE_SSH=0
	note "SSH: $REMOTE not reachable non-interactively; rollout will fall back to a"
	note "     local 'shirudo upatch load' (same code path, minus the transport)."
fi

command -v "$PROBE_CC" >/dev/null 2>&1 && good "C compiler: $PROBE_CC (for the unsigned-load + AF_ALG probes)" \
	|| note "no C compiler found; the live unsigned-load / AF_ALG probes will be skipped"

# 'status --include-tpm' reads the TPM chain; drop the flag in degraded mode.
if [ -n "$NO_TPM_FLAG" ]; then
	STATUS="shirudo status"
else
	STATUS="shirudo status --include-tpm"
fi

if prior_state; then
	note "A previous shirudo run was detected -- this run will reset it first."
fi

printf '\n'
if [ "$ASSUME_YES" != 1 ]; then
	printf '%sThis installs shirudo and locks down bpf() on THIS host (until reboot, or%s\n' "$BOLD$RED" "$RST"
	printf "%s'contrib/demo.sh --cleanup'). Any previous shirudo state is reset first.%s\n" "$BOLD$RED" "$RST"
	tty_confirm "$(printf '%sProceed? [y/N] %s' "$BOLD" "$RST")" \
		|| { echo "aborted (non-interactive? pass --yes)."; exit 0; }
fi

# Self-clean so a second run starts from a clean slate (no reboot needed).
if prior_state; then
	step 0 "Reset prior shirudo state (clean slate for this run)"
	say "A previous shirudo install/run was detected. Detaching its LSM and"
	say "wiping its state so this run starts clean -- this is exactly what"
	say "'contrib/demo.sh --cleanup' does."
	reset_state
fi

# ---------------------------------------------------------------------------
# Probe helpers (compiled once, reused before/after each transition)
# ---------------------------------------------------------------------------

UNSIGNED_PROBE=""
AFALG_PROBE=""

build_probes() {
	command -v "$PROBE_CC" >/dev/null 2>&1 || return 0

	cat > "$WORK/unsigned_load.c" <<'EOF'
/* Load a tiny, UNSIGNED BPF program via the raw bpf() syscall. */
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <sys/syscall.h>

int main(void)
{
	struct bpf_insn insns[] = {
		{ .code = 0xb7, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 }, /* r0 = 0 */
		{ .code = 0x95, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 }, /* exit   */
	};
	union bpf_attr attr;
	int fd;

	memset(&attr, 0, sizeof(attr));
	attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
	attr.insn_cnt  = 2;
	attr.insns     = (uint64_t)(unsigned long)insns;
	attr.license   = (uint64_t)(unsigned long)"GPL";

	fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	if (fd >= 0) {
		printf("ALLOWED: unsigned BPF program loaded (prog fd %d)\n", fd);
		close(fd);
		return 0;
	}
	printf("DENIED: unsigned BPF load refused: %s (errno %d)\n",
	       strerror(errno), errno);
	return 1;
}
EOF
	cat > "$WORK/afalg.c" <<'EOF'
/* Try to create an AF_ALG socket -- what CVE-2026-31431 mitigation blocks. */
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#ifndef AF_ALG
#define AF_ALG 38
#endif

int main(void)
{
	int fd = socket(AF_ALG, SOCK_SEQPACKET, 0);

	if (fd >= 0) {
		printf("ALLOWED: AF_ALG socket created (fd %d)\n", fd);
		close(fd);
		return 0;
	}
	printf("BLOCKED: AF_ALG socket refused: %s (errno %d)\n",
	       strerror(errno), errno);
	return 1;
}
EOF
	if "$PROBE_CC" -O2 -o "$WORK/unsigned_load" "$WORK/unsigned_load.c" 2>"$WORK/cc.log"; then
		UNSIGNED_PROBE="$WORK/unsigned_load"
	else
		note "could not compile the unsigned-load probe (see $WORK/cc.log); skipping it"
	fi
	if "$PROBE_CC" -O2 -o "$WORK/afalg" "$WORK/afalg.c" 2>>"$WORK/cc.log"; then
		AFALG_PROBE="$WORK/afalg"
	else
		note "could not compile the AF_ALG probe; skipping it"
	fi
}

build_probes

# ---------------------------------------------------------------------------
# 1. Build + install (operator + target on this host)
# ---------------------------------------------------------------------------

step 1 "Build and install shirudo (operator + target)"
say "shirudo is plain C. We build the core binary and the operator-only"
say "'shirudo-build' (the signer), then install both. 'shirudo build' is a"
say "libexec dispatch, so the signer MUST be installed for it to run -- the"
say "core target binary never signs."
if [ -x ./shirudo ] && [ -x ./tools/shirudo-build/shirudo-build ]; then
	note "binaries already built; (re)installing to refresh /usr/local copies."
else
	note "first build compiles vendored libbpf -- this can take a minute."
	run "make && make shirudo-build"
fi
run "make install && make install-operator"
good "shirudo installed at $(command -v shirudo)"

# ---------------------------------------------------------------------------
# 2. genkey (operator)
# ---------------------------------------------------------------------------

step 2 "Operator: forge the trust anchor  (shirudo genkey)"
say "The operator is the agent's trusted, credential-holding side. It creates"
say "an RSA-2048 key + self-signed X.509 cert -- the anchor for ${BOLD}everything an"
say "agent will ever deploy${RST}. The ${BOLD}${RED}private key never leaves the operator${RST}; only"
say "the public cert is shipped to targets, into a sealed kernel keyring."
run "shirudo genkey --force"
run "shirudo keys"

# ---------------------------------------------------------------------------
# 3. build (operator)
# ---------------------------------------------------------------------------

step 3 "An agent's fix, compiled + signed  (shirudo build)"
say "Picture an AI agent that just found a threat and ${BOLD}wrote the fix as a BPF"
say "program${RST} -- ${YEL}examples/${NAME}.bpf.c${RST} blocks userspace AF_ALG sockets via an"
say "lsm/socket_create hook. No config DSL: the policy ${BOLD}is${RST} the code. 'shirudo"
say "build' compiles it with clang, runs gen_loader, and ${BOLD}${GRN}CMS-signs${RST} the loader"
say "bytes into one self-contained, signed .upatch the fleet will accept."
run "shirudo build examples/${NAME}.bpf.c -o $UPATCH"

# ---------------------------------------------------------------------------
# 4. upatch info (offline inspection, either side)
# ---------------------------------------------------------------------------

step 4 "Review what the agent wrote  (shirudo upatch info)"
say "Before trusting an agent-authored patch, anyone -- a human reviewer or"
say "another agent -- can read its ${BOLD}full source straight from the artifact${RST},"
say "offline, with no kernel, keyring, or root. (The embedded source is"
say "advisory; the ${BOLD}${GRN}signature${RST} covers the loader bytes and the program is"
say "hash-locked at load, so what runs is exactly what was signed.)"
run "shirudo upatch info $UPATCH"

# ---------------------------------------------------------------------------
# 5. baseline: unsigned BPF load succeeds (pre-init)
# ---------------------------------------------------------------------------

step 5 "Baseline: any root can inject BPF today  (before shirudo)"
say "The flip side of live BPF patching: the very same primitive an agent uses"
say "to ${BOLD}fix${RST} a system, an attacker with root uses to ${BOLD}${RED}backdoor${RST} it -- rootkits,"
say "hiding processes, tampering. With no shirudo, unsigned BPF loads freely:"
if [ -n "$UNSIGNED_PROBE" ]; then
	run "$UNSIGNED_PROBE" && good "As expected: unsigned BPF loads freely today." \
		|| note "Unexpected -- some other LSM may already be restricting bpf()."
else
	note "(probe unavailable; skipping)"
fi

# ---------------------------------------------------------------------------
# 6. init (target)
# ---------------------------------------------------------------------------

step 6 "Target: lock down bpf()  (shirudo init)"
say "This is what a target runs once to enroll in the fleet. init pre-flights"
say "(root, BPF LSM, bpffs, cert, keyring, TPM), mounts a private bpffs,"
say "installs the cert into a ${BOLD}sealed${RST} keyring, attaches the ${BOLD}${GRN}signature-enforcing"
say "lsm/bpf hook${RST} plus filesystem-sealing hooks, and extends the TPM chain."
say "From here, ${BOLD}the kernel verifies a signature on every userspace BPF load${RST}."
run "shirudo init${NO_TPM_FLAG}"

# Did the TPM measurement chain actually come up? It can degrade even with a
# TPM present (e.g. owner auth set -> NV_DefineSpace fails), so check rather
# than assume, and narrate the chain honestly below.
CHAIN_ACTIVE=0
if [ -z "$NO_TPM_FLAG" ] \
   && ! shirudo status --include-tpm 2>/dev/null | grep -qi 'tpm chain:.*unavailable'; then
	CHAIN_ACTIVE=1
else
	note "TPM measurement is in degraded mode on this host (chain not recorded)."
	note "The LSM still fully enforces; only the audit chain is unavailable."
fi

# ---------------------------------------------------------------------------
# 7. unsigned BPF load is now denied
# ---------------------------------------------------------------------------

step 7 "The lockdown is live: UNSIGNED BPF is now refused"
say "Exactly the same unsigned load as Step 5 -- still root, same syscall:"
if [ -n "$UNSIGNED_PROBE" ]; then
	if run "$UNSIGNED_PROBE"; then
		bad "Unexpected: the unsigned load was allowed. Is the LSM attached?"
	else
		good "Refused with EACCES. Root can no longer inject unsigned BPF."
	fi
else
	note "(probe unavailable; skipping)"
fi
say ""
say "Read-only observability still works (status uses only read-only bpf cmds):"
run "$STATUS" || true

# ---------------------------------------------------------------------------
# 8. remote add + rollout the SIGNED upatch
# ---------------------------------------------------------------------------

step 8 "Deploy the agent's signed fix to the fleet  (shirudo rollout)"
say "The deploy half of the loop. Targets are addressed by registered name (or"
say "a Kubernetes-style label selector across a whole fleet), never raw"
say "user@host. 'rollout' SFTP-pushes the artifact and runs 'shirudo upatch"
say "load' on each target over SSH -- ${BOLD}agentless${RST}: no daemon, no open socket."
run "shirudo remote rm demo >/dev/null 2>&1; shirudo remote add demo $REMOTE"
run "shirudo remote list"
say ""
say "Push it. The kernel ${BOLD}${GRN}verifies the CMS signature${RST} against the sealed keyring"
say "before the loader runs -- ${BOLD}every deployed patch, kernel or (later) userspace,"
say "enters through this one signature-gated BPF_PROG_LOAD${RST}, nothing else:"
if [ "$USE_SSH" = 1 ]; then
	run "shirudo rollout $UPATCH demo${ROLLOUT_PRECHECK}"
else
	note "(no loopback SSH; using the identical local load path instead)"
	run "shirudo upatch load $UPATCH${ROLLOUT_PRECHECK}"
fi

# ---------------------------------------------------------------------------
# 9. observe
# ---------------------------------------------------------------------------

step 9 "Observe the loaded state  (status / upatch list / get)"
say "The signed program loaded fine -- the signature path is open; the"
say "unsigned path stays closed."
[ "$CHAIN_ACTIVE" = 1 ] && say "Every state change is measured into the TPM chain."
run "$STATUS" || true
run "shirudo upatch list" || true
say ""
say "'upatch get' reads the loaded program's source back FROM THE KERNEL"
say "(its BTF line_info) -- authoritative proof of what is actually running:"
run "shirudo upatch get $NAME" || true

# ---------------------------------------------------------------------------
# 10. prove the mitigation works
# ---------------------------------------------------------------------------

step 10 "Prove the mitigation: AF_ALG sockets are now blocked"
say "Before the rollout this succeeded. With the signed program attached to"
say "lsm/socket_create, the kernel now refuses AF_ALG socket creation:"
if [ -n "$AFALG_PROBE" ]; then
	if run "$AFALG_PROBE"; then
		bad "Unexpected: AF_ALG was allowed. Did the upatch attach?"
	else
		good "Blocked with EPERM -- the signed mitigation is enforcing."
	fi
else
	note "(probe unavailable; skipping)"
fi

# ---------------------------------------------------------------------------
# 11. rollback (signed UNLOAD directive)
# ---------------------------------------------------------------------------

step 11 "Close the loop: signed rollback"
say "The agent (or operator) decides the fix is no longer needed -- the kernel"
say "shipped the upstream patch, say -- and rolls it back. There is no separate"
say "'rollback' verb: removal is a rollout of a signed ${BOLD}UNLOAD directive${RST}, through"
say "the ${BOLD}${GRN}same signature-gated path${RST} as load, bound to the exact payload it removes."
PAYLOAD=$(shirudo upatch info --json "$UPATCH" 2>/dev/null \
	  | grep -oE '"payload_sha256":"[0-9a-f]+"' | head -1 | cut -d'"' -f4)
if [ -n "${PAYLOAD:-}" ]; then
	run "shirudo build --unload $NAME -o $UNLOAD --payload-sha256 $PAYLOAD"
else
	run "shirudo build --unload $NAME -o $UNLOAD"
fi
if [ "$USE_SSH" = 1 ]; then
	run "shirudo rollout $UNLOAD demo${ROLLOUT_PRECHECK}"
else
	run "shirudo upatch unload $NAME${ROLLOUT_PRECHECK}"
fi
say ""
say "AF_ALG works again -- the mitigation is gone, cleanly and measurably:"
if [ -n "$AFALG_PROBE" ]; then
	run "$AFALG_PROBE" && good "Allowed again. Rollback complete." \
		|| note "Still blocked -- the unload may not have detached the program."
else
	note "(probe unavailable; skipping)"
fi
say ""
if [ "$CHAIN_ACTIVE" = 1 ]; then
	say "The TPM chain has advanced once per transition (init, load, unload) --"
	say "an append-only audit trail an operator can predict and verify:"
else
	say "Final state (TPM measurement degraded on this host, so the chain shows"
	say "as unavailable; on a TPM with clear/known owner auth it records every"
	say "transition as an append-only, operator-verifiable audit trail):"
fi
run "$STATUS" || true

# ---------------------------------------------------------------------------
# Wrap up
# ---------------------------------------------------------------------------

banner "Demo complete -- the agent-deployment loop, closed"
cat <<EOF

  You just watched the full ${BOLD}${CYN}agent -> sign -> deploy -> observe -> rollback${RST} loop:

    ${GRN}-${RST} an agent's fix (a .bpf.c) compiled + ${BOLD}signed${RST} into one .upatch
    ${GRN}-${RST} the target locked down: ${BOLD}UNSIGNED BPF refused even for root${RST}
    ${GRN}-${RST} the ${BOLD}signed${RST} fix deployed live over SSH; the kernel verified it
    ${GRN}-${RST} observed it (status / list / get) and proved it blocked AF_ALG
    ${GRN}-${RST} rolled it back with a ${BOLD}signed${RST} UNLOAD directive
    ${GRN}-${RST} every transition measured into the TPM chain (when TPM is available)

  ${BOLD}Every patch -- kernel today, userspace apps on the roadmap -- was signed BPF
  through one signature-gated path.${RST} No reboot. No config DSL. No daemon. Tight
  enough for an agent to drive at fleet scale or on embedded devices
  (switches, robots, etc).

  ${BOLD}${YEL}Cleanup / reset (no reboot needed):${RST}
    The BPF LSM lockdown is live now. To return this host to a clean slate
    (detach the LSM, clear the keyring, remove /var/lib/shirudo + scratch):

      contrib/demo.sh --cleanup

    A reboot also resets the LSM + bpffs state (this demo installed no
    persistence unit). Re-running the demo auto-resets any prior state first,
    so you can just run it again. (The TPM NV chain is append-only by design
    and is not reset by either path.)

  Learn more:  PLAN.md, Documentation/threat-model.rst, Documentation/upatch-spec.rst
EOF
