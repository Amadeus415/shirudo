#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0050 -- util/conditions.c: the KeyringSealed condition names the kind
# of keyring the anchor is in, a keyring other than the one init froze,
# or none where it froze one, makes the status tampered, and the register
# conditions tell a TPM that does not answer from one with no register.
# A hint names what to check, and a tampered node gets no remedy.

cd "$(dirname "$0")"
. ./test-lib.sh

H=helper/test-conditions

test_expect_success 'the bpf keyring init froze is the production anchor' '
	out=$(./$H 1 bpf 100 100 match) &&
	echo "$out" | grep -qx "status=ok" &&
	echo "$out" | grep -qx "KeyringSealed OK .bpf keyring serial 100, the one init recorded"
'

test_expect_success 'before init the keyring is pending, not tampered' '
	out=$(./$H 0 none -1 0 none) &&
	echo "$out" | grep -qx "status=lsm-off" &&
	echo "$out" | grep -qx "KeyringSealed WARN no .bpf keyring recorded (init not run?)"
'

test_expect_success 'a swapped keyring is tampered' '
	out=$(./$H 1 bpf 101 100 match) &&
	echo "$out" | grep -qx "status=tampered" &&
	echo "$out" | grep -qx "reason=the .bpf keyring was swapped" &&
	echo "$out" | grep -qx "KeyringSealed ALERT the live .bpf keyring (serial 101) is not the one init recorded (serial 100) (swapped?)"
'

test_expect_success 'a frozen bpf keyring that is gone is tampered' '
	out=$(./$H 1 bpf -1 100 match) &&
	echo "$out" | grep -qx "status=tampered" &&
	echo "$out" | grep -qx "KeyringSealed ALERT the .bpf keyring init recorded (serial 100) is gone (removed?)"
'

test_expect_success 'with the LSM off a gone keyring is still tampered' '
	./$H 0 bpf -1 200 none | grep -qx "status=tampered"
'

test_expect_success 'a register mismatch is the reason given first' '
	./$H 1 bpf -1 200 mismatch |
		grep -qx "reason=the TPM register does not match the eventlog"
'

test_expect_success 'no TPM answering is told apart from an unbound register' '
	out=$(./$H 1 bpf 100 100 notpm) &&
	echo "$out" | grep -qx "status=degraded" &&
	echo "$out" | grep -qx "reason=no TPM answered" &&
	echo "$out" | grep -qx "ChainIntact WARN no TPM answered, nothing to compare" &&
	echo "$out" | grep -qx "TpmMeasured WARN no TPM answered"
'

test_expect_success 'a TPM without a register this boot says so' '
	out=$(./$H 1 bpf 100 100 none) &&
	echo "$out" | grep -qx "status=degraded" &&
	echo "$out" | grep -qx "reason=no TPM register set up this boot" &&
	echo "$out" | grep -qx "ChainIntact WARN no TPM register set up this boot (init incomplete)" &&
	echo "$out" | grep -qx "TpmMeasured WARN NV index 0x01818E00 is not set up this boot"
'

test_expect_success 'a bound register is measured' '
	./$H 1 bpf 100 100 match |
		grep -qx "TpmMeasured OK NV index 0x01818E00 is set up and readable"
'

test_expect_success 'a healthy node carries no hint' '
	out=$(./$H 1 bpf 100 100 match) &&
	echo "$out" | grep -qx "hint=" &&
	! echo "$out" | grep -q " hint="
'

test_expect_success 'a tampered node gets the incident hint, not a remedy' '
	out=$(./$H 1 bpf 100 100 mismatch) &&
	echo "$out" | grep -q "^hint=shirudo considers this node tampered: do not retry" &&
	echo "$out" | grep -q "^ChainIntact hint=shirudo considers this node tampered" &&
	! echo "$out" | grep -qi "re-run\|re-issue"
'

test_expect_success 'the register mismatch names why when the caller knows' '
	out=$(./$H 1 bpf 100 100 mismatch "this boot'"'"'s eventlog cannot be replayed") &&
	echo "$out" | grep -qx "reason=this boot'"'"'s eventlog cannot be replayed" &&
	echo "$out" | grep -qx "ChainIntact ALERT this boot'"'"'s eventlog cannot be replayed (tamper?)"
'

test_expect_success 'an active config is OK' '
	./$H 1 bpf 100 100 match |
		grep -qx "ConfigActive OK config 0123456789ab.. is active"
'

test_expect_success 'a pending activation is reboot-pending with a reboot hint' '
	out=$(SHIRUDO_TEST_CONFIG_STATE=pending ./$H 1 bpf 100 100 match) &&
	echo "$out" | grep -qx "status=reboot-pending" &&
	echo "$out" | grep -qx "reason=a config activation is pending until the next reboot" &&
	echo "$out" | grep -qx "ConfigActive WARN the activation of config 0123456789ab.. is pending until the next reboot" &&
	echo "$out" | grep -q "^hint=reboot the node when convenient"
'

test_expect_success 'a config its records cannot vouch for is tampered' '
	for state in untrusted stale
	do
		out=$(SHIRUDO_TEST_CONFIG_STATE=$state ./$H 1 bpf 100 100 match) &&
		echo "$out" | grep -qx "status=tampered" &&
		echo "$out" | grep -qx "reason=the selected config cannot be verified against its records" &&
		echo "$out" | grep -q "^ConfigActive ALERT .*(tamper?)$" &&
		echo "$out" | grep -q "^hint=shirudo considers this node tampered" || return 1
	done
'

test_expect_success 'a pending activation does not hide a register mismatch' '
	SHIRUDO_TEST_CONFIG_STATE=pending ./$H 1 bpf 100 100 mismatch |
		grep -qx "status=tampered"
'

test_expect_success 'a degraded node points at the TPM or at init' '
	./$H 1 bpf 100 100 notpm | grep -q "^hint=no TPM answered: check" &&
	./$H 1 bpf 100 100 none | grep -q "^hint=shirudo init did not set up the TPM register this boot"
'

test_done
