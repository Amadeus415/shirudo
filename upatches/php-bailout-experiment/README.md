# PHP bailout experiment

This is an experiment in containing PHP2Shell with a signed Shirudo upatch.
It is not a fix for PHP. Upgrade PHP to a fixed upstream release before
using a service in production.

## How the upatch works

The BPF program attaches a uprobe to the entry of _zend_bailout in one PHP
executable. Each time that function is entered, it requests SIGKILL for the
current process. It also counts calls and failed signal requests:

~~~c
value = bpf_map_lookup_elem(&stats, &key);
if (value)
	__sync_fetch_and_add(&value->hits, 1);
err = bpf_send_signal(9);
if (err && value)
	__sync_fetch_and_add(&value->signal_errors, 1);
~~~

The program does not rewrite PHP memory or skip a PHP instruction. It asks
the kernel to kill a process that reaches the bailout path. That includes
ordinary fatal errors, so this may reduce service availability. A successful
bpf_send_signal call does not prove that PHP stopped before executing more
code. The test below checks that timing for a small fixture on one kernel.

Shirudo signs the BPF loader and its attach details. At load time it checks
the target ELF's GNU build ID against the signed value. A changed binary is
refused. The signature does not make the target binary immutable after load,
and replacing a pathname does not move an existing uprobe to a new inode.
Shirudo measures each successful load and unload in its TPM register.

## Try it in the Shirudo VM

This recipe runs on x86-64. It downloads the PHP 8.4.26 source archive from
php.net, checks its SHA-256, and builds a small CLI binary with a GNU build
ID. It also builds a tiny C fixture with the same function name. No
PHP2Shell payload is used.

First prepare a working Shirudo test VM bundle and kernel, as described in
Documentation/upatches/testing.rst. From the root of this checkout, the
usual build command is:

~~~sh
make -j"$(nproc)" -C testing test-vm-bundle
~~~

Then build and sign the two experimental upatches with that bundle's test
key. The script writes the upatches, unload directives, and test binaries
into the host bundle. The private key stays outside the guest.

~~~sh
BUNDLE="$PWD/build/test-vm/host-bundle-bpf-next-verity"
upatches/php-bailout-experiment/prepare-vm.sh "$BUNDLE"
~~~

Shirudo keeps signing keys out of swap. If either build command says
"cannot lock process memory", the shell's memory-lock limit is too low.
Run those two commands through this helper, which raises the limit and then
runs them as your normal user:

~~~sh
with_memlock() {
    sudo prlimit --memlock=unlimited -- \
        setpriv --reuid="$(id -u)" --regid="$(id -g)" --init-groups \
        env HOME="$HOME" "$@"
}
with_memlock make -j"$(nproc)" -C testing test-vm-bundle
with_memlock upatches/php-bailout-experiment/prepare-vm.sh "$BUNDLE"
~~~

Run the opt-in test family in a fresh VM:

~~~sh
KERNEL="$PWD/artifacts/bpf-next-kernel-debs"
sudo env TEST_VM_KERNEL="$KERNEL/bzImage" \
    TEST_VM_KERNEL_ARTIFACT_DIR="$KERNEL" \
    TEST_VM_HOST_BUNDLE="$BUNDLE" \
    TEST_VM_SUITE=php2shell \
    VM_NAME=php2shell-demo \
    testing/vm/run.sh
~~~

The command prints PASS only when Shirudo initializes from the initrd and
the complete test succeeds. Its main log is
build/test-vm/vms/php2shell-demo/result/verity/t3115-php2shell-experiment.sh.log.
The load, unload, status and map reports are under
build/test-vm/vms/php2shell-demo/result/php2shell/.

The test checks this sequence:

1. Before loading, 100 serial and 100 concurrent fixture calls reach their
   marker. Healthy PHP exits normally; benign memory exhaustion and a
   fatal error run their shutdown handlers.
2. Changing one byte in the PHP build ID makes Shirudo reject the signed
   load as binary_mismatch. The original binary is then restored.
3. Both signed upatches load. The same 200 fixture children die by SIGKILL
   before writing their marker. Healthy PHP still exits normally. The two
   PHP error cases die by SIGKILL before their shutdown handlers. The map
   must show 200 fixture hits, 2 PHP hits and zero signal errors.
4. The signed unload directives remove both probes. The same controls
   return to their baseline behavior.

The test keeps its output and downloaded PHP under build/, outside Git.
prepare-vm.sh must run again after rebuilding the VM bundle, because each
bundle has its own signing key.

## Apache worker demo

The CLI test above checks Shirudo's load path. This second demo runs
PHP 8.4.26 as Apache's `mod_php` on an x86-64 Shirudo VM. It uses the
prefork MPM, one worker, and a listener on `127.0.0.1:18080`. The
operator builds `libphp.so` in a Docker container from the same
SHA-256-checked PHP source and signs a probe for that library's build
ID. The VM installs Apache and copies the library to the exact path
named by the signed probe.

Prepare the same VM bundle as above, then run:

~~~sh
BUNDLE="$PWD/build/test-vm/host-bundle-bpf-next-verity"
with_memlock upatches/php-bailout-experiment/apache/prepare-vm.sh "$BUNDLE"

KERNEL="$PWD/artifacts/bpf-next-kernel-debs"
sudo env TEST_VM_KERNEL="$KERNEL/bzImage" \
    TEST_VM_KERNEL_ARTIFACT_DIR="$KERNEL" \
    TEST_VM_HOST_BUNDLE="$BUNDLE" TEST_VM_SUITE=php2shell \
    VM_MODE=interactive VM_NAME=php2shell-apache \
    testing/vm/run.sh

sudo env VM_NAME=php2shell-apache \
    VM_SSH_COMMAND='bash /mnt/shirudo-src/upatches/php-bailout-experiment/apache/guest-test.sh' \
    testing/vm/run.sh --ssh

sudo env VM_NAME=php2shell-apache testing/vm/run.sh --stop
~~~

The host needs Docker and the guest needs network access to install
Apache. The demo starts Apache directly. This also lets a checkout under
`/tmp` supply the module even when the Apache systemd service uses a
private `/tmp`. The guest script stops Apache and unloads
the signed upatch when it finishes.

The script makes only local, benign HTTP requests. Before loading,
fatal and memory-limit errors run the PHP shutdown handler in the
same worker. With the probe loaded, those two requests lose their
connections, their shutdown marker is absent, and a new worker serves
the next healthy request. It checks for two probe hits and zero signal
errors. Signed unload restores the original behavior. A passing run
ends with `APACHE_PHP_BAILOUT_DEMO_PASS`.

In a fresh VM using kernel CI run 40839802208, the baseline requests
all used worker PID 2953. The two guarded errors closed their
connections; the next healthy request used PID 3024. Shirudo reported
`{ hits=2, signal_errors=0 }` and measured both load and unload.

## Scope of the result

This experiment was tested with the PHP CLI binary and fixture above on an
x86-64 Shirudo VM using kernel CI run 40839802208, repository commit
e28420aa2dae03e7c787af5fbd4128583533319f. The signed load, both
counters, the build-ID refusal and both signed unloads passed.

The complete fix is to upgrade to a patched PHP release, such as 8.4.27,
and restart every Apache worker. The upstream changes cover more request
state and error paths than this one probe. The benign tests here do not
exercise a PHP2Shell payload or establish protection against every path.

Code may run before the bailout probe, and some error paths never enter
_zend_bailout. The probe does not repair state already retained by a
worker. The Apache/libphp demo above covers non-ZTS prefork only. FPM,
extensions, JIT, ZTS, other architectures and other kernel scheduling
behavior remain untested. Sign separately for the ELF each worker maps.

Upstream advisories:
- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
