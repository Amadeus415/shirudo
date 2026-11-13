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

## Compare the broad and selective guards

The Apache preparation script also signs two guards for the exact
`libphp.so` build. The broad guard stops OOM, bailout, every diagnostic,
and every multipart request. The selective guard allows ordinary script
warnings and multipart forms while stopping OOM, bailout, fatal or early
diagnostics, and early session initialization. Both guards also prevent a
marked worker or its children from executing another program.

Build both tested fixture sets:

~~~sh
BUNDLE="$PWD/build/test-vm/host-bundle-bpf-next-verity"
with_memlock upatches/php-bailout-experiment/apache/prepare-vm.sh "$BUNDLE"
PHP_DEMO_VERSION=8.5.11 \
    with_memlock upatches/php-bailout-experiment/apache/prepare-vm.sh "$BUNDLE"
~~~

Run each version in a fresh VM. Use the same kernel and bundle paths as the
Apache demo above:

~~~sh
sudo env TEST_VM_KERNEL="$KERNEL/bzImage" \
    TEST_VM_KERNEL_ARTIFACT_DIR="$KERNEL" \
    TEST_VM_HOST_BUNDLE="$BUNDLE" TEST_VM_SUITE=php2shell \
    VM_MODE=interactive VM_NAME=php2shell-guards \
    testing/vm/run.sh

sudo env VM_NAME=php2shell-guards \
    VM_SSH_COMMAND='bash /mnt/shirudo-src/upatches/php-bailout-experiment/apache/guard-test.sh' \
    testing/vm/run.sh --ssh
~~~

For PHP 8.5.11, set `PHP_DEMO_VERSION=8.5.11` in `VM_SSH_COMMAND` and
boot a fresh VM with that fixture set. A passing comparison ends with
`APACHE_PHP_GUARD_PASS`.

The test checks a healthy page, an ordinary warning, an ordinary multipart
form, session upload progress, a harmless fatal error, a memory-limit error,
and a shutdown warning. It verifies signed load and unload, worker
replacement, the reason counters, and zero signal or task-state errors.

The broad guard drops the ordinary warning and multipart form. The selective
guard preserves those requests and drops the other tested error paths. These
controls show which boundaries the probes stop and the collateral damage of
each mode. They do not reproduce an invalid memory access, so they do not
establish complete PHP2Shell coverage.

`Documentation/upatches/php-worker-guards.rst` explains the design, test
results, limits, and relationship to the upstream PHP fix.

## Prevent workers from starting other programs

Both `php-guard-broad` and `php-guard-selective` include the same exec
restriction from `php-exec.h`. The original `php-bailout-apache` upatch
still contains only the bailout probe.

The restriction works like this:

```text
php_request_startup() in the signed libphp.so target
    -> mark this worker in BPF task storage

worker forks or creates a thread
    -> lsm/task_alloc copies the mark to the new task

marked task calls execve() or execveat()
    -> lsm/bprm_check_security returns -EPERM
    -> the new program does not start
```

The mark lasts until the task exits. Request shutdown does not clear it;
it is separate from the selective guard's temporary script-execution
mark. Changing a process name does not change the decision. Unmarked
processes, including the Apache parent and an administrator's shell,
keep their existing exec permissions. A fork that cannot copy the mark
fails with `ENOMEM`. If request startup cannot allocate the mark, the
probe requests `SIGKILL` and records any failure.

The load's build-ID check applies to the PHP library used to mark workers.
It does not match a process by its name or by the program it wants to
start. All new programs are refused from a marked worker, including
legitimate helpers such as image converters, mailers and CGI programs
launched directly by that worker. A separate, unmarked CGI daemon is not
covered.

Load one guard before allowing traffic. For an existing instance, stop
Apache and its existing child processes, load the guard, then start Apache.
Tasks that already exist are not marked retroactively; restarting a worker
does not cover a child that outlives it. The VM test uses one idle prefork
worker and replaces it after each load. This demo is for
non-ZTS `mod_php`, where PHP runs inside the Apache worker. It does not
establish coverage of PHP-FPM, another SAPI, or arbitrary Apache modules.

### What this does not stop

This check prevents a new executable from replacing the marked task's
program. It does not prevent PHP code or native code from running inside
an existing worker. It also does not restrict that worker's file access,
network access, or communication with an unmarked service. Those need
separate policies. The PHP error probes remain useful because they stop
selected error paths before those paths continue inside the worker.

The exec restriction adds containment. It does not turn the experiment
into a complete fix for PHP2Shell.
