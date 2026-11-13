..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: upatch authors

PHP worker guards
=================

PHP2Shell exposes two ways an Apache worker can use invalid PHP request
state. An out-of-memory exit during request startup can leave state that
the same request's shutdown path uses. Separately, a fatal error or late
diagnostic can leave a pointer to freed request memory in worker-wide
state; a later request on the same worker can use it before normal
initialization. PHP's `OOM
advisory <https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w>`__
and `stale-state
advisory <https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp>`__
describe those mechanisms. PHP's upstream fix changes the runtime.
shirudo's experiment leaves the vulnerable PHP binary in place and
attaches signed BPF programs to selected function entries.

::

   request -> guarded PHP entry -> signed BPF probe -> SIGKILL
                                                        |
                                                        v
                       next request <- new worker <- Apache

Two guards
----------

The broad guard stops the worker at PHP's OOM helper,
``_zend_bailout``, either main error callback, or the start of multipart
parsing. It treats every diagnostic and multipart request as potentially
unsafe. This gives a small, auditable set of hook sites, but ordinary
warnings and uploads also lose their connections.

The selective guard keeps the OOM and bailout probes. BPF task
storage marks the time from ``php_execute_script`` entry until
``php_request_shutdown`` entry; startup clears the mark too. A fatal
diagnostic always stops the worker. A nonfatal diagnostic is allowed
only while the application mark exists. Entry to
``php_session_initialize`` before script execution stops the early
session-upload path. An absent mark makes the decision stricter, and the
mark disappears when the task exits. This lets an ordinary warning and
an ordinary multipart form complete, while stopping the tested shutdown
warning and session-upload-progress request.

Both guards call ``bpf_send_signal(SIGKILL)`` at function entry and
count each reason and any failed signal request. On the pinned VM
kernel, the current worker handles the uprobe before returning to PHP;
the kernel's signal handling processes a successful ``SIGKILL`` before
PHP resumes through that function. This statement is specific to the
tested kernel configuration. A successful counter alone does not
establish that every unsafe PHP path reaches one of these hooks.

The operator builds each guard for the exact ``libphp.so`` ELF, signs
its loader and attachment information, and signs its unload directive.
shirudo rejects a load if the target build ID has changed. Successful
loads and unloads extend its TPM register. The two guards are loaded one
at a time.

Preventing a new program from starting
--------------------------------------

Both guards also include ``php-exec.h``. A uprobe at
``php_request_startup`` marks the current worker in BPF task storage.
That mark lasts for the task's lifetime; it is independent of the
selective guard's script-execution mark and survives request shutdown.
``lsm/task_alloc`` copies it to children and new threads, refusing the
creation if copying fails. ``lsm/bprm_check_security`` refuses exec by a
marked task with ``EPERM``, preserving any earlier LSM refusal.

::

   PHP request startup -> mark worker
                              |
                              +-> fork or new thread -> copy mark
                              |
                              +-> execve / execveat -> EPERM

The mark comes from entry to the exact PHP library the signed upatch
names. A process name does not grant or remove it. This leaves unrelated
programs and the Apache parent free to exec. Loading a guard does not
mark an existing request retroactively. Replace all old workers before
resuming traffic; the VM test replaces its single idle worker after
loading each guard. If marking fails, the probe requests ``SIGKILL``
and counts any failed signal request.

Legitimate subprocesses are refused too: a PHP application that starts
an image converter or a mailer will fail that operation. This policy
does not restrict code already running in the worker, files it can
access, sockets it can use, or an unmarked service it can ask for work.
PHP-FPM and a separate CGI daemon need their own coverage. The demo is
scoped to Apache prefork with non-ZTS ``mod_php``. Blocking exec adds
containment but does not establish complete PHP2Shell mitigation.

What the Apache VM shows
------------------------

We ran the same benign controls with no guard, the broad guard, and the
selective guard. The results below held on both vulnerable PHP builds. A
closed connection is reported as HTTP ``000`` by ``curl``; Apache served
the next healthy request from a replacement worker.

+----------------+----------------+----------------+----------------+
| Request        | No guard       | Broad          | Selective      |
+================+================+================+================+
| Healthy PHP    | 200            | 200            | 200            |
| page           |                |                |                |
+----------------+----------------+----------------+----------------+
| Ordinary       | 200            | Connection     | 200            |
| script warning |                | closed         |                |
+----------------+----------------+----------------+----------------+
| Ordinary       | 200            | Connection     | 200            |
| multipart form |                | closed         |                |
+----------------+----------------+----------------+----------------+
| Multipart form | 200            | Connection     | Connection     |
| using session  |                | closed         | closed         |
| upload         |                |                |                |
| progress       |                |                |                |
+----------------+----------------+----------------+----------------+
| Harmless fatal | Shutdown       | Connection     | Connection     |
| error          | completes      | closed         | closed         |
+----------------+----------------+----------------+----------------+
| Harmless       | Shutdown       | Connection     | Connection     |
| memory-limit   | completes      | closed         | closed         |
| error          |                |                |                |
+----------------+----------------+----------------+----------------+
| Harmless       | Shutdown       | Connection     | Connection     |
| shutdown       | completes      | closed         | closed         |
| warning        |                |                |                |
+----------------+----------------+----------------+----------------+

Each guard loaded through shirudo's signed-loader path and unloaded
through a signed directive. On PHP 8.4.26, the broad counters recorded
one OOM, three diagnostics, and two multipart requests; the selective
counters recorded one OOM, one fatal diagnostic, one diagnostic outside
application execution, and one early session operation. Both reported
zero signal errors. The same guard test passed on PHP 8.5.11. The
selective guard also reported zero task-state allocation errors. The
test ended with ``APACHE_PHP_GUARD_PASS`` on both builds.

These requests exercise the hook sites and show collateral damage. They
have not established a repeatable invalid memory access in unguarded PHP
followed by its absence under a guard. On PHP 8.5.11, an unguarded fatal
request followed by an early-config request returned from the same
worker; without a memory checker, that observation does not prove a
use-after-free. We will not claim full PHP2Shell mitigation from these
results.

Run the comparison
------------------

The ``upatches/php-bailout-experiment`` directory contains the operator
build, PHP pages, BPF sources and guest test. After building the shirudo VM
bundle and kernel described in its README, build the signed Apache fixtures
for either version:

.. code-block:: console

   operator$ BUNDLE="$PWD/build/test-vm/host-bundle-bpf-next-verity"
   operator$ upatches/php-bailout-experiment/apache/prepare-vm.sh "$BUNDLE"
   operator$ PHP_DEMO_VERSION=8.5.11 \
               upatches/php-bailout-experiment/apache/prepare-vm.sh "$BUNDLE"

Boot a fresh interactive VM with that bundle, then run
``apache/guard-test.sh`` inside it. Set ``PHP_DEMO_VERSION=8.5.11`` in
the guest for the second build. The script starts Apache on guest
loopback ``127.0.0.1:18080``, runs the three phases, checks BPF
counters, unloads the guards, and prints ``APACHE_PHP_GUARD_PASS``.
``apache/start-demo.sh`` leaves a normal PHP page running for an
interactive demonstration. The README has the full VM commands.

What remains to prove
---------------------

The next experiment needs a memory checker or a similarly direct
observation of the published invalid-state use without BPF. The
identical request sequence must then show the guard stopping the worker
before that operation, with no memory error. The OOM case and the
fatal-backtrace case need separate results. We must also audit other PHP
builds, extension paths, and SAPIs before making a broader claim.

For the demonstrated PHP 8.4 and 8.5 releases, the complete upstream fix
is PHP 8.4.27 and 8.5.12 respectively, followed by replacement of every
old Apache worker. Signed BPF can provide a fast, measured intervention
while that update is prepared; its measured behavior and its
availability cost should be reported together. `PHP
fix <https://github.com/php/php-src/commit/31c0ea7d>`__
