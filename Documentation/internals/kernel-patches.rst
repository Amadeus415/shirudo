..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Kernel developers, security reviewers

Carried kernel patches
======================

The kernel patches in :src:`kernel/` of the shirudo tree. The test kernel
build applies them; a production kernel needs the same changes.

Summary
-------

.. list-table::
   :header-rows: 1
   :widths: 34 22 22 22

   * - Patch
     - Author
     - In bpf-next
     - Architectures
   * - ``0001-tpm-Let-LSMs-inspect-userspace-commands.patch``
     - KP Singh
     - No
     - All
   * - ``0002-bpf-Read-security.bpf-xattrs-for-LSM-programs-without-the-caller-s-permission.patch``
     - Daniel Borkmann
     - No
     - All
   * - ``0003-bpf-Let-sleepable-LSM-programs-attach-to-the-remaining-inode-hooks.patch``
     - Daniel Borkmann
     - No
     - All
   * - ``0004-bpf-Treat-dentry-d_parent-as-a-trusted-pointer.patch``
     - Daniel Borkmann
     - No
     - All
   * - ``0005-bpf-Match-struct_ops-members-by-name-in-the-kernel.patch``
     - Alexei Starovoitov
     - No
     - All

"In bpf-next" was checked against the bpf-next tree at commit
``57fae4059380``: ``include/linux/lsm_hook_defs.h`` there has no
``tpm_command`` hook, ``fs/bpf_fs_kfuncs.c`` checks the calling task's
read permission before it returns a ``security.bpf.`` xattr to an LSM
program, the sleepable hook set of ``kernel/bpf/bpf_lsm.c`` lacks
``inode_mkdir``, ``inode_link``, ``inode_set_acl``, ``inode_remove_acl``,
``inode_file_setattr`` and ``inode_copy_up``, the verifier trusts
``d_inode`` of a dentry but not ``d_parent``, and a struct_ops map or
program can name its struct only by an id in the kernel's BTF.

The x86 ftrace fix the tree used to carry is upstream as
``31ac959c915c`` ("x86/ftrace: Mark jmp mode by clearing bit 63 of
trampoline address"), in bpf-next and in the bpf fixes tree for 7.4.
:doc:`/operate/plan/system-requirements` says which kernels still need
it.

How the test kernel applies them
--------------------------------

``make -C testing kernel`` passes ``KERNEL_PATCHES``, which defaults to
:src:`kernel/` when that directory holds patches.
:src:`testing/vm/build-kernel.sh` applies each patch in name order with
``git apply --index`` and commits it, and skips a patch whose reverse
already applies. A patch that applies neither way fails the build.

TPM command LSM hook
--------------------

Subject
    tpm: Let LSMs inspect userspace commands

Files
    ``drivers/char/tpm/tpm-dev-common.c``,
    ``include/linux/lsm_hook_defs.h``, ``include/linux/security.h``,
    ``security/security.c``.

What it changes
    ``tpm_common_write()``, the write handler of both ``/dev/tpm0`` and
    ``/dev/tpmrm0``, calls a new hook,
    ``security_tpm_command(file, command, command_len)``, after it has
    copied the command from userspace and validated the header, and
    before it sends or queues the command. ``command_len`` is the length
    the header declares, so trailing bytes of the write are not part of
    the decision; the command stays in the device buffer until the hook
    returns. The patch also refuses a header whose declared length is
    smaller than the header itself.

Why shirudo needs it
    The key that authorizes extensions of shirudo's NV register lives in
    the TPM and is recreatable by any process that knows its public input,
    which the identity map holds. A guard on the key cannot work, so
    ``lsm/tpm_command`` guards the command: it refuses
    ``TPM2_NV_Extend`` of the frozen index to tasks without runtime
    authority. A check when the device is opened would miss descriptors
    opened earlier or inherited from another process; the hook sees every
    command. :doc:`measurement-register` explains the writer.

Without it
    The kernel's BTF has no ``bpf_lsm_tpm_command``, so the ``bpf2``
    object fails to load and ``init`` fails at "loading enforcement". The
    boot is not stopped, and the target runs without enforcement, as
    :doc:`boot-flow` describes.

Label reads without the caller's permission
-------------------------------------------

Subject
    bpf: Read security.bpf xattrs for LSM programs without the caller's
    permission

Files
    ``fs/bpf_fs_kfuncs.c``.

What it changes
    ``bpf_get_dentry_xattr()`` and ``bpf_get_file_xattr()`` check that
    the calling task may read the inode before they return an extended
    attribute, for ``user.`` and ``security.bpf.`` names alike. The
    patch skips that check for ``security.bpf.`` names, which a BPF LSM
    program keeps for itself, as SELinux, Smack and EVM read their
    labels with ``__vfs_getxattr()`` in kernel context. ``user.`` names
    keep the check.

Why shirudo needs it
    The seal reads ``security.bpf.shirudo`` in the hooks that decide the
    calling task's operation, and that task is the one the seal may
    refuse. With the check, the task's read permission decides whether
    the seal sees the label, and root arranges a read that fails: an
    idmapped bind mount shows its files as another id's, an ACL grants
    another id a write without a read, a file system uid set with
    ``setfsuid()`` keeps ``CAP_SYS_ADMIN`` without the DAC capabilities,
    and another LSM's ``inode_permission`` policy refuses the read.
    :doc:`seal` explains the verdict.

Without it
    The seal loads and runs. A label read that fails with ``EACCES`` or
    ``EPERM`` is decided by the mark of the inode, or of the directory
    the operation changes, and a labeled inode without a mark looks
    unlabeled to the seal. :doc:`seal` lists this under its limits.

Sleepable programs on the remaining inode hooks
-----------------------------------------------

Subject
    bpf: Let sleepable LSM programs attach to the remaining inode hooks

Files
    ``kernel/bpf/bpf_lsm.c``.

What it changes
    The kernel keeps a list of the LSM hooks that take a sleepable BPF
    program. The patch adds ``inode_mkdir``, ``inode_link``,
    ``inode_set_acl``, ``inode_remove_acl``, ``inode_file_setattr`` and
    ``inode_copy_up`` to it. Each is called from process context with
    the inode lock held, as the hooks already in the list are, and may
    sleep.

Why shirudo needs it
    The seal reads labels with ``bpf_get_dentry_xattr()``, which sleeps,
    so only a sleepable program can decide an operation by a label.
    ``lsm.s/inode_mkdir`` and ``lsm.s/inode_link`` read the label of the
    directory the entry goes into, ``lsm.s/inode_set_acl``,
    ``lsm.s/inode_remove_acl`` and ``lsm.s/inode_file_setattr`` the
    label of the inode they change, and ``lsm.s/inode_copy_up`` the
    label of the inode an overlay copies up, instead of a mark that an
    eviction of the inode empties.

Without it
    The kernel refuses the ``lsm.s/`` form of those programs, so the
    ``seal`` object fails to load and ``init`` fails at "loading
    enforcement", with the result the TPM command hook describes.

Trusted dentry parent
---------------------

Subject
    bpf: Treat dentry->d_parent as a trusted pointer

Files
    ``kernel/bpf/verifier.c``.

What it changes
    The verifier lists the fields of a kernel structure that a program
    may read as trusted pointers. For ``struct dentry`` it lists
    ``d_inode``; the patch adds ``d_parent`` beside it, as trusted or
    null, so a program checks it for NULL before use. The parent of a
    dentry an inode hook receives is stable while the hook runs, under
    the parent's inode lock the caller holds, and is never NULL, since
    the root's points to itself.

Why shirudo needs it
    ``inode_create``, ``inode_mkdir``, ``inode_symlink``,
    ``inode_mknod``, ``inode_link`` and ``inode_rename`` receive the
    directory an entry goes into as a ``struct inode`` and the entry as
    a dentry. ``bpf_get_dentry_xattr()`` takes a dentry, and the only
    one the seal has for the directory is ``dentry->d_parent``. The
    seal reads the directory's label from it and refreshes the
    directory's mark on the way, which ``inode_init_security`` labels
    the new inode from.

Without it
    The verifier refuses ``d_parent`` as the kfunc's argument, so the
    ``seal`` object fails to load and ``init`` fails at "loading
    enforcement", with the result the TPM command hook describes.

struct_ops by name
------------------

Subject
    bpf: Match struct_ops members by name in the kernel

Files
    ``include/linux/bpf.h``, ``include/uapi/linux/bpf.h``,
    ``kernel/bpf/bpf_struct_ops.c``, ``kernel/bpf/syscall.c``,
    ``tools/include/uapi/linux/bpf.h``.

What it changes
    ``BPF_MAP_CREATE`` of a ``BPF_MAP_TYPE_STRUCT_OPS`` map takes
    ``btf_fd``, ``btf_value_type_id`` and ``value_size`` of a struct in
    the BTF of the object, ``tcp_congestion_ops`` or
    ``tcp_congestion_ops___v2``. The kernel finds its struct_ops of the
    same name, without the ``___`` suffix, in vmlinux or a module.
    ``BPF_PROG_LOAD`` of a ``BPF_PROG_TYPE_STRUCT_OPS`` program takes the
    object's BTF as ``attach_btf_obj_fd``, that struct as
    ``attach_btf_id`` and the index of its member as
    ``expected_attach_type``, and the kernel replaces them with its own
    struct and the member of the same name. ``BPF_MAP_UPDATE_ELEM``
    takes the object's struct with the program descriptors in it and
    copies each member to the kernel's member of the same name. A member
    the kernel lacks is skipped when it is zero and refused when it is
    not. The kernel refused these calls before, so nothing changes for
    a loader that passes the kernel's ids. Alexei Starovoitov proposed
    it on the bpf list.

Why shirudo needs it
    libbpf matches a struct_ops by name in userspace, against the BTF
    of the running kernel, and passes the ids and offsets it finds. A
    signed loader is generated on the operator and cannot know them;
    with the patch it passes only what the object's BTF holds, which the
    signature covers. ``struct_ops`` upatches need it, see
    :doc:`/upatches/write/attach-kinds`. Its libbpf half is the local
    change in ``vendor/libbpf/README.md``.

Without it
    The kernel refuses the struct_ops map or program the loader creates,
    so a ``struct_ops`` upatch fails inside the loader as
    ``verifier_rejected``. Other upatches are not affected.

Related
-------

- :doc:`kernel-interfaces` for the other kernel requirements
- :doc:`/contribute/testing/testing` for building and booting the test kernel
