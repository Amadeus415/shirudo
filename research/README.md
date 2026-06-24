# research/ — reference material for the live-patching roadmaps

This directory holds primary sources that ground `PLAN.uspace.md` and
`PLAN.kspace.md` (the userspace- and kernel-space live-patching roadmaps). They
are kept here for convenience and citation stability; the roadmaps link to these
local copies alongside the upstream URLs.

## Contents

- **`borkmann-lsfmmbpf-2026-bpf-userspace-live-patching.pdf`**
  Daniel Borkmann (Isovalent / Cisco), *"netkit updates; BPF for user space live
  patching"*, LSF/MM/BPF 2026. Part 2 is the design north star for
  `PLAN.uspace.md`: a kernel-installed, trap-free trampoline that runs a signed
  BPF program JIT'd to position-independent code in a kernel-owned RX page mapped
  into the target process, with a BPF arena as the only kernel<->user comms
  channel, user-provided helpers (call-id -> relocation + BTF signature), and an
  ABI-preservation verifier pass. No target rebuild, no injected import library.
  Project author's own slides.

- **`dion-libpatch-dynamic-patching-userspace.pdf`**
  Olivier Dion, Mathieu Desnoyers, Mohammad Nassiri, Michel Dagenais
  (Polytechnique Montreal / EfficiOS / Ciena), *"Dynamic patching of binaries in
  user space"*. The academic foundation for trap-free, jump-based dynamic
  instrumentation (the `Libpatch` library): jump-pattern reachability, a fast
  trampoline allocator, out-of-line execution (OLX) buffers, a cross-modifying
  code protocol without stop-the-world, an executable-region garbage collector,
  and shadow-stack (Intel CET) compatibility. It enumerates the hard problems the
  kernel must own to deliver the talk's design. Third-party academic preprint,
  included for reference only; copyright remains with the authors/publisher.

## Provenance and licensing

The Libpatch paper is third-party material kept solely as a reference; it is not
covered by shirudo's BSD-2-Clause license and must not be treated as project
source. The LSF/MM/BPF 2026 deck is the project author's own presentation. Do
not vendor code from either into the shirudo binary; cite ideas and apply the
clean-room procedure (see `PLAN.md` "Vendoring and whiteroom reimplementation")
if any technique is ever implemented.
