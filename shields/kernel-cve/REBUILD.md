# Rebuilding exported kernel-CVE upatches

This builder-inputs bundle contains only the generated Beefile, top-level manifest, the shared `vmlinux.h`, BPF C sources, and these rebuild notes. Signed payloads, object files, logs, and per-record JSON metadata are intentionally omitted.

From a compatible Shirudo checkout, copy this directory beneath `shields/` and run the normal Jbrust shield builder for `kernel-cve` with the destination project's signer.

The generated Beefile includes entries with a recoverable `.bpf.c` source. All sources include `vmlinux.h`; the single copy at `kernel-cve/vmlinux.h` is found because the shield builder runs with `kernel-cve/` as its working directory. Do not add per-entry copies under `sources/*/observability/`.
