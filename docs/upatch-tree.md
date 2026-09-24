# Append-only BPM upatch tree

The target-side tree integration is optional. Configure it by creating
`/etc/shirudo/bpm/upatch-tree.conf`:

```ini
endpoint = oci://quay.io/example/shirudo-upatch-tree
reference = stable
```

When this file is absent, `shirudo upatch load` and `shirudo upatch unload`
retain their existing manual-loading behavior. A target timer invokes
`shirudo bpm tree sync` every 60 seconds; the command also supports
`--dry-run` and `--report=<path>`.

## Publication

The OCI manifest contains one signed JSON payload layer and one detached CMS
signature layer. The payload is globally ordered and contains no node
assignment:

```json
{
  "schema": 2,
  "tree_id": "production",
  "generation": 8,
  "parent_manifest_digest": "sha256:...",
  "base": {"seq": 0},
  "operations": [
    {
      "seq": 1,
      "op": "add",
      "id": "block-afalg",
      "selector": {
        "kernel_release_prefix": ["6.16", "6.18"],
        "architecture": ["x86_64"],
        "kconfig": {"CONFIG_BPF": ["y"]},
        "labels": {"env": ["prod"]}
      },
      "artifact": {
        "repository": "oci://quay.io/example/shirudo-upatch-tree",
        "manifest_digest": "sha256:...",
        "layer_digest": "sha256:...",
        "payload_sha256": "sha256:..."
      },
      "operation_digest": "sha256:..."
    }
  ],
  "head": {"seq": 1}
}
```

`operation_digest` is the SHA-256 digest of the canonical operation fields:
sequence, operation, ID, selector, and artifact metadata. It does not include
the digest field itself. The signed publication and OCI manifest digest
authenticate the ordered operation list; this version has no global tree-root
field.

`base.seq` and `head.seq` describe the retained operation range. The current
implementation requires the complete operation list from sequence zero, so
`base.seq` is zero. Operations must be contiguous and `head.seq` must equal
the last operation sequence, or `base.seq` for an empty operation list.

The operator-side `bpm tree append <package-file> <repository> --cert <cert>
--key <key>` command publishes immutable upatch artifacts and appends all tree-enabled
upatches from the package in Beefile declaration order. Multiple
`[[upatches]]` entries remain supported. A tree-enabled entry uses:

```toml
[upatches.tree]
id = "block-afalg"
load_artifact = "upatches/block-afalg.upatch"
unload_artifact = "upatches/block-afalg.unload.upatch"

[upatches.tree.selector]
kernel_release_prefix = ["6.16", "6.18"]
architecture = ["x86_64"]

[upatches.tree.selector.kconfig]
CONFIG_BPF = ["y"]

[upatches.tree.selector.labels]
env = ["prod"]
```

Entries without `[upatches.tree]` are legacy package entries and are not
published into the tree. The target never reads Beefiles or package archives.

## Target evaluation and measurement

The target verifies the manifest layer digests, CMS signature, publication
continuity, operation digest fields, immutable artifact manifest/layer
digests, and the `.upatch` payload hash. It evaluates selectors locally:

| Selector | Target source of truth |
| --- | --- |
| `kernel_release_prefix` | `uname(2).release`; any listed complete release-component prefix may match (for example, `6.1` matches `6.1.0` but not `6.18`) |
| `architecture` | `uname(2).machine`; any listed architecture may match |
| `kconfig` | `/proc/config.gz`, falling back to `/boot/config-<uname -r>`; any listed value for each key may match; `y`, `m`, and unset are normalized |
| `labels` | `/etc/shirudo/node.labels`, one `key=value` per line; any listed value for each key may match |

Lists use OR semantics within one selector dimension, while selector
dimensions and distinct Kconfig/label keys use AND semantics. For example,
`kernel_release_prefix = ["6.16", "6.18"]` matches either kernel family.

Operations are considered in ascending `seq`. A nonmatching operation only
advances the global cursor. A matching `add` or `delete` downloads its direct
immutable `.upatch` artifact, verifies it, and applies it through the normal
signed upatch path.

The local projection is a dedicated TPM NV-extend chain at
`SHIRUDO_TREE_NV_INDEX`; it folds only selected operation digests as
`SHA256(previous || operation_digest)`. Therefore the TPM projection value is
expected to differ between nodes with different selectors. The regular audit
chain remains separate. The control plane uses the reported projection hash,
sequence, generation, and manifest identity to assess node health; the target
does not need a `node_id` or a published per-node projection.

The sealed state also carries a software projection fold solely to preserve
the selected-operation cursor when a node is running without a TPM. It is
reported separately as `projection_root`; `projection_root_tpm` is null in a
sync report when no TPM value is available.

The sealed cursor and cached manifest state are stored in:

```text
/var/lib/shirudo/bpm/upatch-tree/state.json
/var/lib/shirudo/bpm/upatch-tree/tree-eventlog
/var/lib/shirudo/bpm/upatch-tree/pending.json
/var/lib/shirudo/bpm/upatch-tree/artifacts/<payload-sha256>.upatch
```

`shirudo status --json --include-tpm` reports the tree generation, cursor,
manifest digest, software projection, and live TPM projection. It checks the
tree eventlog replay against the live tree NV value. A live TPM value that
differs from the sealed projection state causes tree sync to stop before
applying further operations.

Snapshot compaction is deferred. If persistent cursor or eventlog state is
lost, the complete publication history must still be replayed to reconstruct
the TPM projection; removing the global tree-root calculation does not change
that recovery requirement.
