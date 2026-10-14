# Linux observability

The `bpf-observability` package installs the `linux-observability` upatch
for observing executable activity, TCP connections, UDP destinations,
DNS answers, and IPv4 destination shield counters.

Run installation and map commands on the target machine. The target needs
Shirudo initialized before loading the package's upatch.

## Verify the signing key

Use the package reference supplied by your publisher. Replace the namespace
and version in this example:

```sh
PACKAGE=oci://quay.io/namespace/bpf-observability:0.0.1
shirudo bpm key fingerprint "$PACKAGE"
```

Compare the printed SHA-256 public-key (SPKI) fingerprint with the expected
fingerprint obtained from the publisher through a trusted channel. Proceed
only when they match. The fingerprint identifies the signing key; it is
not a checksum of the package.

You can also inspect a downloaded package:

```sh
shirudo bpm key fingerprint ./bpf-observability-0.0.1.bee
```

For first-time target setup, import the verified signing certificate before
initializing Shirudo:

```sh
sudo shirudo bpm key add "$PACKAGE"
sudo shirudo bpm key list
```

`key add` prints the imported key's fingerprint. Check that it matches the
expected fingerprint as well. On a target that already has an active key,
the package must use that key; `key add` refuses to replace it with a
different key.

## Install the package

Once Shirudo is initialized with the verified key, install from the registry:

```sh
sudo shirudo bpm install "$PACKAGE"
sudo shirudo upatch list
```

Installation downloads the package and loads its signed upatch. Confirm
that `linux-observability` appears in the loaded upatch list.

To read the package documentation without installing it:

```sh
shirudo bpm info "$PACKAGE"
```

## Dump BPF maps

List the maps available for this upatch:

```sh
sudo shirudo upatch map linux-observability
```

The package exposes these observability maps:

| Map | Contents |
| --- | --- |
| `exec_arena` | Executable identities and parent execution relationships |
| `tcp_arena` | TCP destination endpoints and connection counts by executable |
| `udp_arena` | UDP destination IPs and send counts by executable |
| `dns_arena` | DNS A and AAAA answers associated with IP addresses |
| `ipv4_shields` | IPv4 destination shield counters |

Dump a map by specifying its name. For example:

```sh
sudo shirudo upatch map linux-observability exec_arena
sudo shirudo upatch map linux-observability tcp_arena
sudo shirudo upatch map linux-observability udp_arena
sudo shirudo upatch map linux-observability dns_arena
sudo shirudo upatch map linux-observability ipv4_shields
```

Map dumps show at most 256 entries by default. Add `--show-full` to request
all entries:

```sh
sudo shirudo upatch map linux-observability tcp_arena --show-full
```

To save decoded records as newline-delimited JSON, pass an output path.
Each invocation appends a record using the package's Lua decoder:

```sh
sudo shirudo upatch map linux-observability dns_arena \
  --show-full --json=./dns.ndjson
```
