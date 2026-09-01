# Java SQL injection shield

This example packages a Byte Buddy Java agent as a Shirudo `type = "java"`
upatch. The agent instruments concrete JDBC `Statement` implementations and
blocks SQL containing simple structural SQL injection indicators.

The application is intentionally vulnerable: it concatenates a request value
into a SQL query against an embedded H2 database. The default value,
`admin' OR 1=1`, is blocked when the upatch is loaded.

## Build

From the repository root, build the example artifacts with:

```sh
JAVA_SQL_INJ_OUTPUT_DIR=/tmp/shirudo-java-sql-inj \
  shields/java_sql_inj/build.sh
```

The output contains the shaded agent and application JARs, Java load/unload
upatches, the `javaagent_metrics` BPF companion, and a BPM package. Java
upatches intentionally have no kernel loader instructions or kernel signature
in this v1 implementation.

## VM demo

`make vm` builds and stages the vulnerable application and the
`sql_inj_vuln` reproducer in every interactive test VM. It deliberately does
not load the upatches. Configure an OCI BPM repository when creating the VM,
then install the package through the target-local BPM client:

```sh
make vm VM_NAME=sql-inj-vuln \
  TEST_VM_BPM_OCI_REPOSITORY=example=oci://registry.example.com \
  TEST_VM_BPM_OCI_INDEX_CERT=/path/to/repository-index-cert.pem
make vm-ssh VM_NAME=sql-inj-vuln \
  VM_SSH_COMMAND='sudo shirudo bpm repo update'
make vm-ssh VM_NAME=sql-inj-vuln \
  VM_SSH_COMMAND='sudo shirudo bpm install example/java-sql-injection'
```

The BPM package loads the metrics companion before the Java upatch. Once it
is installed, run the reproducer; it prints the RASP alert and blocked-action
message:

```sh
make vm-ssh VM_NAME=sql-inj-vuln VM_SSH_COMMAND=sql_inj_vuln
```

A benign request remains allowed:

```sh
make vm-ssh VM_NAME=sql-inj-vuln \
  VM_SSH_COMMAND='sql_inj_vuln admin'
```

The companion records blocked requests by JAR ID, hook ID, and executable
device/inode. Dump the decoded metric locally, or send it to an OTLP metrics
endpoint:

```sh
make vm-ssh VM_NAME=sql-inj-vuln \
  VM_SSH_COMMAND='shirudo upatch map javaagent_metrics javaagent_arena --json=/tmp/javaagent.ndjson'
make vm-ssh VM_NAME=sql-inj-vuln \
  VM_SSH_COMMAND='shirudo upatch map javaagent_metrics javaagent_arena --otel'
```
