# JJWT Byte Buddy Guard

This package contains a Byte Buddy Java agent that rejects JJWT compact tokens
with an empty third/signature segment, for example:

```text
eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.
```

The agent targets `io.jsonwebtoken.impl.DefaultJwtParser.parse(String)` and is
intended as a temporary runtime mitigation for older JJWT deployments.

## Use at JVM startup

```bash
java -javaagent:jjwt-bytebuddy-guard.jar ...
```

## Attach to a running JVM

```bash
java -jar jjwt-bytebuddy-guard.jar <target-pid>
```

This package addresses empty signature segments only. It does not implement a
bounded decompression fix for JJWT compression codecs. Upgrading JJWT remains
the preferred remediation.
