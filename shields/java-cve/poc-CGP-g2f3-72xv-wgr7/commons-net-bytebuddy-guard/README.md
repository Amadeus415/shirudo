# CGP-g2f3-72xv-wgr7 Byte Buddy guard

This Java agent guards the vulnerable Apache Commons Net 3.4 method:

```text
org.apache.commons.net.ftp.FTPClient
  ._parseExtendedPassiveModeReply(String): void
```

Malformed `229` EPSV replies with missing/reversed parentheses or a truncated
payload are rejected with `MalformedServerReplyException` before the original
parser can throw an unchecked `StringIndexOutOfBoundsException`.

The guard supports both startup instrumentation and retransformation of an
already-loaded `FTPClient`:

```bash
java -javaagent:target/wgr7-epsv-guard.jar ...
java -jar target/wgr7-epsv-guard.jar <pid>
```

Build with Maven:

```bash
mvn clean package
```

The output is `target/wgr7-epsv-guard.jar`.
