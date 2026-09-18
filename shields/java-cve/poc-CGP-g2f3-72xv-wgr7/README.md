# CGP-g2f3-72xv-wgr7 PoC and Byte Buddy mitigation

This demonstration targets Apache Commons Net 3.4. A malformed FTP `229` EPSV
reply reaches `FTPClient._parseExtendedPassiveModeReply(String)` and escapes as
an unchecked `StringIndexOutOfBoundsException`.

## Build

Build both shaded JARs from this directory:

```bash
docker run --rm -v "$PWD:/work" -w /work/commons-net-bytebuddy-guard \
  maven:3.9.11-eclipse-temurin-17 mvn -q clean package

docker run --rm -v "$PWD:/work" -w /work/vulnerable-ftp-app \
  maven:3.9.11-eclipse-temurin-17 mvn -q clean package
```

## One-shot demonstration

Without the agent:

```bash
java -jar vulnerable-ftp-app/target/wgr7-vulnerable-ftp-app.jar
```

The first line contains:

```text
MALICIOUS_RESULT=VULNERABLE unchecked=StringIndexOutOfBoundsException
```

With startup instrumentation:

```bash
java \
  -javaagent:commons-net-bytebuddy-guard/target/wgr7-epsv-guard.jar \
  -jar vulnerable-ftp-app/target/wgr7-vulnerable-ftp-app.jar
```

The agent prints `BLOCKED`, and the application reports:

```text
MALICIOUS_RESULT=PROTECTED checked=MalformedServerReplyException
```

In both runs, the benign reply remains accepted and an unrelated malformed port
continues to produce the library's checked exception.

## Live-attachment demonstration

Start the application and record its printed PID:

```bash
java -XX:+StartAttachListener \
  -jar vulnerable-ftp-app/target/wgr7-vulnerable-ftp-app.jar serve 8080
```

Before attachment:

```bash
curl -s http://127.0.0.1:8080/malicious
curl -s http://127.0.0.1:8080/benign
curl -s http://127.0.0.1:8080/unrelated
```

Attach without restarting, replacing `<pid>` with the printed value:

```bash
java -jar commons-net-bytebuddy-guard/target/wgr7-epsv-guard.jar <pid>
```

Repeat the same three requests. The malicious result changes from `VULNERABLE`
to `PROTECTED`; the benign and unrelated results do not change.
