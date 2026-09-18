# CGP-753c-3hg7-j33f JJWT zip-bomb guard

This Byte Buddy agent protects the vulnerable JJWT parser path by rejecting a
JWT containing `zip` or legacy `calg` before `DefaultJwtParser` can invoke its
unbounded GZIP/DEFLATE decompressor. It supports both startup instrumentation
and retransformation of an already-loaded parser:

```bash
java -javaagent:target/cgp-753c-jjwt-zip-guard.jar ...
java -jar target/cgp-753c-jjwt-zip-guard.jar <target-pid>
```

The mitigation intentionally disables JJWT compression as a temporary runtime
policy. Upgrade JJWT to the fixed release before removing the guard.
