### Root Cause

`FTPClient._parseExtendedPassiveModeReply(String reply)` at line 608 parses the 229 EPSV reply text by assuming well-formed input. The parsing uses:

```java
reply.substring(reply.indexOf('(') + 1, reply.indexOf(')'))
```

and accesses `reply.charAt(0)` through `reply.charAt(2)`. No bounds or presence checks are performed before these operations:

- If `'('` is absent, `indexOf('(')` returns `-1`, and `substring(-1 + 1, ...)` = `substring(0, ...)` may still succeed, but if `')'` is also absent, `indexOf(')')` returns `-1` and `substring(0, -1)` throws `StringIndexOutOfBoundsException`.
- If `')'` is absent, `indexOf(')')` returns `-1`, causing `substring(start, -1)` to throw `StringIndexOutOfBoundsException`.
- If the reply string has fewer than 3 characters, `reply.charAt(2)` throws `StringIndexOutOfBoundsException`.

The `StringIndexOutOfBoundsException` is an unchecked `RuntimeException`. It propagates out of `_openDataConnection_()` rather than being wrapped in or replaced by an `IOException`. Callers that catch only `IOException` (the documented exception type for FTPClient data-connection methods) will not catch this exception, causing unexpected application termination or unhandled exception propagation.

### Affected Locations

- `org.apache.commons.net.ftp.FTPClient._parseExtendedPassiveModeReply(String)` — line 608: unchecked `substring()` and `charAt()` calls on the server-supplied EPSV reply string.

### Attack Vectors

**Vector 1 — Client-side DoS via malformed 229 EPSV reply:** A malicious or buggy FTP server responds to the EPSV command with a short or malformed 229 reply (e.g., missing the `(` or `)` delimiters, or a reply shorter than 3 characters). The `_parseExtendedPassiveModeReply()` method throws `StringIndexOutOfBoundsException`, which propagates out of the FTPClient call stack as an unchecked exception. If the calling application does not catch `RuntimeException` or `Throwable`, the thread or application terminates unexpectedly.

**Vector 2 — Exception type confusion:** Callers that catch `IOException` (the documented exception for FTPClient methods) will not catch `StringIndexOutOfBoundsException`. This can cause resource leaks (open sockets, streams) if cleanup code in `catch (IOException e)` blocks is not reached.

### Impact

A malicious or buggy FTP server can cause the FTPClient to throw an unchecked `StringIndexOutOfBoundsException` during EPSV reply parsing. The impact is limited to client-side availability: the FTP operation fails with an unexpected exception type, potentially causing application crashes or resource leaks in callers that handle only `IOException`. There is no confidentiality or integrity impact.

### Trace

1. Client calls an FTPClient method requiring a data connection (e.g., `retrieveFile()`, `listFiles()`).
2. `_openDataConnection_()` is entered; EPSV mode is attempted.
3. `epsv()` sends the EPSV command; the malicious server replies with a short or malformed 229 line (e.g., no `(` or `)` delimiters, or fewer than 3 characters).
4. `_parseExtendedPassiveModeReply(reply)` is called at line 608.
5. `reply.indexOf(')')` returns `-1`; `reply.substring(start, -1)` throws `StringIndexOutOfBoundsException`.
6. The unchecked exception propagates out of `_openDataConnection_()` and up the call stack.
7. Callers catching only `IOException` do not handle the exception; application behavior is undefined.