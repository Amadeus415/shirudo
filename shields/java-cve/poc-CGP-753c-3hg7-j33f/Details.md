### Root Cause
`DefaultJwtParser.parse()` resolves the compression codec from the unauthenticated JOSE header at lines 260–270, before the signature-verification block at line 280. The call at line 266 is:
```java
byte[] decompressed = compressionCodec.decompress(TextCodec.BASE64URL.decode(base64UrlEncodedPayload));
```
`DefaultCompressionCodecResolver.resolveCompressionCodec(header)` reads the attacker-controlled `zip` (or `calg`) header value and returns either `GzipCompressionCodec` or `DeflateCompressionCodec`. Both implementations stream into a `ByteArrayOutputStream` with no output-size cap:
- `GzipCompressionCodec.doDecompress(byte[])` (lines 42–57): loops `gzipInputStream.read(buffer)` writing into `outputStream` until EOF.
- `DeflateCompressionCodec.doDecompress(byte[])` (lines 60–71): writes all compressed bytes into an `InflaterOutputStream` backed by an unbounded `ByteArrayOutputStream`.
The `DefaultCompressionCodecResolver` is installed by default at line 70 of `DefaultJwtParser`, so no special configuration is required for this path to be reachable.
### Affected Locations
- `io.jsonwebtoken.impl.DefaultJwtParser` (lines 260–270): the call site where `compressionCodec.decompress(...)` is invoked on attacker-controlled bytes before signature verification.
- `io.jsonwebtoken.impl.compression.GzipCompressionCodec.doDecompress(byte[])` (lines 42–57): GZIP decompression loop with no output-size limit.
- `io.jsonwebtoken.impl.compression.DeflateCompressionCodec.doDecompress(byte[])` (lines 60–71): DEFLATE decompression with no output-size limit.
### Attack Vectors
**Zip-bomb via GZIP payload:**
An unauthenticated attacker crafts a compact JWT whose header is `{\"alg\":\"HS256\",\"zip\":\"GZIP\"}` and whose body segment is a few-kilobyte GZIP stream that expands to hundreds of megabytes or gigabytes. Because decompression occurs before signature verification, no valid key is required. The parser expands the entire bomb into heap memory, causing `OutOfMemoryError` or extreme GC pressure in any service calling `Jwts.parser()...parse(token)` or `parseClaimsJws(token)`.
**Zip-bomb via DEFLATE payload:**
Identical attack using `{\"alg\":\"HS256\",\"zip\":\"DEF\"}` with a DEFLATE-compressed bomb payload. The `DeflateCompressionCodec` path is equally unbounded.
### Impact
An unauthenticated remote attacker can cause `OutOfMemoryError` or severe GC pressure in any JVM process that calls `JwtParser.parse()` or `JwtParser.parseClaimsJws()` on attacker-supplied input. This results in denial of service — the service becomes unresponsive or crashes — without requiring any knowledge of signing keys or valid credentials. Confidentiality and integrity are not directly affected.
### Trace
1. Attacker submits a compact JWT string with `zip: GZIP` or `zip: DEF` in the unauthenticated header and a compressed-bomb payload body.
2. `DefaultJwtParser.parse(String)` splits the JWT into header, payload, and digest segments.
3. `DefaultCompressionCodecResolver.resolveCompressionCodec(header)` reads the attacker-set `zip` value and returns `GzipCompressionCodec` or `DeflateCompressionCodec`.
4. `compressionCodec.decompress(TextCodec.BASE64URL.decode(base64UrlEncodedPayload))` is called at line 266, triggering `doDecompress(byte[])` which streams the entire expanded output into a `ByteArrayOutputStream` with no size cap.
5. Signature verification at line 280 is never reached; the JVM exhausts heap memory during step 4."