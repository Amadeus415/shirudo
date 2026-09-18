# CGP-753c-3hg7-j33f JJWT zip-bomb PoC

The Java application only runs an HTTP server. It accepts a compact JWT in the
`Authorization: Bearer <jwt>` header of a `GET /parse` request and parses it
with the vulnerable JJWT API. The separate
`send_jwt.py` script creates and sends the benign and malicious JWTs.

## Build

Build the agent first:

```bash
cd jjwt-bytebuddy-guard
mvn clean package
```

Build the application image from the workspace root:

```bash
cd ../..
docker build -t cgp-753c-jjwt-poc \
  -f vulnerable-jwt-app/Dockerfile .
```

## See the marker

Start the server without the agent:

```bash
docker run -d --rm --name cgp-753c-jjwt-poc -p 8080:8080 cgp-753c-jjwt-poc
python3 vulnerable-jwt-app/send_jwt.py
```

The sender prints:

```text
=== BENIGN SIGNED JWT ===
HTTP_STATUS=200
PARSE_RESULT=ACCEPTED subject=alice marker=BENIGN_MARKER expanded_marker_bytes=13
=== MALICIOUS COMPRESSED UNSIGNED JWT ===
HTTP_STATUS=200
PARSE_RESULT=ACCEPTED subject=mallory marker=CGP-753c-3hg7-j33f ... expanded_marker_bytes=4194322
```

The second token is only a few kilobytes on the wire, but expands to a 4 MiB
marker before JJWT accepts it without verifying a signature.

Start with startup protection instead:

```bash
docker rm -f cgp-753c-jjwt-poc 2>/dev/null || true
docker run -d --rm --name cgp-753c-jjwt-poc -p 8080:8080 \
  --entrypoint java cgp-753c-jjwt-poc \
  -javaagent:/app/cgp-753c-jjwt-zip-guard.jar \
  -jar /app/cgp-753c-vulnerable-jwt-app.jar 8080
python3 vulnerable-jwt-app/send_jwt.py
```

The malicious request now returns:

```text
HTTP_STATUS=400
PARSE_RESULT=PROTECTED rejected_before_decompression=true
```

The benign request remains accepted.

## Live attachment

The server loads `DefaultJwtParser` before printing its PID:

```bash
docker rm -f cgp-753c-jjwt-poc 2>/dev/null || true
docker run -d --rm --name cgp-753c-jjwt-poc -p 8080:8080 cgp-753c-jjwt-poc
python3 vulnerable-jwt-app/send_jwt.py
docker exec cgp-753c-jjwt-poc \
  java -jar /app/cgp-753c-jjwt-zip-guard.jar 1
python3 vulnerable-jwt-app/send_jwt.py
```

After attachment, the same malicious request is protected and the benign one
is still accepted. The container and application PID remain unchanged.
