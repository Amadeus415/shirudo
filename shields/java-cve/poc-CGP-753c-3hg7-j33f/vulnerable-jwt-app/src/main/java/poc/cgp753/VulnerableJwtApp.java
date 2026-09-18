package poc.cgp753;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.management.ManagementFactory;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;

public final class VulnerableJwtApp {
    private static final byte[] SIGNING_KEY =
        "cgp-753c-demo-signing-key-32!!".getBytes(StandardCharsets.UTF_8);

    private VulnerableJwtApp() {
    }

    public static void main(String[] args) throws Exception {
        serve(args.length == 0 ? 8080 : Integer.parseInt(args[0]));
    }

    private static void serve(int port) throws IOException, InterruptedException {
        // Load the parser before live attachment so retransformation is tested.
        Jwts.parser().setSigningKey(SIGNING_KEY);
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
        server.createContext("/parse", new ParseHandler());
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();

        System.out.println("READY pid=" + currentPid() + " port=" + port);
        System.out.println("TARGET_CLASS_LOADED=true endpoint=/parse");
        new CountDownLatch(1).await();
    }

    private static String currentPid() {
        return ManagementFactory.getRuntimeMXBean().getName().split("@", 2)[0];
    }

    private static final class ParseHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equals(exchange.getRequestMethod())) {
                respond(exchange, 405, "GET /parse with Authorization: Bearer <jwt>");
                return;
            }

            String authorization = exchange.getRequestHeaders().getFirst("Authorization");
            if (authorization == null || !authorization.startsWith("Bearer ")) {
                respond(exchange, 401, "PARSE_RESULT=REJECTED missing_bearer_token=true");
                return;
            }

            String token = authorization.substring("Bearer ".length()).trim();
            if (token.isEmpty()) {
                respond(exchange, 401, "PARSE_RESULT=REJECTED missing_bearer_token=true");
                return;
            }

            try {
                Jwt parsed = Jwts.parser()
                    .setSigningKey(SIGNING_KEY)
                    .parse(token);
                Claims claims = (Claims) parsed.getBody();
                Object marker = claims.get("marker");
                respond(exchange, 200,
                    "PARSE_RESULT=ACCEPTED subject=" + claims.getSubject()
                        + " marker=" + markerSummary(marker)
                        + " expanded_marker_bytes=" + markerLength(marker));
            } catch (SecurityException protectedByAgent) {
                respond(exchange, 400,
                    "PARSE_RESULT=PROTECTED rejected_before_decompression=true");
            } catch (JwtException rejectedByJjwt) {
                respond(exchange, 400,
                    "PARSE_RESULT=REJECTED exception="
                        + rejectedByJjwt.getClass().getSimpleName());
            } catch (RuntimeException failure) {
                respond(exchange, 400,
                    "PARSE_RESULT=FAILED exception=" + failure.getClass().getSimpleName());
            }
        }
    }

    private static String markerSummary(Object marker) {
        if (marker == null) {
            return "<none>";
        }
        String value = marker.toString();
        return value.substring(0, Math.min(value.length(), 24));
    }

    private static int markerLength(Object marker) {
        return marker == null ? 0 : marker.toString().length();
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
