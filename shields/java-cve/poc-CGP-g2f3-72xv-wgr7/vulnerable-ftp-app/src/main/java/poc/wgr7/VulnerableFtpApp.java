package poc.wgr7;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.apache.commons.net.MalformedServerReplyException;
import org.apache.commons.net.ftp.FTPClient;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.management.ManagementFactory;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

public final class VulnerableFtpApp {
    private static final String MALICIOUS_REPLY = "229 Entering Extended Passive Mode";
    private static final String BENIGN_REPLY = "229 Entering Extended Passive Mode (|||2121|)";
    private static final String UNRELATED_MALFORMED_REPLY =
        "229 Entering Extended Passive Mode (|||not-a-port|)";

    private VulnerableFtpApp() {
    }

    public static void main(final String[] args) throws Exception {
        if (args.length > 0 && "serve".equals(args[0])) {
            final int port = args.length > 1 ? Integer.parseInt(args[1]) : 8080;
            serve(port);
            return;
        }

        System.out.println(runMalicious());
        System.out.println(runBenign());
        System.out.println(runUnrelatedMalformed());
    }

    private static void serve(final int port) throws IOException {
        // Load and execute FTPClient before attachment, proving retransformation.
        final String warmup = runBenign();
        final HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.createContext("/malicious", new TextHandler(VulnerableFtpApp::runMalicious));
        server.createContext("/benign", new TextHandler(VulnerableFtpApp::runBenign));
        server.createContext("/unrelated", new TextHandler(VulnerableFtpApp::runUnrelatedMalformed));
        server.setExecutor(null);
        server.start();

        System.out.println("READY pid=" + currentPid() + " port=" + port);
        System.out.println("TARGET_CLASS_LOADED=true " + warmup);
    }

    private static String runMalicious() {
        try {
            new DemoFtpClient().parseExtendedPassiveReply(MALICIOUS_REPLY);
            return "MALICIOUS_RESULT=UNEXPECTEDLY_ACCEPTED";
        } catch (final MalformedServerReplyException expectedAfterGuard) {
            return "MALICIOUS_RESULT=PROTECTED checked=MalformedServerReplyException";
        } catch (final RuntimeException vulnerable) {
            return "MALICIOUS_RESULT=VULNERABLE unchecked="
                + vulnerable.getClass().getSimpleName();
        }
    }

    private static String runBenign() {
        final DemoFtpClient client = new DemoFtpClient();
        try {
            client.parseExtendedPassiveReply(BENIGN_REPLY);
            return "BENIGN_RESULT=OK host=" + client.getPassiveHost()
                + " port=" + client.getPassivePort();
        } catch (final Exception failure) {
            return "BENIGN_RESULT=FAILED exception=" + failure.getClass().getSimpleName();
        }
    }

    private static String runUnrelatedMalformed() {
        try {
            new DemoFtpClient().parseExtendedPassiveReply(UNRELATED_MALFORMED_REPLY);
            return "UNRELATED_RESULT=UNEXPECTEDLY_ACCEPTED";
        } catch (final MalformedServerReplyException expected) {
            return "UNRELATED_RESULT=EXPECTED_CHECKED_EXCEPTION";
        } catch (final RuntimeException changedBehavior) {
            return "UNRELATED_RESULT=FAILED unchecked="
                + changedBehavior.getClass().getSimpleName();
        }
    }

    private static String currentPid() {
        return ManagementFactory.getRuntimeMXBean().getName().split("@", 2)[0];
    }

    private interface ResultSupplier {
        String get();
    }

    private static final class TextHandler implements HttpHandler {
        private final ResultSupplier supplier;

        private TextHandler(final ResultSupplier supplier) {
            this.supplier = supplier;
        }

        @Override
        public void handle(final HttpExchange exchange) throws IOException {
            final byte[] body = (supplier.get() + "\n").getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream output = exchange.getResponseBody()) {
                output.write(body);
            }
        }
    }

    private static final class DemoFtpClient extends FTPClient {
        private void parseExtendedPassiveReply(final String reply)
                throws MalformedServerReplyException {
            _parseExtendedPassiveModeReply(reply);
        }

        @Override
        public InetAddress getRemoteAddress() {
            return InetAddress.getLoopbackAddress();
        }
    }
}
