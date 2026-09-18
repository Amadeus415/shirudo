package poc.cgp753.agent;

import net.bytebuddy.agent.ByteBuddyAgent;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

import java.io.File;
import java.lang.instrument.Instrumentation;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static net.bytebuddy.matcher.ElementMatchers.isMethod;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

public final class JjwtZipBombGuardAgent {
    private JjwtZipBombGuardAgent() {
    }

    public static void premain(String args, Instrumentation instrumentation) {
        install(instrumentation);
    }

    public static void agentmain(String args, Instrumentation instrumentation) {
        install(instrumentation);
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("Usage: java -jar cgp-753c-jjwt-zip-guard.jar <target-pid>");
            System.exit(2);
        }
        ByteBuddyAgent.attach(agentJar(), args[0]);
    }

    private static void install(Instrumentation instrumentation) {
        new AgentBuilder.Default()
            .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
            .disableClassFormatChanges()
            .type(named("io.jsonwebtoken.impl.DefaultJwtParser"))
            .transform((builder, type, classLoader, module, protectionDomain) ->
                builder.visit(Advice.to(RejectCompressedJwt.class).on(
                    named("parse")
                        .and(isMethod())
                        .and(takesArguments(String.class))
                ))
            )
            .installOn(instrumentation);

        System.out.println("CGP-753c-3hg7-j33f AGENT_ACTIVE "
            + "guard=reject-compression-before-decompression");
    }

    private static File agentJar() throws URISyntaxException {
        return new File(JjwtZipBombGuardAgent.class.getProtectionDomain()
            .getCodeSource().getLocation().toURI());
    }

    public static class RejectCompressedJwt {
        @Advice.OnMethodEnter
        static void reject(@Advice.Argument(0) String jwt) {
            if (jwt == null) {
                return;
            }

            int separator = jwt.indexOf('.');
            if (separator <= 0) {
                return;
            }

            try {
                String header = new String(
                    Base64.getUrlDecoder().decode(jwt.substring(0, separator)),
                    StandardCharsets.UTF_8
                );

                // JJWT selects GZIP/DEFLATE from these attacker-controlled
                // header fields before it verifies the signature. Rejecting
                // the compression feature at parser entry keeps the original
                // unbounded codec from receiving attacker-controlled bytes.

                // calg is present because it's the fallback
                if (header.contains("\"zip\"") || header.contains("\"calg\"")) {
                    throw new SecurityException(
                        "Rejected JWT compression before decompression."
                    );
                }
            } catch (IllegalArgumentException ignored) {
                // Let JJWT preserve its normal malformed-token behavior.
            }
        }
    }
}
