import net.bytebuddy.agent.ByteBuddyAgent;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

import java.io.File;
import java.lang.instrument.Instrumentation;
import java.net.URISyntaxException;

import static net.bytebuddy.matcher.ElementMatchers.isMethod;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

public final class JjwtGuardAgent {
    private JjwtGuardAgent() {
    }

    public static void premain(String args, Instrumentation instrumentation) {
        install(instrumentation);
    }

    public static void agentmain(String args, Instrumentation instrumentation) {
        install(instrumentation);
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("Usage: java -jar jjwt-bytebuddy-guard.jar <target-pid>");
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
                builder.visit(Advice.to(RejectEmptySignature.class).on(
                    named("parse")
                        .and(isMethod())
                        .and(takesArguments(String.class))
                ))
            )
            .installOn(instrumentation);
    }

    private static File agentJar() throws URISyntaxException {
        return new File(JjwtGuardAgent.class.getProtectionDomain()
            .getCodeSource().getLocation().toURI());
    }

    public static class RejectEmptySignature {
        @Advice.OnMethodEnter
        static void reject(@Advice.Argument(0) String token) {
            if (token != null) {
                int first = token.indexOf('.');
                int second = first < 0 ? -1 : token.indexOf('.', first + 1);
                boolean emptyThirdSegment = second >= 0
                    && second == token.length() - 1
                    && token.indexOf('.', second + 1) < 0;

                if (emptyThirdSegment) {
                    throw new SecurityException(
                        "Rejected JWT with an empty signature segment."
                    );
                }
            }
        }
    }
}
