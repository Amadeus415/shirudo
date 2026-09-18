package poc.wgr7.agent;

import net.bytebuddy.agent.ByteBuddyAgent;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.utility.JavaModule;
import org.apache.commons.net.MalformedServerReplyException;

import java.io.File;
import java.lang.instrument.Instrumentation;
import java.net.URISyntaxException;

import static net.bytebuddy.matcher.ElementMatchers.isMethod;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.returns;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

public final class EpsvGuardAgent {
    private static boolean installed;

    private EpsvGuardAgent() {
    }

    public static void premain(final String args, final Instrumentation instrumentation) {
        install(instrumentation);
    }

    public static void agentmain(final String args, final Instrumentation instrumentation) {
        install(instrumentation);
    }

    public static void main(final String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("Usage: java -jar wgr7-epsv-guard.jar <pid>");
            System.exit(2);
        }
        ByteBuddyAgent.attach(agentJar(), args[0]);
    }

    private static synchronized void install(final Instrumentation instrumentation) {
        if (installed) {
            System.err.println("[wgr7-guard] already installed");
            return;
        }

        new AgentBuilder.Default()
            .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
            .disableClassFormatChanges()
            .with(new TransformationListener())
            .type(named("org.apache.commons.net.ftp.FTPClient"))
            .transform((builder, type, classLoader, module, protectionDomain) ->
                builder.visit(Advice.to(RejectMalformedEpsvReply.class).on(
                    named("_parseExtendedPassiveModeReply")
                        .and(isMethod())
                        .and(takesArguments(String.class))
                        .and(returns(void.class))
                ))
            )
            .installOn(instrumentation);

        installed = true;
        System.err.println("[wgr7-guard] installed");
    }

    private static File agentJar() throws URISyntaxException {
        return new File(EpsvGuardAgent.class.getProtectionDomain()
            .getCodeSource().getLocation().toURI());
    }

    public static final class RejectMalformedEpsvReply {
        private RejectMalformedEpsvReply() {
        }

        @Advice.OnMethodEnter
        static void reject(final @Advice.Argument(0) String reply)
                throws MalformedServerReplyException {
            final int opening = reply == null ? -1 : reply.indexOf('(');
            final int closing = reply == null ? -1 : reply.indexOf(')');
            final boolean missingOrReversedDelimiters = opening < 0 || closing <= opening;
            final boolean truncatedPayload = !missingOrReversedDelimiters
                && reply.substring(opening + 1, closing).trim().length() < 4;

            if (missingOrReversedDelimiters || truncatedPayload) {
                System.err.println("[wgr7-guard] BLOCKED malformed EPSV reply");
                throw new MalformedServerReplyException(
                    "Rejected malformed extended passive mode reply."
                );
            }
        }
    }

    private static final class TransformationListener extends AgentBuilder.Listener.Adapter {
        @Override
        public void onTransformation(final TypeDescription typeDescription,
                                     final ClassLoader classLoader,
                                     final JavaModule module,
                                     final boolean loaded,
                                     final DynamicType dynamicType) {
            System.err.println("[wgr7-guard] transformed " + typeDescription.getName()
                + " (alreadyLoaded=" + loaded + ")");
        }

        @Override
        public void onError(final String typeName,
                            final ClassLoader classLoader,
                            final JavaModule module,
                            final boolean loaded,
                            final Throwable throwable) {
            System.err.println("[wgr7-guard] ERROR transforming " + typeName + ": " + throwable);
        }
    }
}
