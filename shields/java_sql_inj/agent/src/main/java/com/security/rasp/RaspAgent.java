package com.security.rasp;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.matcher.ElementMatchers;
import java.lang.instrument.Instrumentation;
import java.sql.Statement;

public class RaspAgent {

    public static void premain(String agentArgs, Instrumentation inst) {
        AgentConfig config = AgentConfig.parse(agentArgs);
        long hookId = HookRegistry.register();
        ShirudoTelemetry.configure(config.jarId, config.telemetryUpatch);
        SqlInjectionAdvisor.configure(hookId);
        System.out.println("[RASP Agent] Initializing SQL Injection Shield...");

        new AgentBuilder.Default()
            // Match any class implementing JDBC Statement, excluding interfaces themselves
            .type(ElementMatchers.isSubTypeOf(Statement.class)
                    .and(ElementMatchers.not(ElementMatchers.isInterface())))
            .transform((builder, typeDescription, classLoader, module, protectionDomain) ->
                builder.method(
                    // Intercept execute(), executeQuery(), executeUpdate() variants taking a String
                    ElementMatchers.nameStartsWith("execute")
                        .and(ElementMatchers.takesArgument(0, String.class))
                )
                .intercept(Advice.to(SqlInjectionAdvisor.class))
            )
            .installOn(inst);
    }

    private static final class AgentConfig {
        private final long jarId;
        private final String telemetryUpatch;

        private AgentConfig(long jarId, String telemetryUpatch) {
            this.jarId = jarId;
            this.telemetryUpatch = telemetryUpatch;
        }

        private static AgentConfig parse(String args) {
            long id = 0;
            String upatch = "";
            if (args != null) {
                for (String option : args.split(",")) {
                    String[] pair = option.split("=", 2);
                    if (pair.length != 2) {
                        continue;
                    }
                    if ("jar_id".equals(pair[0])) {
                        try {
                            id = Long.parseUnsignedLong(pair[1], 16);
                        } catch (NumberFormatException ignored) {
                            id = 0;
                        }
                    } else if ("telemetry_upatch".equals(pair[0])) {
                        upatch = pair[1];
                    }
                }
            }
            return new AgentConfig(id, upatch);
        }
    }
}
