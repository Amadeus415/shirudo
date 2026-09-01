package com.security.rasp;

import net.bytebuddy.asm.Advice;
import java.util.regex.Pattern;

public class SqlInjectionAdvisor {

    private static volatile long hookId;

    static void configure(long configuredHookId) {
        hookId = configuredHookId;
    }

    // Simple structural pattern looking for typical SQLi indicators
    private static final Pattern SQLI_PATTERN = Pattern.compile(
            "('(\"" + Pattern.quote("|") + ")?--)|(\\b(OR|AND)\\b\\s+\\d+\\s*=\\s*\\d+)",
            Pattern.CASE_INSENSITIVE
    );

    @Advice.OnMethodEnter(inline = false)
    public static void onEnter(@Advice.Argument(0) String sql) {
        if (sql != null && SQLI_PATTERN.matcher(sql).find()) {
            ShirudoTelemetry.record(hookId);
            System.err.println("[RASP ALERT] SQL Injection Attempt Detected: " + sql);

            // Immediate Mitigation: Throw a runtime exception to block database execution
            throw new SecurityException("Request blocked by RASP: Malicious SQL patterns detected.");
        }
    }
}
