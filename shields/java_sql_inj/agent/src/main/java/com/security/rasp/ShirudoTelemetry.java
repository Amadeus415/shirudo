package com.security.rasp;

final class ShirudoTelemetry {
    private static final String LIBRARY = "/usr/lib/shirudo/libshirudo_javaagent.so";
    private static volatile boolean available;
    private static volatile String telemetryUpatch;
    private static volatile long jarId;

    private ShirudoTelemetry() {
    }

    static void configure(long configuredJarId, String configuredTelemetryUpatch) {
        jarId = configuredJarId;
        telemetryUpatch = configuredTelemetryUpatch;
        if (configuredJarId == 0 || configuredTelemetryUpatch == null ||
                configuredTelemetryUpatch.isEmpty()) {
            available = false;
            return;
        }
        try {
            System.load(LIBRARY);
            available = true;
        } catch (UnsatisfiedLinkError e) {
            available = false;
            System.err.println("[RASP Agent] Shirudo telemetry unavailable: " + e.getMessage());
        }
    }

    static boolean record(long hookId) {
        if (!available) {
            return false;
        }
        try {
            return recordNative(jarId, hookId, telemetryUpatch);
        } catch (LinkageError e) {
            available = false;
            return false;
        }
    }

    private static native boolean recordNative(long jarId, long hookId,
                                                String telemetryUpatch);
}
