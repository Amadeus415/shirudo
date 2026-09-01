package com.security.rasp;

import java.util.concurrent.atomic.AtomicLong;

final class HookRegistry {
    private static final AtomicLong NEXT_HOOK_ID = new AtomicLong(0);

    private HookRegistry() {
    }

    static long register() {
        return NEXT_HOOK_ID.incrementAndGet();
    }
}
