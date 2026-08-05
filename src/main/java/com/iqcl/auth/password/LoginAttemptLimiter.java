/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.password;

import com.iqcl.auth.config.ModConfig;

import java.util.Iterator;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 登录爆破防护：每玩家独立失败计数 + 锁定。
 * <p>
 * 线程安全（{@link ConcurrentHashMap}），可在 IO 线程读写。
 * <ul>
 *   <li>失败次数达到 {@code maxLoginAttempts} 后锁定 {@code lockSeconds} 秒</li>
 *   <li>开启指数退避时，每次连续锁定时长翻倍，上限 {@code maxLockSeconds}</li>
 *   <li>登录成功或登出时调用 {@link #reset} 清零计数</li>
 *   <li>锁定期间 {@link #recordFailure} 仍记录但不再延长锁定（避免无限叠加）</li>
 * </ul>
 */
public final class LoginAttemptLimiter {

    private static final Map<UUID, AttemptState> STATES = new ConcurrentHashMap<>();

    private LoginAttemptLimiter() {
    }

    /** 单玩家失败计数 + 锁定状态。 */
    private static final class AttemptState {
        volatile int attempts;
        volatile long lastFailureMs;
        volatile long lockedUntilMs;
        /** 当前锁定级别（指数退避用，每次锁定 +1）。 */
        volatile int lockLevel;
    }

    /**
     * 记录一次失败尝试。
     *
     * @return true = 本次失败导致玩家被锁定（或已被锁定）
     */
    public static boolean recordFailure(UUID uuid) {
        ModConfig.LoginAttemptConfig cfg = ModConfig.get().loginAttempt;
        long now = System.currentTimeMillis();

        AttemptState state = STATES.computeIfAbsent(uuid, k -> new AttemptState());
        synchronized (state) {
            // 若已过锁定期，重置计数与级别
            if (state.lockedUntilMs > 0 && now >= state.lockedUntilMs) {
                state.attempts = 0;
                state.lockLevel = 0;
                state.lockedUntilMs = 0;
            }

            state.attempts++;
            state.lastFailureMs = now;

            if (state.attempts >= cfg.maxLoginAttempts) {
                // 触发锁定
                int level = state.lockLevel;
                long baseLockMs = (long) cfg.lockSeconds * 1000L;
                long lockMs;
                if (cfg.exponentialBackoff && level > 0) {
                    // 指数退避：baseLockMs * 2^level，封顶 maxLockSeconds
                    long scaled = baseLockMs << Math.min(level, 10);
                    long maxMs = (long) cfg.maxLockSeconds * 1000L;
                    lockMs = Math.min(scaled, maxMs);
                } else {
                    lockMs = baseLockMs;
                }
                state.lockedUntilMs = now + lockMs;
                state.lockLevel = level + 1;
                return true;
            }
            return false;
        }
    }

    /**
     * 重置计数（登录成功或登出时调用）。
     */
    public static void reset(UUID uuid) {
        STATES.remove(uuid);
    }

    /**
     * 当前是否被锁定。
     */
    public static boolean isLocked(UUID uuid) {
        AttemptState state = STATES.get(uuid);
        if (state == null) return false;
        long now = System.currentTimeMillis();
        return state.lockedUntilMs > now;
    }

    /**
     * 距离解锁还剩多少毫秒（0 表示未锁定或已到期）。
     */
    public static long remainingLockMs(UUID uuid) {
        AttemptState state = STATES.get(uuid);
        if (state == null) return 0L;
        long now = System.currentTimeMillis();
        long remain = state.lockedUntilMs - now;
        return Math.max(0L, remain);
    }

    /**
     * 当前剩余尝试次数（未锁定时）。
     */
    public static int remainingAttempts(UUID uuid) {
        ModConfig.LoginAttemptConfig cfg = ModConfig.get().loginAttempt;
        AttemptState state = STATES.get(uuid);
        if (state == null) return cfg.maxLoginAttempts;
        if (isLocked(uuid)) return 0;
        return Math.max(0, cfg.maxLoginAttempts - state.attempts);
    }

    /**
     * 定期清理过期条目（onServerTick 偶发调用，避免内存泄漏）。
     */
    public static void cleanup() {
        long now = System.currentTimeMillis();
        Iterator<Map.Entry<UUID, AttemptState>> it = STATES.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<UUID, AttemptState> e = it.next();
            AttemptState s = e.getValue();
            // 锁定已过期且最后失败时间超过 1 小时 → 移除
            if (s.lockedUntilMs <= now
                    && (now - s.lastFailureMs) > 3_600_000L) {
                it.remove();
            }
        }
    }
}
