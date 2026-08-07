/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.server;

import net.minecraft.server.network.ServerPlayerEntity;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 玩家认证状态追踪器（服务端单例）。
 * <p>
 * 追踪每个玩家的：
 * <ul>
 *   <li>当前是否已通过验证（{@code authenticated}）</li>
 *   <li>上次活动时间（用于超时踢出）</li>
 *   <li>加入时间（用于首次宽限时间）</li>
 *   <li>当前会话绑定的 IQCL 账户信息（{@code currentDisplayId}/{@code currentUsername}，仅 PIN 登录后设置，不持久化）</li>
 * </ul>
 * 线程安全，可在工作线程与服务端主线程并发访问。
 * <p>
 * 注意：本地不再持久化 UUID↔displayId 绑定关系，绑定逻辑已由 IQCL 后端接管。
 * 此处的 currentDisplayId/currentUsername 仅用于当前会话的防多开与消息展示，登出即清除。
 */
public final class AuthState {

    /** 每玩家的认证状态（key = player UUID）。 */
    private static final Map<UUID, PlayerAuthState> STATES = new ConcurrentHashMap<>();

    private AuthState() {
    }

    /** 记录玩家加入（尚未认证）。 */
    public static void onPlayerJoin(ServerPlayerEntity player) {
        long now = System.currentTimeMillis();
        STATES.put(player.getUuid(), new PlayerAuthState(false, now, now));
    }

    /** 记录玩家离线，清理状态。 */
    public static void onPlayerDisconnect(UUID uuid) {
        STATES.remove(uuid);
    }

    /** 标记玩家已通过验证。 */
    public static void authenticate(ServerPlayerEntity player) {
        PlayerAuthState state = STATES.get(player.getUuid());
        if (state != null) {
            state.authenticated = true;
            state.lastActivityMs = System.currentTimeMillis();
        } else {
            long now = System.currentTimeMillis();
            STATES.put(player.getUuid(), new PlayerAuthState(true, now, now));
        }
    }

    /**
     * 记录玩家 PIN 验证通过，设置当前会话绑定的 IQCL 账户信息。
     * <p>
     * 该信息仅保存在内存中，不持久化到磁盘。登出时清除。
     * 用于防多开（displayId 唯一在线）与 game-session 通知。
     *
     * @param displayId  IQCL 显示 ID（可为 null）
     * @param username   IQCL 用户名（可为 null）
     * @param permission 权限等级
     */
    public static void setCurrentAccount(ServerPlayerEntity player,
                                          Integer displayId, String username,
                                          String permission) {
        PlayerAuthState state = STATES.get(player.getUuid());
        if (state != null) {
            state.currentDisplayId = displayId;
            state.currentUsername = username;
            state.permission = permission;
        } else {
            long now = System.currentTimeMillis();
            PlayerAuthState newState = new PlayerAuthState(false, now, now);
            newState.currentDisplayId = displayId;
            newState.currentUsername = username;
            newState.permission = permission;
            STATES.put(player.getUuid(), newState);
        }
    }

    /** 获取玩家当前会话绑定的 IQCL displayId（仅 PIN 登录后非 null）。 */
    public static Integer getCurrentDisplayId(UUID uuid) {
        PlayerAuthState state = STATES.get(uuid);
        return state != null ? state.currentDisplayId : null;
    }

    /** 获取玩家当前会话绑定的 IQCL 用户名（仅 PIN 登录后非 null）。 */
    public static String getCurrentUsername(UUID uuid) {
        PlayerAuthState state = STATES.get(uuid);
        return state != null ? state.currentUsername : null;
    }

    /** 获取玩家的 IQCL 权限等级（trial/formal/banned，可能为 null）。 */
    public static String getPermission(UUID uuid) {
        PlayerAuthState state = STATES.get(uuid);
        return state != null ? state.permission : null;
    }

    /** 登出：清除认证状态与会话账户信息。 */
    public static void logout(ServerPlayerEntity player) {
        PlayerAuthState state = STATES.get(player.getUuid());
        long now = System.currentTimeMillis();
        if (state != null) {
            state.authenticated = false;
            // 未认证超时/宽限期从登出时刻重新起算，避免登出后立即被登录超时踢出
            state.joinMs = now;
            state.lastActivityMs = now;
            state.currentDisplayId = null;
            state.currentUsername = null;
            state.permission = null;
            state.pendingTotp = false;
            state.totpPendingAction = null;
        } else {
            STATES.put(player.getUuid(), new PlayerAuthState(false, now, now));
        }
    }

    /** 玩家是否已认证。 */
    public static boolean isAuthenticated(UUID uuid) {
        PlayerAuthState state = STATES.get(uuid);
        return state != null && state.authenticated;
    }

    /** 更新玩家最近活动时间（在线已认证玩家每 tick 刷新；在线即活动，不会因 session 超时被踢）。 */
    public static void touchActivity(UUID uuid) {
        PlayerAuthState state = STATES.get(uuid);
        if (state != null) {
            state.lastActivityMs = System.currentTimeMillis();
        }
    }

    /**
     * 是否在宽限期内（刚加入不久，允许活动）。
     * @param gracePeriodSeconds 宽限时间（秒），来自配置。-1 或 0 表示无宽限。
     */
    public static boolean isInGracePeriod(UUID uuid, int gracePeriodSeconds) {
        // -1 或 0 表示关闭宽限，玩家进服即受限制
        if (gracePeriodSeconds <= 0) return false;
        PlayerAuthState state = STATES.get(uuid);
        if (state == null) return false;
        long elapsed = System.currentTimeMillis() - state.joinMs;
        return elapsed < gracePeriodSeconds * 1000L;
    }

    /**
     * 检查玩家是否已超时。
     * <p>
     * 已认证玩家在线期间由 tick 循环持续刷新活动时间，session 超时分支实际不会命中；
     * sessionTimeoutSeconds 在玩家退出后通过收紧持久会话过期时间生效（见
     * {@link PlayerSessionManager#applyDisconnectSessionTimeout}）。
     *
     * @param uuid 玩家 UUID
     * @param sessionTimeout 已认证玩家 session 超时（秒），仅离线语义保留
     * @param loginTimeout 未认证玩家登录超时（秒）
     */
    public static boolean isTimedOut(UUID uuid, int sessionTimeout, int loginTimeout) {
        PlayerAuthState state = STATES.get(uuid);
        if (state == null) return false;
        long now = System.currentTimeMillis();
        if (!state.authenticated) {
            // 未认证：从加入时间算起，超过 loginTimeout 秒即超时
            return loginTimeout > 0 && (now - state.joinMs) > loginTimeout * 1000L;
        }
        // 已认证：从最后活动时间算起，超过 sessionTimeout 秒即超时
        if (sessionTimeout > 0) {
            return (now - state.lastActivityMs) > sessionTimeout * 1000L;
        }
        return false;
    }

    /**
     * 获取玩家当前状态（只读）。
     */
    public static PlayerAuthState getState(UUID uuid) {
        return STATES.get(uuid);
    }

    /** 清理所有状态（服务端停用时）。 */
    public static void clear() {
        STATES.clear();
    }

    /** 单玩家状态记录。 */
    public static final class PlayerAuthState {
        public volatile boolean authenticated;
        /** 未认证超时/宽限期的起算时刻（进服时设置，登出时重置）。 */
        public volatile long joinMs;
        public volatile long lastActivityMs;

        // —— 当前会话 IQCL 账户信息（仅内存，不持久化）——
        /** 当前会话绑定的 IQCL displayId（PIN 登录后设置，登出清除） */
        public volatile Integer currentDisplayId;
        /** 当前会话绑定的 IQCL 用户名 */
        public volatile String currentUsername;
        /** 权限等级: trial / formal / banned */
        public volatile String permission;

        // —— TOTP 双因素认证状态 ——
        /** 密码已验证通过，等待 TOTP 验证码 */
        public volatile boolean pendingTotp;
        /** TOTP 验证通过后要执行的完成回调类型（password / pin） */
        public volatile String totpPendingAction;

        /** 本次会话的登录方式: "pin" 或 "password"（登录成功后设置） */
        public volatile String loginMethod;

        PlayerAuthState(boolean authenticated, long joinMs, long lastActivityMs) {
            this.authenticated = authenticated;
            this.joinMs = joinMs;
            this.lastActivityMs = lastActivityMs;
            this.currentDisplayId = null;
            this.currentUsername = null;
            this.permission = null;
            this.pendingTotp = false;
            this.totpPendingAction = null;
            this.loginMethod = null;
        }
    }

    // ========== TOTP 待验证状态 ==========

    /** 设置玩家进入待 TOTP 验证状态（密码已验证）。 */
    public static void setPendingTotp(UUID uuid, String action) {
        PlayerAuthState state = STATES.get(uuid);
        if (state != null) {
            state.pendingTotp = true;
            state.totpPendingAction = action;
        }
    }

    /** 玩家是否处于待 TOTP 验证状态。 */
    public static boolean hasPendingTotp(UUID uuid) {
        PlayerAuthState state = STATES.get(uuid);
        return state != null && state.pendingTotp;
    }

    /** 获取待 TOTP 验证的动作类型。 */
    public static String getTotpPendingAction(UUID uuid) {
        PlayerAuthState state = STATES.get(uuid);
        return state != null ? state.totpPendingAction : null;
    }

    /** 清除待 TOTP 验证状态。 */
    public static void clearPendingTotp(UUID uuid) {
        PlayerAuthState state = STATES.get(uuid);
        if (state != null) {
            state.pendingTotp = false;
            state.totpPendingAction = null;
        }
    }

    /** 设置玩家本次会话的登录方式。 */
    public static void setLoginMethod(UUID uuid, String method) {
        PlayerAuthState state = STATES.get(uuid);
        if (state != null) {
            state.loginMethod = method;
        }
    }

    /** 获取玩家本次会话的登录方式（"pin" / "password" / null）。 */
    public static String getLoginMethod(UUID uuid) {
        PlayerAuthState state = STATES.get(uuid);
        return state != null ? state.loginMethod : null;
    }
}
