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
 *   <li>当前是否已通过 PIN 验证（{@code authenticated}）</li>
 *   <li>上次活动时间（用于超时踢出）</li>
 *   <li>加入时间（用于首次宽限时间）</li>
 * </ul>
 * 线程安全，可在工作线程与服务端主线程并发访问。
 */
public final class AuthState {

    /** 每玩家的认证状态（key = player UUID）。 */
    private static final Map<UUID, PlayerAuthState> STATES = new ConcurrentHashMap<>();

    private AuthState() {
    }

    /** 记录玩家加入（尚未认证）。彻底重置所有状态，防止残留。 */
    public static void onPlayerJoin(ServerPlayerEntity player) {
        long now = System.currentTimeMillis();
        // 彻底重置：所有关联信息、权限、状态全部清空
        STATES.put(player.getUuid(), new PlayerAuthState(false, now, now));
    }

    /** 记录玩家离线，清理状态。 */
    public static void onPlayerDisconnect(UUID uuid) {
        STATES.remove(uuid);
    }

    /** 标记玩家已通过 PIN 验证。 */
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
     * 标记玩家已通过 PIN 验证，并保存 IQCL 账号信息供 /link 使用。
     *
     * @param displayId    IQCL 显示 ID（可为 null）
     * @param username     IQCL 用户名（可为 null）
     * @param permission   权限等级
     */
    public static void authenticateWithAccount(ServerPlayerEntity player,
                                               Integer displayId, String username,
                                               String permission) {
        PlayerAuthState state = STATES.get(player.getUuid());
        if (state != null) {
            state.authenticated = true;
            state.lastActivityMs = System.currentTimeMillis();
            state.pendingDisplayId = displayId;
            state.pendingUsername = username;
            state.permission = permission;
        } else {
            long now = System.currentTimeMillis();
            PlayerAuthState newState = new PlayerAuthState(true, now, now);
            newState.pendingDisplayId = displayId;
            newState.pendingUsername = username;
            newState.permission = permission;
            STATES.put(player.getUuid(), newState);
        }
    }

    /**
     * 确认账号关联：将 pending 账户信息标记为已关联。
     */
    public static void confirmLink(UUID uuid) {
        PlayerAuthState state = STATES.get(uuid);
        if (state != null) {
            state.linkedDisplayId = state.pendingDisplayId;
            state.linkedUsername = state.pendingUsername;
            state.linked = true;
            state.pendingDisplayId = null;
            state.pendingUsername = null;
        }
    }

    /**
     * 取消待关联状态（PIN 验证成功但玩家未 link 就超时/登出）。
     */
    public static void cancelPendingLink(UUID uuid) {
        PlayerAuthState state = STATES.get(uuid);
        if (state != null) {
            state.pendingDisplayId = null;
            state.pendingUsername = null;
        }
    }

    /** 玩家是否已完成账号关联。 */
    public static boolean isLinked(UUID uuid) {
        PlayerAuthState state = STATES.get(uuid);
        return state != null && state.linked;
    }

    /** 玩家是否有待确认的关联（PIN 验证成功但未 /link）。 */
    public static boolean hasPendingLink(UUID uuid) {
        PlayerAuthState state = STATES.get(uuid);
        return state != null && state.pendingDisplayId != null;
    }

    /** 登出：彻底重置为未认证状态，清除所有关联信息。 */
    public static void logout(ServerPlayerEntity player) {
        long now = System.currentTimeMillis();
        // 彻底重置：清除所有关联信息、权限
        STATES.put(player.getUuid(), new PlayerAuthState(false, now, now));
    }

    /** 玩家是否已认证。 */
    public static boolean isAuthenticated(UUID uuid) {
        PlayerAuthState state = STATES.get(uuid);
        return state != null && state.authenticated;
    }

    /** 更新玩家最近活动时间（通过 PIN 时调用）。 */
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
     * @param uuid 玩家 UUID
     * @param sessionTimeout 已认证玩家 session 超时（秒）
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
        public final long joinMs;
        public volatile long lastActivityMs;

        // —— IQCL 账号关联信息 ——
        /** 待确认关联的 IQCL displayId（PIN 验证成功后暂存，/link 确认后移入 linked） */
        public volatile Integer pendingDisplayId;
        /** 待确认关联的 IQCL username */
        public volatile String pendingUsername;
        /** 已关联的 IQCL displayId */
        public volatile Integer linkedDisplayId;
        /** 已关联的 IQCL username */
        public volatile String linkedUsername;
        /** 权限等级: trial / formal / banned */
        public volatile String permission;
        /** 是否已完成账号关联（/link 确认后为 true） */
        public volatile boolean linked;

        PlayerAuthState(boolean authenticated, long joinMs, long lastActivityMs) {
            this.authenticated = authenticated;
            this.joinMs = joinMs;
            this.lastActivityMs = lastActivityMs;
            this.pendingDisplayId = null;
            this.pendingUsername = null;
            this.linkedDisplayId = null;
            this.linkedUsername = null;
            this.permission = null;
            this.linked = false;
        }
    }
}
