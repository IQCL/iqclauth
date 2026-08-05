package com.iqcl.auth.server;

import com.iqcl.auth.IqclAuth;
import com.iqcl.auth.config.ModConfig;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerTickEvents;
import net.fabricmc.fabric.api.event.player.AttackBlockCallback;
import net.fabricmc.fabric.api.event.player.AttackEntityCallback;
import net.fabricmc.fabric.api.event.player.PlayerBlockBreakEvents;
import net.fabricmc.fabric.api.event.player.UseBlockCallback;
import net.fabricmc.fabric.api.event.player.UseEntityCallback;
import net.fabricmc.fabric.api.event.player.UseItemCallback;
import net.fabricmc.fabric.api.networking.v1.ServerPlayConnectionEvents;
import net.minecraft.entity.player.PlayerEntity;
import net.minecraft.item.ItemStack;
import net.minecraft.server.network.ServerPlayNetworkHandler;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.network.ServerPlayerEntity;
import net.minecraft.text.Text;
import net.minecraft.util.ActionResult;
import net.minecraft.util.Formatting;
import net.minecraft.util.TypedActionResult;
import net.minecraft.util.math.Vec3d;

/**
 * 玩家行为限制管理器（服务端）。
 * <p>
 * 所有限制项均通过 {@link ModConfig} 中的布尔开关控制，服主可按需启用/关闭。
 * 限制仅对 <b>未认证</b> 玩家且 <b>超过宽限期</b> 后生效。
 * 登录成功后立即解除所有限制。
 * <p>
 * 支持两种隔离模式：
 * <ul>
 *   <li><b>Limbo 模式</b>（默认）：传送至隔离区，清空背包，施加失明效果</li>
 *   <li><b>原地冻结模式</b>：锁定位置，施加缓慢效果</li>
 * </ul>
 */
public final class PlayerRestrictionManager {

    private PlayerRestrictionManager() {
    }

    /** 注册所有限制事件处理器。 */
    public static void register() {
        // —— 玩家连接事件 ——
        ServerPlayConnectionEvents.INIT.register((handler, server) ->
                handlePlayerJoin(handler));

        ServerPlayConnectionEvents.DISCONNECT.register((handler, server) ->
                handlePlayerDisconnect(handler));

        // —— 数据包级拦截（防绕过）——
        registerPacketInterceptors();

        // —— 每 tick：超时踢出 + 未认证玩家逐项限制 ——
        ServerTickEvents.END_SERVER_TICK.register(PlayerRestrictionManager::onServerTick);

        // —— 拦截方块破坏 ——
        PlayerBlockBreakEvents.BEFORE.register((world, player, pos, state, blockEntity) -> {
            if (isRestricted(player, ModConfig.get().restrictBlockBreak)) {
                notifyBlocked(player, "破坏方块");
                return false;
            }
            return true;
        });

        // —— 拦截攻击方块 ——
        AttackBlockCallback.EVENT.register((player, world, hand, pos, direction) -> {
            if (isRestricted(player, ModConfig.get().restrictBlockAttack)) {
                notifyBlocked(player, "攻击方块");
                return ActionResult.FAIL;
            }
            return ActionResult.PASS;
        });

        // —— 拦截方块交互（放置/使用/打开容器）——
        UseBlockCallback.EVENT.register((player, world, hand, hitResult) -> {
            if (isRestricted(player, ModConfig.get().restrictBlockUse)) {
                notifyBlocked(player, "使用方块");
                return ActionResult.FAIL;
            }
            return ActionResult.PASS;
        });

        // —— 拦截实体交互 ——
        UseEntityCallback.EVENT.register((player, world, hand, entity, hitResult) -> {
            if (isRestricted(player, ModConfig.get().restrictEntityInteract)) {
                notifyBlocked(player, "与实体交互");
                return ActionResult.FAIL;
            }
            return ActionResult.PASS;
        });

        // —— 拦截攻击实体 ——
        AttackEntityCallback.EVENT.register((player, world, hand, entity, hitResult) -> {
            if (isRestricted(player, ModConfig.get().restrictEntityAttack)) {
                notifyBlocked(player, "攻击实体");
                return ActionResult.FAIL;
            }
            return ActionResult.PASS;
        });

        // —— 拦截物品使用 ——
        UseItemCallback.EVENT.register((player, world, hand) -> {
            if (isRestricted(player, ModConfig.get().restrictItemUse)) {
                notifyBlocked(player, "使用物品");
                return TypedActionResult.fail(player.getStackInHand(hand));
            }
            return TypedActionResult.pass(player.getStackInHand(hand));
        });

        IqclAuth.LOGGER.info("[IQCL Auth] 玩家行为限制器已注册");
    }

    /**
     * 数据包级拦截（防绕过核心）。
     * <p>
     * 通过 Fabric 事件回调实现多层面拦截：
     * <ul>
     *   <li>事件回调层：拦截方块破坏、实体交互、物品使用等（已在 register() 中注册）</li>
     *   <li>Tick 层：每 tick 检查 Limbo 模式位置、关闭容器、强制传送</li>
     * </ul>
     * 聊天/命令拦截由客户端 PinChatInterceptor 处理（PIN 明文永不上传），
     * 服务端仅保留 tick 层的容器关闭和位置锁定作为兜底。
     */
    private static void registerPacketInterceptors() {
        IqclAuth.LOGGER.debug("[IQCL Auth] 数据包级拦截已启用（事件回调 + tick 层）");
    }

    /**
     * 核心判定：某玩家的某行为是否应被限制。
     */
    private static boolean isRestricted(PlayerEntity player, boolean configFlag) {
        if (!configFlag) return false;
        if (!(player instanceof ServerPlayerEntity sp)) return false;
        if (AuthState.isAuthenticated(sp.getUuid())) return false;
        ModConfig config = ModConfig.get();
        if (AuthState.isInGracePeriod(sp.getUuid(), config.gracePeriodSeconds)) return false;
        return true;
    }

    /** 玩家加入 → 快照 + 持久会话检查 + 送入 Limbo + 发送引导消息。 */
    private static void handlePlayerJoin(ServerPlayNetworkHandler handler) {
        ServerPlayerEntity player = handler.getPlayer();
        if (player == null) return;

        // 快照物品和位置
        PlayerSessionManager.captureJoinSnapshot(player);

        // 初始化认证状态（从磁盘加载关联信息）
        AuthState.onPlayerJoin(player);

        ModConfig config = ModConfig.get();

        // —— 持久会话检查（在 sendToLimbo 之前！）——
        if (config.persistentSession) {
            boolean autoLoggedIn = PlayerSessionManager.tryPersistentSession(player);
            if (autoLoggedIn) {
                // JOIN 事件已在主线程，直接同步执行，避免竞态
                PlayerSessionManager.recordAuthenticatedIp(player);
                AuthState.authenticate(player);
                PlayerSessionManager.restoreFromLimbo(player);

                // 发送 game-session login
                String username = player.getEntityName();
                AuthState.PlayerAuthState st = AuthState.getState(player.getUuid());
                if (st != null && st.linkedUsername != null) {
                    username = st.linkedUsername;
                }
                ApiGateway.notifyLogin(player.getUuid().toString(), username);

                // 通知客户端设置已登录状态
                net.minecraft.network.PacketByteBuf buf =
                        net.fabricmc.fabric.api.networking.v1.PacketByteBufs.create();
                buf.writeBoolean(true);
                buf.writeString("欢迎回来！已自动恢复登录状态");
                net.fabricmc.fabric.api.networking.v1.ServerPlayNetworking.send(
                        player,
                        com.iqcl.auth.network.NetworkConstants.S2C_RESULT_ID,
                        buf);

                // 发送欢迎消息
                player.sendMessage(
                        Text.literal("[IQCL] ✅ 欢迎回来！已自动恢复登录状态")
                                .formatted(Formatting.GREEN, Formatting.BOLD), false);

                IqclAuth.LOGGER.info("[IQCL Auth] 玩家 {} 自动恢复登录成功",
                        player.getEntityName());
                return;
            }
        }

        // —— 已关联账号的检查：如果玩家已关联过，提示用绑定的 PIN 登录 ——
        AuthState.PlayerAuthState state = AuthState.getState(player.getUuid());
        if (state != null && state.linked) {
            player.sendMessage(
                    Text.literal("[IQCL] 你已关联 IQCL 账号 (ID: " + state.linkedDisplayId + ")，" +
                            "请使用该账号的 PIN 码登录")
                            .formatted(Formatting.YELLOW), false);
        }

        // —— 送入 Limbo 隔离区（仅未命中持久会话的玩家）——
        if (config.limboEnabled) {
            PlayerSessionManager.sendToLimbo(player);
        }

        // —— 发送引导消息 ——
        int graceSec = config.gracePeriodSeconds;
        String graceText = (graceSec < 0)
                ? "宽限时间已关闭，进服即受登录限制。"
                : ("宽限时间 " + graceSec + " 秒内可自由移动。");

        player.sendMessage(
                Text.literal("====================================")
                        .formatted(Formatting.GOLD), false);
        player.sendMessage(
                Text.literal("[IQCL] 欢迎来到服务器！")
                        .formatted(Formatting.GOLD, Formatting.BOLD), false);
        player.sendMessage(
                Text.literal("")
                        .formatted(Formatting.RESET), false);
        player.sendMessage(
                Text.literal("  你需要登录才能游玩，可选方式：")
                        .formatted(Formatting.WHITE), false);
        player.sendMessage(
                Text.literal("  PIN 登录: /iqcl login pin <你的PIN码>")
                        .formatted(Formatting.AQUA, Formatting.BOLD), false);
        if (config.passwordLoginEnabled) {
            player.sendMessage(
                    Text.literal("  密码登录: /iqcl login password <密码>")
                            .formatted(Formatting.AQUA, Formatting.BOLD), false);
            player.sendMessage(
                    Text.literal("  首次使用密码登录请先注册: /iqcl register password <密码> <确认密码>")
                            .formatted(Formatting.AQUA), false);
        }
        player.sendMessage(
                Text.literal("")
                        .formatted(Formatting.RESET), false);
        player.sendMessage(
                Text.literal("  " + graceText)
                        .formatted(Formatting.GRAY), false);
        player.sendMessage(
                Text.literal("  登录超时: " + config.loginTimeoutSeconds + " 秒")
                        .formatted(Formatting.GRAY), false);
        player.sendMessage(
                Text.literal("====================================")
                        .formatted(Formatting.GOLD), false);
    }

    /** 玩家离开 → 清理会话 + 通知 game-session logout。 */
    private static void handlePlayerDisconnect(ServerPlayNetworkHandler handler) {
        ServerPlayerEntity player = handler.getPlayer();
        if (player != null) {
            boolean wasAuthed = AuthState.isAuthenticated(player.getUuid());
            String mcUuid = player.getUuid().toString();
            String username = player.getEntityName();

            // 清理会话
            PlayerSessionManager.cleanupSession(player.getUuid());
            AuthState.onPlayerDisconnect(player.getUuid());

            // 通知 game-session logout
            if (wasAuthed) {
                ApiGateway.notifyLogout(mcUuid);
                IqclAuth.LOGGER.info("[IQCL Auth] 玩家 {} 已登出", username);
            }
        }
    }

    /** 每 tick：超时检查 + Limbo 坠落保护 + 传送后坠落保护 + 逐项限制。 */
    private static void onServerTick(MinecraftServer server) {
        ModConfig config = ModConfig.get();
        int sessionTimeout = config.sessionTimeoutSeconds;
        int loginTimeout = config.loginTimeoutSeconds;

        for (ServerPlayerEntity player : server.getPlayerManager().getPlayerList()) {
            boolean authed = AuthState.isAuthenticated(player.getUuid());

            // —— 超时踢出检查 ——
            if (AuthState.isTimedOut(player.getUuid(), sessionTimeout, loginTimeout)) {
                kickPlayer(player, authed);
                continue;
            }

            // —— Limbo 坠落保护：所有未认证玩家（含宽限期内）——
            if (!authed && config.limboEnabled) {
                PlayerSessionManager.tickLimboProtection(player, config);
            }

            // —— 传送后坠落保护：所有玩家（含已认证）——
            PlayerSessionManager.tickFallProtection(player);

            // —— 未认证 + 宽限已过 → 执行逐项 tick 限制 ——
            if (!authed && !AuthState.isInGracePeriod(player.getUuid(), config.gracePeriodSeconds)) {
                applyTickRestrictions(player, config);
            }
        }
    }

    /**
     * 每 tick 执行的限制（仅对未认证且过宽限的玩家）。
     * 注意：Limbo 位置锁定已在 tickLimboProtection 中统一处理。
     */
    private static void applyTickRestrictions(ServerPlayerEntity player, ModConfig config) {
        // —— Limbo 模式：位置锁定已在 tickLimboProtection 中处理 ——
        // —— 原地冻结模式：每 tick 冻结位置 ——
        if (!config.limboEnabled && config.restrictMovement) {
            Vec3d pos = player.getPos();
            net.minecraft.util.math.BlockPos spawnPos = player.getSpawnPointPosition();
            if (spawnPos != null) {
                Vec3d spawn = spawnPos.toCenterPos();
                double distSq = pos.squaredDistanceTo(spawn);
                if (distSq > 0.5) {
                    player.networkHandler.requestTeleport(
                            spawn.x, spawn.y, spawn.z,
                            player.getYaw(), player.getPitch());
                }
            }
            player.setVelocity(Vec3d.ZERO);
            player.fallDistance = 0f;
        }

        // —— 视角转动限制（仅在非 Limbo 模式）——
        if (config.restrictViewRotation && !config.limboEnabled) {
            float yaw = player.getYaw();
            float pitch = player.getPitch();
            float clampedPitch = Math.max(-45f, Math.min(45f, pitch));
            float sectorYaw = Math.round(yaw / 90f) * 90f;
            float clampedYaw = sectorYaw + Math.signum(yaw - sectorYaw) * 45f;
            player.networkHandler.requestTeleport(
                    player.getX(), player.getY(), player.getZ(),
                    clampedYaw, clampedPitch);
        }

        // —— 容器强制关闭 ——
        if (config.restrictContainerOpen
                && player.currentScreenHandler != player.playerScreenHandler) {
            player.closeHandledScreen();
        }

        // —— 周期性提示 ——
        if (player.age % 100 == 0) {
            sendLoginPrompt(player);
        }
    }

    /** 发送登录提示 + 剩余时间。 */
    private static void sendLoginPrompt(ServerPlayerEntity player) {
        ModConfig config = ModConfig.get();
        if (config.passwordLoginEnabled) {
            player.sendMessage(
                    Text.literal("[IQCL] 你尚未登录！请输入: /iqcl login pin <PIN码> 或 /iqcl login password <密码>")
                            .formatted(Formatting.RED, Formatting.BOLD),
                    false);
        } else {
            player.sendMessage(
                    Text.literal("[IQCL] 你尚未登录！请输入: /iqcl login pin <你的PIN码>")
                            .formatted(Formatting.RED, Formatting.BOLD),
                    false);
        }
        long remaining = getRemainingSeconds(player);
        if (remaining > 0) {
            player.sendMessage(
                    Text.literal("  超时将在 " + remaining + " 秒后踢出")
                            .formatted(Formatting.GRAY),
                    false);
        }
    }

    /** 计算玩家距离超时还剩多少秒。 */
    private static long getRemainingSeconds(ServerPlayerEntity player) {
        ModConfig config = ModConfig.get();
        boolean authed = AuthState.isAuthenticated(player.getUuid());
        int timeout = authed ? config.sessionTimeoutSeconds : config.loginTimeoutSeconds;
        if (timeout <= 0) return 0;

        var state = AuthState.getState(player.getUuid());
        if (state == null) return 0;

        long now = System.currentTimeMillis();
        long lastActive = state.lastActivityMs;
        long elapsed = (now - lastActive) / 1000;
        long remaining = timeout - elapsed;
        return Math.max(0, remaining);
    }

    /** 通知玩家操作被阻止。 */
    private static void notifyBlocked(PlayerEntity player, String action) {
        if (player.age % 80 == 0 && player instanceof ServerPlayerEntity sp) {
            ModConfig config = ModConfig.get();
            String cmd = config.passwordLoginEnabled
                    ? "/iqcl login pin <PIN> 或 /iqcl login password <密码>"
                    : "/iqcl login pin <PIN>";
            sp.sendMessage(
                    Text.literal("[IQCL] 你尚未登录，无法" + action + "。请输入 " + cmd)
                            .formatted(Formatting.RED),
                    false);
        }
    }

    /** 踢出超时玩家。 */
    private static void kickPlayer(ServerPlayerEntity player, boolean wasAuthed) {
        String reason;
        if (wasAuthed) {
            reason = "[IQCL] 登录超时（超过 " + ModConfig.get().sessionTimeoutSeconds
                    + " 秒无活动），请重新输入 PIN";
        } else {
            reason = "[IQCL] 未在规定时间内完成登录，请重新连接服务器并输入 PIN";
        }
        player.networkHandler.disconnect(Text.literal(reason));
        IqclAuth.LOGGER.info("[IQCL Auth] 玩家 {} 因 {}超时被踢出",
                player.getEntityName(), wasAuthed ? "session" : "login");
    }
}
