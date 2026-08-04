package com.iqcl.auth.server;

import com.iqcl.auth.IqclAuth;
import com.iqcl.auth.config.ModConfig;
import com.iqcl.auth.network.NetworkConstants;
import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.arguments.StringArgumentType;
import com.mojang.brigadier.context.CommandContext;
import com.mojang.brigadier.exceptions.CommandSyntaxException;
import net.fabricmc.fabric.api.command.v2.CommandRegistrationCallback;
import net.fabricmc.fabric.api.networking.v1.PacketByteBufs;
import net.fabricmc.fabric.api.networking.v1.ServerPlayNetworking;
import net.minecraft.command.argument.EntityArgumentType;
import net.minecraft.network.PacketByteBuf;
import net.minecraft.server.command.CommandManager;
import net.minecraft.server.command.ServerCommandSource;
import net.minecraft.server.network.ServerPlayerEntity;
import net.minecraft.text.Text;
import net.minecraft.util.Formatting;

/**
 * 指令注册器。
 * <p>
 * 使用 Fabric {@link CommandRegistrationCallback} 注册以下指令：
 * <ul>
 *   <li>{@code /iqcl login pin <pin>} — 玩家 PIN 登录验证（所有玩家可用）</li>
 *   <li>{@code /iqcl status} — 查看自身认证状态（所有玩家可用）</li>
 *   <li>{@code /iqcl status <player>} — 查看指定玩家状态（需 OP 2 级）</li>
 *   <li>{@code /iqcl logout} — 登出自己（所有玩家可用）</li>
 *   <li>{@code /iqcl logout <player>} — 登出指定玩家（需 OP 2 级）</li>
 * </ul>
 * <p>
 * 权限规则：
 * <ul>
 *   <li>普通玩家无参数执行 status/logout → 操作自己</li>
 *   <li>普通玩家带玩家名参数 → 需要 OP 2 级权限</li>
 *   <li>服务端控制台必须带玩家名参数</li>
 * </ul>
 */
public final class CommandRegistry {

    private CommandRegistry() {
    }

    /** 在模组主入口调用，注册所有指令。 */
    public static void register() {
        CommandRegistrationCallback.EVENT.register(
                (dispatcher, registryAccess, environment) -> {
                    registerIqclRoot(dispatcher);
                });
        IqclAuth.LOGGER.info("[IQCL Auth] 指令已注册");
    }

    private static void registerIqclRoot(CommandDispatcher dispatcher) {
        dispatcher.register(
                CommandManager.literal("iqcl")
                        .then(CommandManager.literal("login")
                                .then(CommandManager.literal("pin")
                                        .then(CommandManager.argument("pin",
                                                StringArgumentType.string())
                                                .executes(CommandRegistry::executeLoginPin))))
                        .then(CommandManager.literal("status")
                                .executes(CommandRegistry::executeStatusSelf)
                                .then(CommandManager.argument("player",
                                        EntityArgumentType.player())
                                        .requires(source -> source.hasPermissionLevel(2))
                                        .executes(CommandRegistry::executeStatusOther)))
                        .then(CommandManager.literal("logout")
                                .executes(CommandRegistry::executeLogoutSelf)
                                .then(CommandManager.argument("player",
                                        EntityArgumentType.player())
                                        .requires(source -> source.hasPermissionLevel(2))
                                        .executes(CommandRegistry::executeLogoutOther)))
                        .then(CommandManager.literal("force")
                                .requires(source -> source.hasPermissionLevel(2))
                                .then(CommandManager.argument("player",
                                        EntityArgumentType.player())
                                        .executes(CommandRegistry::executeForce)))
                        .then(CommandManager.literal("link")
                                .executes(CommandRegistry::executeLink)));
    }

    /**
     * 执行 {@code /iqcl login pin <pin>}。
     * <p>
     * 服务端仅做占位处理，实际 PIN 加密与密文发送由客户端拦截器完成。
     */
    private static int executeLoginPin(CommandContext<ServerCommandSource> context) {
        ServerPlayerEntity player = context.getSource().getPlayer();
        if (player == null) {
            context.getSource().sendError(
                    Text.literal("此命令只能由玩家执行").formatted(Formatting.RED));
            return 0;
        }
        player.sendMessage(
                Text.literal("[IQCL] PIN 验证请求已发送，等待服务端响应...").formatted(Formatting.YELLOW),
                false);
        return 1;
    }

    // ========== status ==========

    /** {@code /iqcl status} — 查看自己状态。服务端控制台执行报错。 */
    private static int executeStatusSelf(CommandContext<ServerCommandSource> context) {
        ServerCommandSource source = context.getSource();
        ServerPlayerEntity player = source.getPlayer();
        if (player == null) {
            source.sendError(Text.literal("服务端执行必须指定玩家名: /iqcl status <player>")
                    .formatted(Formatting.RED));
            return 0;
        }
        showStatus(source, player, false);
        return 1;
    }

    /** {@code /iqcl status <player>} — 管理员查看指定玩家状态。 */
    private static int executeStatusOther(CommandContext<ServerCommandSource> context)
            throws CommandSyntaxException {
        ServerCommandSource source = context.getSource();
        ServerPlayerEntity target = EntityArgumentType.getPlayer(context, "player");
        showStatus(source, target, true);
        return 1;
    }

    private static void showStatus(ServerCommandSource source,
                                   ServerPlayerEntity target, boolean isOther) {
        boolean authed = AuthState.isAuthenticated(target.getUuid());
        if (authed) {
            int timeout = ModConfig.get().sessionTimeoutSeconds;
            if (isOther) {
                source.sendFeedback(() ->
                        Text.literal("[IQCL] ✅ " + target.getEntityName()
                                + " 已通过 PIN 认证（session 超时 " + timeout + " 秒）")
                                .formatted(Formatting.GREEN), false);
            } else {
                source.sendFeedback(() ->
                        Text.literal("[IQCL] ✅ 你已通过 PIN 认证（session 超时 " + timeout + " 秒）")
                                .formatted(Formatting.GREEN), false);
            }
        } else {
            ModConfig config = ModConfig.get();
            int graceSec = config.gracePeriodSeconds;
            int loginTimeout = config.loginTimeoutSeconds;
            if (isOther) {
                source.sendFeedback(() ->
                        Text.literal("[IQCL] ❌ " + target.getEntityName() + " 尚未登录")
                                .formatted(Formatting.RED, Formatting.BOLD), false);
                source.sendFeedback(() ->
                        Text.literal("  宽限时间: " + graceSec + " 秒 | 登录超时: " + loginTimeout + " 秒")
                                .formatted(Formatting.GRAY), false);
            } else {
                source.sendFeedback(() ->
                        Text.literal("[IQCL] ❌ 你尚未登录！")
                                .formatted(Formatting.RED, Formatting.BOLD), false);
                source.sendFeedback(() ->
                        Text.literal("  请输入: /iqcl login pin <你的PIN码>")
                                .formatted(Formatting.AQUA), false);
                source.sendFeedback(() ->
                        Text.literal("  宽限时间: " + graceSec + " 秒 | 登录超时: " + loginTimeout + " 秒")
                                .formatted(Formatting.GRAY), false);
            }
        }
    }

    // ========== logout ==========

    /** {@code /iqcl logout} — 登出自己。服务端控制台执行报错。 */
    private static int executeLogoutSelf(CommandContext<ServerCommandSource> context) {
        ServerCommandSource source = context.getSource();
        ServerPlayerEntity player = source.getPlayer();
        if (player == null) {
            source.sendError(Text.literal("服务端执行必须指定玩家名: /iqcl logout <player>")
                    .formatted(Formatting.RED));
            return 0;
        }

        boolean authed = AuthState.isAuthenticated(player.getUuid());
        if (!authed) {
            player.sendMessage(
                    Text.literal("[IQCL] 你当前未登录，无需登出")
                            .formatted(Formatting.YELLOW),
                    false);
            return 0;
        }
        AuthState.logout(player);
        PlayerSessionManager.removeAccountBinding(player);
        PlayerSessionManager.removeSession(player.getUuid());

        // 通知客户端重置本地认证状态
        PacketByteBuf buf = PacketByteBufs.create();
        ServerPlayNetworking.send(player, NetworkConstants.S2C_LOGOUT_ID, buf);

        player.sendMessage(
                Text.literal("[IQCL] 已成功登出，请重新输入 /iqcl login pin <PIN码> 登录")
                        .formatted(Formatting.GREEN),
                false);
        IqclAuth.LOGGER.info("[IQCL Auth] 玩家 {} 已登出", player.getEntityName());
        return 1;
    }

    /** {@code /iqcl logout <player>} — 管理员登出指定玩家。 */
    private static int executeLogoutOther(CommandContext<ServerCommandSource> context)
            throws CommandSyntaxException {
        ServerCommandSource source = context.getSource();
        ServerPlayerEntity target = EntityArgumentType.getPlayer(context, "player");

        boolean authed = AuthState.isAuthenticated(target.getUuid());
        if (!authed) {
            source.sendFeedback(() ->
                    Text.literal("[IQCL] " + target.getEntityName() + " 当前未登录，无需登出")
                            .formatted(Formatting.YELLOW), false);
            return 0;
        }
        AuthState.logout(target);
        PlayerSessionManager.removeAccountBinding(target);
        PlayerSessionManager.removeSession(target.getUuid());

        // 通知目标客户端重置本地认证状态
        PacketByteBuf buf = PacketByteBufs.create();
        ServerPlayNetworking.send(target, NetworkConstants.S2C_LOGOUT_ID, buf);

        source.sendFeedback(() ->
                Text.literal("[IQCL] 已登出玩家 " + target.getEntityName())
                        .formatted(Formatting.GREEN), false);
        target.sendMessage(
                Text.literal("[IQCL] 你已被管理员登出，请重新输入 /iqcl login pin <PIN码> 登录")
                        .formatted(Formatting.RED),
                false);
        IqclAuth.LOGGER.info("[IQCL Auth] 管理员 {} 登出玩家 {}",
                source.getName(), target.getEntityName());
        return 1;
    }

    // ========== force ==========

    /**
     * {@code /iqcl force <player>} — 管理员强行登录玩家（绕过 PIN 验证）。
     * <p>
     * 仅适用于 OP 2 级及以上权限或服务端控制台。
     */
    private static int executeForce(CommandContext<ServerCommandSource> context)
            throws CommandSyntaxException {
        ServerCommandSource source = context.getSource();
        ServerPlayerEntity target = EntityArgumentType.getPlayer(context, "player");

        if (AuthState.isAuthenticated(target.getUuid())) {
            source.sendFeedback(() ->
                    Text.literal("[IQCL] " + target.getEntityName() + " 已经登录")
                            .formatted(Formatting.YELLOW), false);
            return 0;
        }

        AuthState.authenticate(target);
        PlayerSessionManager.recordAuthenticatedIp(target);

        // 通知目标客户端
        PacketByteBuf buf = PacketByteBufs.create();
        buf.writeBoolean(true);
        buf.writeString("管理员已为你强行登录");
        ServerPlayNetworking.send(target, NetworkConstants.S2C_RESULT_ID, buf);

        source.sendFeedback(() ->
                Text.literal("[IQCL] 已强行登录玩家 " + target.getEntityName())
                        .formatted(Formatting.GREEN), false);
        target.sendMessage(
                Text.literal("[IQCL] 管理员已为你强行登录")
                        .formatted(Formatting.GREEN),
                false);
        IqclAuth.LOGGER.info("[IQCL Auth] 管理员 {} 强行登录玩家 {}",
                source.getName(), target.getEntityName());
        return 1;
    }

    // ========== link ==========

    /**
     * {@code /iqcl link} — 玩家确认将游戏账号与 IQCL 账号关联。
     */
    private static int executeLink(CommandContext<ServerCommandSource> context) {
        ServerCommandSource source = context.getSource();
        ServerPlayerEntity player = source.getPlayer();
        if (player == null) {
            source.sendError(Text.literal("此命令只能由玩家执行").formatted(Formatting.RED));
            return 0;
        }

        AuthState.PlayerAuthState state = AuthState.getState(player.getUuid());
        if (state == null || !AuthState.isAuthenticated(player.getUuid())) {
            player.sendMessage(
                    Text.literal("[IQCL] 请先通过 /iqcl login pin <PIN码> 登录后再关联")
                            .formatted(Formatting.RED),
                    false);
            return 0;
        }

        if (AuthState.isLinked(player.getUuid())) {
            player.sendMessage(
                    Text.literal("[IQCL] 你已经关联过 IQCL 账号，无需重复关联")
                            .formatted(Formatting.YELLOW),
                    false);
            return 0;
        }

        if (state.pendingDisplayId == null && state.pendingUsername == null) {
            player.sendMessage(
                    Text.literal("[IQCL] 当前没有待关联的 IQCL 账号信息，请先完成 PIN 登录")
                            .formatted(Formatting.RED),
                    false);
            return 0;
        }

        // 确认关联
        AuthState.confirmLink(player.getUuid());

        String idLine = state.linkedDisplayId != null
                ? "ID: " + state.linkedDisplayId : "";
        String nameLine = state.linkedUsername != null
                ? "用户名: " + state.linkedUsername : "";

        // 完成登录流程
        ServerNetworkHandler.completeLogin(
                player.getServer(), player, player.getEntityName(),
                state.linkedDisplayId, state.linkedUsername);

        player.sendMessage(
                Text.literal("====================================")
                        .formatted(Formatting.GOLD), false);
        player.sendMessage(
                Text.literal("[IQCL] ✅ 账号关联成功！")
                        .formatted(Formatting.GREEN, Formatting.BOLD), false);
        player.sendMessage(
                Text.literal("  " + idLine)
                        .formatted(Formatting.WHITE), false);
        player.sendMessage(
                Text.literal("  " + nameLine)
                        .formatted(Formatting.WHITE), false);
        player.sendMessage(
                Text.literal("====================================")
                        .formatted(Formatting.GOLD), false);

        IqclAuth.LOGGER.info("[IQCL Auth] 玩家 {} 已关联 IQCL 账号 (displayId={}, username={})",
                player.getEntityName(), state.linkedDisplayId, state.linkedUsername);
        return 1;
    }
}
