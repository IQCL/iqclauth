/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.server;

import com.iqcl.auth.IqclAuth;
import com.iqcl.auth.config.ModConfig;
import com.iqcl.auth.network.NetworkConstants;
import com.iqcl.auth.password.LoginAttemptLimiter;
import com.iqcl.auth.password.PasswordCommandHandler;
import com.iqcl.auth.password.PasswordManager;
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
 *   <li>{@code /iqcl login password <密码>} — 密码登录（所有玩家可用，服务端降级路径）</li>
 *   <li>{@code /iqcl register password <密码> <确认>} — 注册本服密码账号</li>
 *   <li>{@code /iqcl changepassword <旧> <新>} — 修改密码（需已登录）</li>
 *   <li>{@code /iqcl unregister password <密码>} — 注销密码账号（需已登录）</li>
 *   <li>{@code /iqcl account} — 查看自身账号状态</li>
 *   <li>{@code /iqcl status [player]} — 查看认证状态</li>
 *   <li>{@code /iqcl logout [player]} — 登出</li>
 *   <li>{@code /iqcl force <player>} — 强行登录玩家（OP 2）</li>
 *   <li>{@code /iqcl link} — 确认 IQCL 账号关联</li>
 *   <li>{@code /iqcl admin unregister <player>} — 强制删除玩家密码账号（OP 2）</li>
 *   <li>{@code /iqcl admin resetpassword <player>} — 重置玩家密码（OP 2）</li>
 *   <li>{@code /iqcl admin reloadstorage} — 热重载存储后端（OP 2）</li>
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
                                                .executes(CommandRegistry::executeLoginPin)))
                                .then(CommandManager.literal("password")
                                        .then(CommandManager.argument("password",
                                                StringArgumentType.greedyString())
                                                .executes(PasswordCommandHandler::executeLoginPassword)))
                                .then(CommandManager.literal("confirmtotp")
                                        .then(CommandManager.argument("code",
                                                StringArgumentType.string())
                                                .executes(PasswordCommandHandler::executeLoginConfirmTotp))))
                        .then(CommandManager.literal("register")
                                .then(CommandManager.literal("password")
                                        .then(CommandManager.argument("password",
                                                StringArgumentType.string())
                                                .then(CommandManager.argument("confirm",
                                                        StringArgumentType.string())
                                                        .executes(PasswordCommandHandler::executeRegisterPassword)))))
                        .then(CommandManager.literal("changepassword")
                                .then(CommandManager.argument("old",
                                        StringArgumentType.string())
                                        .then(CommandManager.argument("new",
                                                StringArgumentType.string())
                                                .executes(PasswordCommandHandler::executeChangePassword))))
                        .then(CommandManager.literal("unregister")
                                .then(CommandManager.literal("password")
                                        .then(CommandManager.argument("password",
                                                StringArgumentType.string())
                                                .executes(PasswordCommandHandler::executeUnregisterPassword))))
                        .then(CommandManager.literal("account")
                                .executes(PasswordCommandHandler::executeAccount))
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
                                .executes(CommandRegistry::executeLink))
                        .then(CommandManager.literal("admin")
                                .requires(source -> source.hasPermissionLevel(2))
                                .then(CommandManager.literal("unregister")
                                        .then(CommandManager.argument("player",
                                                EntityArgumentType.player())
                                                .executes(PasswordCommandHandler::executeAdminUnregister)))
                                .then(CommandManager.literal("resetpassword")
                                        .then(CommandManager.argument("player",
                                                EntityArgumentType.player())
                                                .executes(PasswordCommandHandler::executeAdminResetPassword)))
                                .then(CommandManager.literal("reloadstorage")
                                        .executes(PasswordCommandHandler::executeAdminReloadStorage)))
                        .then(CommandManager.literal("enablerotp")
                                .executes(PasswordCommandHandler::executeEnableTotp))
                        .then(CommandManager.literal("confirmtotp")
                                .then(CommandManager.argument("code",
                                        StringArgumentType.string())
                                        .executes(PasswordCommandHandler::executeConfirmTotp)))
                        .then(CommandManager.literal("disablerotp")
                                .then(CommandManager.argument("password",
                                        StringArgumentType.string())
                                        .executes(PasswordCommandHandler::executeDisableTotp))));
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
        boolean registered = PasswordManager.isRegisteredSync(target.getUuid());
        if (authed) {
            int timeout = ModConfig.get().sessionTimeoutSeconds;
            if (isOther) {
                source.sendFeedback(() ->
                        Text.literal("[IQCL] ✅ " + target.getEntityName()
                                + " 已通过认证（离线会话保留 " + timeout + " 秒）")
                                .formatted(Formatting.GREEN), false);
            } else {
                source.sendFeedback(() ->
                        Text.literal("[IQCL] ✅ 你已通过认证（在线不受 session 超时限制，离线会话保留 " + timeout + " 秒）")
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
                        Text.literal("  PIN 登录: /iqcl login pin <你的PIN码>")
                                .formatted(Formatting.AQUA), false);
                if (config.passwordLoginEnabled) {
                    source.sendFeedback(() ->
                            Text.literal("  密码登录: /iqcl login password <密码>")
                                    .formatted(Formatting.AQUA), false);
                    if (!registered) {
                        source.sendFeedback(() ->
                                Text.literal("  首次使用请先注册: /iqcl register password <密码> <确认密码>")
                                        .formatted(Formatting.AQUA), false);
                    }
                }
                source.sendFeedback(() ->
                        Text.literal("  宽限时间: " + graceSec + " 秒 | 登录超时: " + loginTimeout + " 秒")
                                .formatted(Formatting.GRAY), false);
            }
        }
        // 密码账号状态
        boolean totpEnabled = PasswordManager.isTotpEnabledSync(target.getUuid());
        source.sendFeedback(() ->
                Text.literal("  密码账号: " + (registered ? "已注册" : "未注册")
                        + (registered ? " | TOTP: " + (totpEnabled ? "已启用" : "未启用") : ""))
                        .formatted(Formatting.GRAY), false);
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
        LoginAttemptLimiter.reset(player.getUuid());
        // 先通知客户端重置本地认证状态（在传送前发送，避免传送延迟丢包）
        PacketByteBuf buf = PacketByteBufs.create();
        ServerPlayNetworking.send(player, NetworkConstants.S2C_LOGOUT_ID, buf);
        // 清理会话记录
        PlayerSessionManager.removeSession(player.getUuid());
        // 登出：先快照当前位置/物品 → 再传送回 Limbo（下次登录可回到登出前位置）
        PlayerSessionManager.logoutToLimbo(player, ModConfig.get().clearInventoryOnJoin);

        player.sendMessage(
                Text.literal("[IQCL] 已成功登出，你已被送回未登录区。请重新输入 /iqcl login pin <PIN码> 或 /iqcl login password <密码> 登录")
                        .formatted(Formatting.GREEN),
                false);
        IqclAuth.LOGGER.info("[IQCL Auth] 玩家 {} 已登出并送回 Limbo", player.getEntityName());
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
        LoginAttemptLimiter.reset(target.getUuid());
        // 先通知客户端重置本地认证状态
        PacketByteBuf buf = PacketByteBufs.create();
        ServerPlayNetworking.send(target, NetworkConstants.S2C_LOGOUT_ID, buf);
        // 清理会话记录
        PlayerSessionManager.removeSession(target.getUuid());
        // 登出：先快照当前位置/物品 → 再传送回 Limbo
        PlayerSessionManager.logoutToLimbo(target, ModConfig.get().clearInventoryOnJoin);

        source.sendFeedback(() ->
                Text.literal("[IQCL] 已登出玩家 " + target.getEntityName() + " 并送回未登录区")
                        .formatted(Formatting.GREEN), false);
        target.sendMessage(
                Text.literal("[IQCL] 你已被管理员登出并送回未登录区，请重新输入 /iqcl login pin <PIN码> 或 /iqcl login password <密码> 登录")
                        .formatted(Formatting.RED),
                false);
        IqclAuth.LOGGER.info("[IQCL Auth] 管理员 {} 登出玩家 {} 并送回 Limbo",
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
     * {@code /iqcl link} — 引导玩家通过 PIN 登录绑定 IQCL 账号。
     * <p>
     * 分三种情况：
     * <ol>
     *   <li>未登录 → 直接提示使用 PIN 登录；</li>
     *   <li>已通过 PIN 登录（会话内有 displayId）→ 展示当前绑定信息，不登出；</li>
     *   <li>已通过密码/TOTP 登录 → <b>真正执行登出</b>（清服务端认证状态 +
     *       通知客户端重置 + 送回 Limbo），并明确提示玩家用 PIN 重新登录。</li>
     * </ol>
     * 绑定逻辑已由 IQCL 后端接管，本地不再存储 UUID↔displayId 关系。
     */
    private static int executeLink(CommandContext<ServerCommandSource> context) {
        ServerCommandSource source = context.getSource();
        ServerPlayerEntity player = source.getPlayer();
        if (player == null) {
            source.sendError(Text.literal("此命令只能由玩家执行").formatted(Formatting.RED));
            return 0;
        }

        // 已通过 PIN 登录（会话内有 displayId）—— 已绑定，展示信息即可，不登出
        Integer displayId = AuthState.getCurrentDisplayId(player.getUuid());
        if (AuthState.isAuthenticated(player.getUuid()) && displayId != null) {
            String username = AuthState.getCurrentUsername(player.getUuid());
            player.sendMessage(
                    Text.literal("[IQCL] 你当前已通过 PIN 登录并绑定 IQCL 账号：")
                            .formatted(Formatting.GREEN), false);
            player.sendMessage(
                    Text.literal("  显示 ID: " + displayId
                            + (username != null ? " | 用户名: " + username : ""))
                            .formatted(Formatting.WHITE), false);
            player.sendMessage(
                    Text.literal("  可在 IQCL 安全中心查看或解绑")
                            .formatted(Formatting.GRAY), false);
            return 1;
        }

        if (AuthState.isAuthenticated(player.getUuid())) {
            // 已登录（密码/TOTP 登录）—— 真正登出：清服务端状态 + 通知客户端 + 送回 Limbo
            LoginAttemptLimiter.reset(player.getUuid());

            // 通知客户端重置本地认证状态（客户端会提示"已登出，请重新登录"）
            PacketByteBuf buf = PacketByteBufs.create();
            ServerPlayNetworking.send(player, NetworkConstants.S2C_LOGOUT_ID, buf);

            // 清理会话记录
            PlayerSessionManager.removeSession(player.getUuid());
            // 登出并送回 Limbo（内部完成 AuthState.logout 与账号绑定清理）
            PlayerSessionManager.logoutToLimbo(player, ModConfig.get().clearInventoryOnJoin);

            player.sendMessage(
                    Text.literal("[IQCL] 你当前是密码/TOTP 登录，绑定 IQCL 账号需要用 PIN 重新登录。")
                            .formatted(Formatting.YELLOW), false);
            player.sendMessage(
                    Text.literal("  已为你登出并送回隔离区，请输入：")
                            .formatted(Formatting.YELLOW), false);
            player.sendMessage(
                    Text.literal("  /iqcl login pin <你的PIN码>")
                            .formatted(Formatting.AQUA, Formatting.BOLD), false);
            player.sendMessage(
                    Text.literal("  PIN 登录成功后将自动绑定，可在 IQCL 安全中心查看或解绑")
                            .formatted(Formatting.GRAY), false);

            IqclAuth.LOGGER.info("[IQCL Auth] 玩家 {} 通过 /iqcl link 登出，等待 PIN 登录绑定",
                    player.getEntityName());
        } else {
            // 未登录 —— 直接提示 PIN 登录
            player.sendMessage(
                    Text.literal("[IQCL] 请使用 PIN 码登录以绑定 IQCL 账号：")
                            .formatted(Formatting.YELLOW), false);
            player.sendMessage(
                    Text.literal("  /iqcl login pin <你的PIN码>")
                            .formatted(Formatting.AQUA, Formatting.BOLD), false);
            player.sendMessage(
                    Text.literal("  PIN 登录成功后将自动绑定，可在 IQCL 安全中心查看或解绑")
                            .formatted(Formatting.GRAY), false);
        }
        return 1;
    }
}
