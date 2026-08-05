/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.password;

import com.iqcl.auth.config.ModConfig;
import com.iqcl.auth.server.AuthState;
import com.mojang.brigadier.context.CommandContext;
import com.mojang.brigadier.exceptions.CommandSyntaxException;
import net.minecraft.command.argument.EntityArgumentType;
import net.minecraft.server.command.ServerCommandSource;
import net.minecraft.server.network.ServerPlayerEntity;
import net.minecraft.text.Text;
import net.minecraft.util.Formatting;

/**
 * 密码命令 executes 集中地。
 * <p>
 * 阶段 1：所有命令走服务端降级路径（明文经 MC 加密通道传输，服务端不记录日志）。
 * 阶段 2：客户端装 mod 时由 {@code PasswordChatInterceptor} 拦截，明文命令不会到达服务端。
 * <p>
 * 安全约定：
 * <ul>
 *   <li>严禁 {@code LOGGER.info} 或 {@code sendFeedback} 包含密码明文</li>
 *   <li>所有反馈消息均为固定文案，不含用户输入</li>
 * </ul>
 */
public final class PasswordCommandHandler {

    private PasswordCommandHandler() {
    }

    // ========== login password ==========

    /** {@code /iqcl login password <密码>} — 服务端降级路径。 */
    public static int executeLoginPassword(CommandContext<ServerCommandSource> context) {
        if (!ModConfig.get().passwordLoginEnabled) {
            context.getSource().sendError(Text.literal("[IQCL] 密码登录功能未启用")
                    .formatted(Formatting.RED));
            return 0;
        }
        ServerPlayerEntity player = context.getSource().getPlayer();
        if (player == null) {
            context.getSource().sendError(Text.literal("此命令只能由玩家执行")
                    .formatted(Formatting.RED));
            return 0;
        }

        // 已认证玩家拒绝重复登录
        if (AuthState.isAuthenticated(player.getUuid())) {
            player.sendMessage(
                    Text.literal("[IQCL] 你已登录，无需重复操作")
                            .formatted(Formatting.YELLOW),
                    false);
            return 0;
        }

        String password = context.getArgument("password", String.class);

        // 发送"验证中"提示，密码不出现在消息中
        player.sendMessage(
                Text.literal("[IQCL] 密码验证中...")
                        .formatted(Formatting.YELLOW),
                false);

        PasswordManager.login(player.getServer(), player, password, null);
        return 1;
    }

    // ========== register password ==========

    /** {@code /iqcl register password <密码> <确认>}。 */
    public static int executeRegisterPassword(CommandContext<ServerCommandSource> context) {
        if (!ModConfig.get().passwordLoginEnabled) {
            context.getSource().sendError(Text.literal("[IQCL] 密码登录功能未启用")
                    .formatted(Formatting.RED));
            return 0;
        }
        ServerPlayerEntity player = context.getSource().getPlayer();
        if (player == null) {
            context.getSource().sendError(Text.literal("此命令只能由玩家执行")
                    .formatted(Formatting.RED));
            return 0;
        }

        String password = context.getArgument("password", String.class);
        String confirm = context.getArgument("confirm", String.class);

        player.sendMessage(
                Text.literal("[IQCL] 注册处理中...")
                        .formatted(Formatting.YELLOW),
                false);

        PasswordManager.register(player.getServer(), player, password, confirm, null);
        return 1;
    }

    // ========== changepassword ==========

    /** {@code /iqcl changepassword <旧> <新>}。 */
    public static int executeChangePassword(CommandContext<ServerCommandSource> context) {
        if (!ModConfig.get().passwordLoginEnabled) {
            context.getSource().sendError(Text.literal("[IQCL] 密码登录功能未启用")
                    .formatted(Formatting.RED));
            return 0;
        }
        ServerPlayerEntity player = context.getSource().getPlayer();
        if (player == null) {
            context.getSource().sendError(Text.literal("此命令只能由玩家执行")
                    .formatted(Formatting.RED));
            return 0;
        }

        if (!AuthState.isAuthenticated(player.getUuid())) {
            player.sendMessage(
                    Text.literal("[IQCL] 请先登录后再修改密码")
                            .formatted(Formatting.RED),
                    false);
            return 0;
        }

        String oldPwd = context.getArgument("old", String.class);
        String newPwd = context.getArgument("new", String.class);

        player.sendMessage(
                Text.literal("[IQCL] 修改密码处理中...")
                        .formatted(Formatting.YELLOW),
                false);

        PasswordManager.changePassword(player.getServer(), player, oldPwd, newPwd, null);
        return 1;
    }

    // ========== unregister password ==========

    /** {@code /iqcl unregister password <密码>}。 */
    public static int executeUnregisterPassword(CommandContext<ServerCommandSource> context) {
        if (!ModConfig.get().passwordLoginEnabled) {
            context.getSource().sendError(Text.literal("[IQCL] 密码登录功能未启用")
                    .formatted(Formatting.RED));
            return 0;
        }
        ServerPlayerEntity player = context.getSource().getPlayer();
        if (player == null) {
            context.getSource().sendError(Text.literal("此命令只能由玩家执行")
                    .formatted(Formatting.RED));
            return 0;
        }

        if (!AuthState.isAuthenticated(player.getUuid())) {
            player.sendMessage(
                    Text.literal("[IQCL] 请先登录后再注销账号")
                            .formatted(Formatting.RED),
                    false);
            return 0;
        }

        String password = context.getArgument("password", String.class);

        player.sendMessage(
                Text.literal("[IQCL] 注销处理中...")
                        .formatted(Formatting.YELLOW),
                false);

        PasswordManager.unregister(player.getServer(), player, password, null);
        return 1;
    }

    // ========== account ==========

    /** {@code /iqcl account} — 显示自身账号状态。 */
    public static int executeAccount(CommandContext<ServerCommandSource> context) {
        ServerPlayerEntity player = context.getSource().getPlayer();
        if (player == null) {
            context.getSource().sendError(Text.literal("此命令只能由玩家执行")
                    .formatted(Formatting.RED));
            return 0;
        }

        boolean authed = AuthState.isAuthenticated(player.getUuid());
        boolean linked = AuthState.isLinked(player.getUuid());
        boolean registered = PasswordManager.isRegisteredSync(player.getUuid());

        player.sendMessage(
                Text.literal("====================================")
                        .formatted(Formatting.GOLD), false);
        player.sendMessage(
                Text.literal("[IQCL] 账号状态")
                        .formatted(Formatting.GOLD, Formatting.BOLD), false);
        player.sendMessage(
                Text.literal("  当前认证: ")
                        .formatted(Formatting.WHITE)
                        .append(authed
                                ? Text.literal("已登录").formatted(Formatting.GREEN)
                                : Text.literal("未登录").formatted(Formatting.RED)),
                false);
        player.sendMessage(
                Text.literal("  密码账号: ")
                        .formatted(Formatting.WHITE)
                        .append(registered
                                ? Text.literal("已注册").formatted(Formatting.GREEN)
                                : Text.literal("未注册").formatted(Formatting.YELLOW)),
                false);
        player.sendMessage(
                Text.literal("  IQCL 关联: ")
                        .formatted(Formatting.WHITE)
                        .append(linked
                                ? Text.literal("已关联").formatted(Formatting.GREEN)
                                : Text.literal("未关联").formatted(Formatting.YELLOW)),
                false);
        player.sendMessage(
                Text.literal("====================================")
                        .formatted(Formatting.GOLD), false);
        return 1;
    }

    // ========== cancel ==========

    /** {@code /iqcl cancel} — 取消 PIN 待关联状态。 */
    public static int executeCancel(CommandContext<ServerCommandSource> context) {
        ServerPlayerEntity player = context.getSource().getPlayer();
        if (player == null) {
            context.getSource().sendError(Text.literal("此命令只能由玩家执行")
                    .formatted(Formatting.RED));
            return 0;
        }

        if (!AuthState.hasPendingLink(player.getUuid())) {
            player.sendMessage(
                    Text.literal("[IQCL] 你当前没有待取消的关联状态")
                            .formatted(Formatting.YELLOW),
                    false);
            return 0;
        }

        AuthState.cancelPendingLink(player.getUuid());
        player.sendMessage(
                Text.literal("[IQCL] 已取消 IQCL 账号关联确认")
                        .formatted(Formatting.GREEN),
                false);
        return 1;
    }

    // ========== admin ==========

    /** {@code /iqcl admin unregister <玩家>} — 强制删除玩家密码账号。 */
    public static int executeAdminUnregister(CommandContext<ServerCommandSource> context)
            throws CommandSyntaxException {
        ServerCommandSource source = context.getSource();
        ServerPlayerEntity target = EntityArgumentType.getPlayer(context, "player");

        if (!PasswordManager.isAvailable()) {
            source.sendError(Text.literal("[IQCL] 密码登录服务不可用")
                    .formatted(Formatting.RED));
            return 0;
        }

        PasswordManager.adminUnregister(source.getServer(), target, result -> {
            if (result.success) {
                source.sendFeedback(() ->
                        Text.literal("[IQCL] 已删除玩家 " + target.getEntityName() + " 的密码账号")
                                .formatted(Formatting.GREEN), false);
            } else {
                source.sendError(Text.literal("[IQCL] " + target.getEntityName() + ": " + result.message)
                        .formatted(Formatting.RED));
            }
        });
        return 1;
    }

    /** {@code /iqcl admin resetpassword <玩家>} — 重置玩家密码为临时随机串。 */
    public static int executeAdminResetPassword(CommandContext<ServerCommandSource> context)
            throws CommandSyntaxException {
        ServerCommandSource source = context.getSource();
        ServerPlayerEntity target = EntityArgumentType.getPlayer(context, "player");

        if (!PasswordManager.isAvailable()) {
            source.sendError(Text.literal("[IQCL] 密码登录服务不可用")
                    .formatted(Formatting.RED));
            return 0;
        }

        PasswordManager.adminResetPassword(source.getServer(), target, result -> {
            if (result.success && result.tempPassword != null) {
                source.sendFeedback(() ->
                        Text.literal("[IQCL] 玩家 " + target.getEntityName() + " 的密码已重置为: "
                                + result.tempPassword)
                                .formatted(Formatting.GREEN), false);
                source.sendFeedback(() ->
                        Text.literal("[IQCL] 请通知玩家尽快使用 /iqcl changepassword 修改密码")
                                .formatted(Formatting.YELLOW), false);
            } else {
                source.sendError(Text.literal("[IQCL] " + result.message)
                        .formatted(Formatting.RED));
            }
        });
        return 1;
    }

    /** {@code /iqcl admin reloadstorage} — 热重载存储后端（阶段3）。 */
    public static int executeAdminReloadStorage(CommandContext<ServerCommandSource> context) {
        ServerCommandSource source = context.getSource();
        try {
            PasswordManager.reload();
            source.sendFeedback(() ->
                    Text.literal("[IQCL] 存储后端已重载")
                            .formatted(Formatting.GREEN), false);
            return 1;
        } catch (Exception e) {
            source.sendError(Text.literal("[IQCL] 存储重载失败: " + e.getMessage())
                    .formatted(Formatting.RED));
            return 0;
        }
    }
}
