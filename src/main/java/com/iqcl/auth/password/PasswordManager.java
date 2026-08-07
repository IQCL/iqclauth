/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.password;

import com.iqcl.auth.IqclAuth;
import com.iqcl.auth.config.ModConfig;
import com.iqcl.auth.network.NetworkConstants;
import com.iqcl.auth.password.crypto.PasswordHasher;
import com.iqcl.auth.password.crypto.TotpManager;
import com.iqcl.auth.password.storage.AccountStorage;
import com.iqcl.auth.password.storage.AccountStorageFactory;
import com.iqcl.auth.password.storage.StorageExecutor;
import com.iqcl.auth.server.ApiGateway;
import com.iqcl.auth.server.AuthState;
import com.iqcl.auth.server.PlayerSessionManager;
import net.fabricmc.fabric.api.networking.v1.PacketByteBufs;
import net.fabricmc.fabric.api.networking.v1.ServerPlayNetworking;
import net.minecraft.network.PacketByteBuf;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.network.ServerPlayerEntity;
import net.minecraft.text.Text;
import net.minecraft.util.Formatting;

import java.security.SecureRandom;
import java.util.function.Consumer;

/**
 * 密码登录业务编排核心。
 * <p>
 * 串联存储层、哈希、爆破防护、策略校验、与 IQCL 账号关联流程衔接。
 * 所有业务方法通过 {@link StorageExecutor} 异步执行，回调通过 {@link MinecraftServer#execute}
 * 调度回主线程，确保对 {@link AuthState}/{@link PlayerSessionManager} 的修改线程安全。
 * <p>
 * 安全约定：
 * <ul>
 *   <li>密码以 {@code char[]} 承载，业务结束后由 {@link PasswordHasher#zero} 清零</li>
 *   <li>严禁 {@code LOGGER.info} 或回调消息包含密码明文</li>
 *   <li>错误消息统一"账号或密码错误"，防账号枚举</li>
 * </ul>
 */
public final class PasswordManager {

    private static final SecureRandom TEMP_PASSWORD_RANDOM = new SecureRandom();
    private static final char[] TEMP_PASSWORD_ALPHABET =
            "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789".toCharArray();

    private static volatile AccountStorage storage;

    private PasswordManager() {
    }

    // ========== 生命周期 ==========

    /** 启动时调用：创建存储后端 + 初始化执行器 + 建表。 */
    public static synchronized void init() {
        try {
            ModConfig cfg = ModConfig.get();
            storage = AccountStorageFactory.create(cfg.passwordStorage);
            storage.init();
            StorageExecutor.init();
            IqclAuth.LOGGER.info("[IQCL Auth] 密码登录存储已就绪 (backend={})", cfg.passwordStorage.backend);
        } catch (Exception e) {
            IqclAuth.LOGGER.error("[IQCL Auth] 密码登录存储初始化失败，密码登录功能不可用", e);
            storage = null;
            StorageExecutor.shutdown();
        }
    }

    /** 停服时调用：关闭存储 + 执行器。 */
    public static synchronized void shutdown() {
        StorageExecutor.shutdown();
        if (storage != null) {
            try {
                storage.close();
            } catch (Exception e) {
                IqclAuth.LOGGER.error("[IQCL Auth] 关闭存储后端失败", e);
            }
            storage = null;
        }
    }

    /** 阶段3：热重载存储后端。 */
    public static synchronized void reload() throws Exception {
        StorageExecutor.enterReloading();
        try {
            shutdown();
            // 重新加载配置
            ModConfig.load();
            init();
        } finally {
            StorageExecutor.exitReloading();
        }
    }

    /** 当前存储是否可用。 */
    public static boolean isAvailable() {
        return storage != null && StorageExecutor.isAvailable();
    }

    /** 查询玩家是否已注册密码账号（同步，仅用于 status 展示，会阻塞主线程，建议少用）。 */
    public static boolean isRegisteredSync(java.util.UUID uuid) {
        if (storage == null) return false;
        try {
            return storage.exists(uuid);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 异步查询玩家是否已注册密码账号。
     * 结果通过 callback 在主线程回调。
     */
    public static void checkHasPasswordAsync(MinecraftServer server, java.util.UUID uuid,
                                              Consumer<Boolean> callback) {
        if (storage == null) {
            server.execute(() -> callback.accept(false));
            return;
        }
        StorageExecutor.submit(server, () -> {
            try {
                return storage.exists(uuid);
            } catch (Exception e) {
                return false;
            }
        }, callback, ex -> server.execute(() -> callback.accept(false)));
    }

    /**
     * 确认 TOTP 验证完成登录（密码已通过后的第二步）。
     */
    public static void confirmTotpLogin(MinecraftServer server, ServerPlayerEntity player,
                                        String code, Consumer<Result> callback) {
        if (!checkAvailable(server, player, callback)) return;
        java.util.UUID uuid = player.getUuid();
        String playerName = player.getEntityName();

        if (!AuthState.hasPendingTotp(uuid)) {
            callback.accept(Result.fail("你当前没有待完成的 TOTP 验证"));
            return;
        }

        StorageExecutor.submit(server, () -> {
            try {
                AccountRecord record = storage.findByUuid(uuid);
                if (record == null) {
                    return Result.fail("账号不存在");
                }
                if (!record.totpEnabled) {
                    return Result.fail("你的账号未启用 TOTP");
                }
                boolean valid = TotpManager.verify(record.totpSecret, code, record.totpLastCode);
                if (!valid) {
                    LoginAttemptLimiter.recordFailure(uuid);
                    int remaining = LoginAttemptLimiter.remainingAttempts(uuid);
                    boolean locked = LoginAttemptLimiter.isLocked(uuid);
                    if (locked) {
                        long remainMs = LoginAttemptLimiter.remainingLockMs(uuid);
                        return Result.failLocked(remainMs / 1000L);
                    }
                    return Result.failAccount(remaining);
                }
                // TOTP 通过
                LoginAttemptLimiter.reset(uuid);
                // 更新 lastCode 防重放
                storage.updateTotpLastCode(uuid, code);
                IqclAuth.LOGGER.info("[IQCL Auth] 玩家 {} TOTP 验证通过", playerName);
                return Result.okForLogin();
            } catch (Exception e) {
                IqclAuth.LOGGER.error("[IQCL Auth] 玩家 {} TOTP 验证异常", playerName, e);
                return Result.fail("验证服务暂时不可用，请稍后再试");
            }
        }, result -> {
            if (result.success && result.kind == Result.Kind.LOGIN_OK) {
                AuthState.clearPendingTotp(uuid);
                completePasswordLogin(server, player);
            } else {
                sendResult(player, false, result.message);
            }
            if (callback != null) callback.accept(result);
        }, ex -> {
            sendResult(player, false, "验证服务暂时不可用，请稍后再试");
            if (callback != null) callback.accept(Result.fail("验证服务暂时不可用，请稍后再试"));
        });
    }

    // ========== 业务入口 ==========

    /**
     * 密码登录。
     */
    public static void login(MinecraftServer server, ServerPlayerEntity player,
                             String password, Consumer<Result> callback) {
        if (!checkAvailable(server, player, callback)) return;

        // 前置状态检查（主线程同步）
        if (AuthState.isAuthenticated(player.getUuid())) {
            callback.accept(Result.fail("你已登录，无需重复操作"));
            return;
        }
        // 会话锁定检查（异地登录后短时间内拒绝登录）
        if (PlayerSessionManager.isSessionLocked(player.getUuid())) {
            long remain = PlayerSessionManager.getLockRemainingSeconds(player.getUuid());
            callback.accept(Result.fail("账号因异地登录已被临时锁定，请 " + remain + " 秒后再试"));
            return;
        }
        if (LoginAttemptLimiter.isLocked(player.getUuid())) {
            long remain = LoginAttemptLimiter.remainingLockMs(player.getUuid()) / 1000L;
            callback.accept(Result.fail("尝试次数过多，请 " + remain + " 秒后再试"));
            return;
        }

        char[] pwd = password.toCharArray();
        java.util.UUID uuid = player.getUuid();
        String playerName = player.getEntityName();

        StorageExecutor.submit(server, () -> {
            try {
                AccountRecord record = storage.findByUuid(uuid);
                if (record == null) {
                    // 账号不存在 — 仍记录失败（防账号枚举，对外消息统一）
                    LoginAttemptLimiter.recordFailure(uuid);
                    int remaining = LoginAttemptLimiter.remainingAttempts(uuid);
                    return Result.failAccount(remaining);
                }
                boolean ok = PasswordHasher.verify(pwd, record.salt, record.hash, record.iterations);
                PasswordHasher.zero(pwd);
                if (!ok) {
                    LoginAttemptLimiter.recordFailure(uuid);
                    int remaining = LoginAttemptLimiter.remainingAttempts(uuid);
                    boolean locked = LoginAttemptLimiter.isLocked(uuid);
                    if (locked) {
                        long remainMs = LoginAttemptLimiter.remainingLockMs(uuid);
                        return Result.failLocked(remainMs / 1000L);
                    }
                    return Result.failAccount(remaining);
                }
                // 密码成功 — 检查 TOTP
                LoginAttemptLimiter.reset(uuid);
                IqclAuth.LOGGER.info("[IQCL Auth] 玩家 {} 密码验证通过", playerName);

                if (record.totpEnabled && record.totpSecret != null) {
                    // 需要 TOTP 双因素认证
                    return Result.okNeedTotp();
                }
                // 无需 TOTP — 直接完成
                return Result.okForLogin();
            } catch (Exception e) {
                IqclAuth.LOGGER.error("[IQCL Auth] 玩家 {} 密码登录存储异常", playerName, e);
                return Result.fail("验证服务暂时不可用，请稍后再试");
            } finally {
                PasswordHasher.zero(pwd);
            }
        }, result -> {
            // 主线程
            if (result.success && result.kind == Result.Kind.LOGIN_OK) {
                completePasswordLogin(server, player);
            } else if (result.success && result.kind == Result.Kind.NEED_TOTP) {
                // 密码通过但需要 TOTP
                AuthState.setPendingTotp(uuid, "password");
                sendResult(player, false, "密码验证成功，请输入 TOTP 验证码: /iqcl login confirmtotp <6位验证码>");
            } else {
                sendResult(player, false, result.message);
            }
            if (callback != null) callback.accept(result);
        }, ex -> {
            sendResult(player, false, "验证服务暂时不可用，请稍后再试");
            if (callback != null) callback.accept(Result.fail("验证服务暂时不可用，请稍后再试"));
        });
    }

    /**
     * 注册密码账号。
     */
    public static void register(MinecraftServer server, ServerPlayerEntity player,
                                String password, String confirm, Consumer<Result> callback) {
        if (!checkAvailable(server, player, callback)) return;

        // 策略校验（主线程同步）
        PasswordPolicy.ValidationResult vr = PasswordPolicy.validate(password);
        if (!vr.isValid()) {
            callback.accept(Result.failKey(vr.messageKey));
            return;
        }
        if (!password.equals(confirm)) {
            callback.accept(Result.failKey("iqclauth.password.error.confirm_mismatch"));
            return;
        }

        ModConfig cfg = ModConfig.get();
        int iterations = cfg.passwordHash.iterations;
        int saltBytes = cfg.passwordHash.saltBytes;
        char[] pwd = password.toCharArray();
        java.util.UUID uuid = player.getUuid();
        String playerName = player.getEntityName();
        long now = System.currentTimeMillis();

        StorageExecutor.submit(server, () -> {
            try {
                if (storage.exists(uuid)) {
                    return Result.failKey("iqclauth.password.error.already_registered");
                }
                PasswordHasher.HashResult hr = PasswordHasher.hash(pwd, iterations, saltBytes);
                AccountRecord record = new AccountRecord(
                        uuid, playerName, hr.salt, hr.hash, hr.iterations, now, now);
                storage.insert(record);
                IqclAuth.LOGGER.info("[IQCL Auth] 玩家 {} 注册密码账号成功", playerName);
                return Result.okKey("iqclauth.password.register.success");
            } catch (AccountStorage.StorageException e) {
                if ("账号已存在".equals(e.getMessage())) {
                    return Result.failKey("iqclauth.password.error.already_registered");
                }
                return Result.fail("注册失败：" + e.getMessage());
            } catch (Exception e) {
                IqclAuth.LOGGER.error("[IQCL Auth] 玩家 {} 注册存储异常", playerName, e);
                return Result.fail("注册失败，请稍后再试");
            } finally {
                PasswordHasher.zero(pwd);
            }
        }, result -> {
            // 注册成功消息根据登录状态调整
            if (result.success) {
                String msg = AuthState.isAuthenticated(player.getUuid())
                        ? "密码设置成功，可使用 /iqcl changepassword <旧密码> <新密码> 修改"
                        : "密码账号注册成功，请使用 /iqcl login password <密码> 登录";
                sendResult(player, true, msg);
            } else {
                sendResult(player, false, result.message);
            }
            // 注册成功后建议关联 IQCL 账号
            if (result.success && cfg.promptIqclLinkAfterPasswordLogin) {
                player.sendMessage(
                        Text.literal("[IQCL] 建议执行 /iqcl link 通过 PIN 登录关联 IQCL 账号，便于跨服统一身份管理")
                                .formatted(Formatting.AQUA),
                        false);
            }
            if (callback != null) callback.accept(result);
        }, ex -> {
            sendResult(player, false, "注册失败，请稍后再试");
            if (callback != null) callback.accept(Result.fail("注册失败，请稍后再试"));
        });
    }

    /**
     * 修改密码。
     */
    public static void changePassword(MinecraftServer server, ServerPlayerEntity player,
                                      String oldPassword, String newPassword, Consumer<Result> callback) {
        if (!checkAvailable(server, player, callback)) return;

        // 必须已认证才能改密
        if (!AuthState.isAuthenticated(player.getUuid())) {
            callback.accept(Result.failKey("iqclauth.password.error.not_authed"));
            return;
        }

        PasswordPolicy.ValidationResult vr = PasswordPolicy.validate(newPassword);
        if (!vr.isValid()) {
            callback.accept(Result.failKey(vr.messageKey));
            return;
        }
        if (oldPassword.equals(newPassword)) {
            callback.accept(Result.failKey("iqclauth.password.error.same_password"));
            return;
        }

        ModConfig cfg = ModConfig.get();
        int iterations = cfg.passwordHash.iterations;
        int saltBytes = cfg.passwordHash.saltBytes;
        char[] oldPwd = oldPassword.toCharArray();
        char[] newPwd = newPassword.toCharArray();
        java.util.UUID uuid = player.getUuid();
        String playerName = player.getEntityName();
        long now = System.currentTimeMillis();

        StorageExecutor.submit(server, () -> {
            try {
                AccountRecord record = storage.findByUuid(uuid);
                if (record == null) {
                    return Result.failKey("iqclauth.password.error.not_registered");
                }
                boolean ok = PasswordHasher.verify(oldPwd, record.salt, record.hash, record.iterations);
                if (!ok) {
                    return Result.failKey("iqclauth.password.error.old_password_wrong");
                }
                PasswordHasher.HashResult hr = PasswordHasher.hash(newPwd, iterations, saltBytes);
                storage.updatePassword(uuid, hr.salt, hr.hash, hr.iterations, now);
                IqclAuth.LOGGER.info("[IQCL Auth] 玩家 {} 修改密码成功", playerName);
                return Result.okKey("iqclauth.password.change_password.success");
            } catch (Exception e) {
                IqclAuth.LOGGER.error("[IQCL Auth] 玩家 {} 改密存储异常", playerName, e);
                return Result.fail("改密失败，请稍后再试");
            } finally {
                PasswordHasher.zero(oldPwd);
                PasswordHasher.zero(newPwd);
            }
        }, result -> {
            sendResult(player, result.success, result.message);
            if (callback != null) callback.accept(result);
        }, ex -> {
            sendResult(player, false, "改密失败，请稍后再试");
            if (callback != null) callback.accept(Result.fail("改密失败，请稍后再试"));
        });
    }

    /**
     * 注销密码账号（需确认密码）。
     */
    public static void unregister(MinecraftServer server, ServerPlayerEntity player,
                                  String password, Consumer<Result> callback) {
        if (!checkAvailable(server, player, callback)) return;

        if (!AuthState.isAuthenticated(player.getUuid())) {
            callback.accept(Result.failKey("iqclauth.password.error.not_authed"));
            return;
        }

        char[] pwd = password.toCharArray();
        java.util.UUID uuid = player.getUuid();
        String playerName = player.getEntityName();

        StorageExecutor.submit(server, () -> {
            try {
                AccountRecord record = storage.findByUuid(uuid);
                if (record == null) {
                    return Result.failKey("iqclauth.password.error.not_registered");
                }
                boolean ok = PasswordHasher.verify(pwd, record.salt, record.hash, record.iterations);
                if (!ok) {
                    return Result.failKey("iqclauth.password.error.password_wrong");
                }
                storage.delete(uuid);
                IqclAuth.LOGGER.info("[IQCL Auth] 玩家 {} 注销密码账号", playerName);
                return Result.okKey("iqclauth.password.unregister.success");
            } catch (Exception e) {
                IqclAuth.LOGGER.error("[IQCL Auth] 玩家 {} 注销存储异常", playerName, e);
                return Result.fail("注销失败，请稍后再试");
            } finally {
                PasswordHasher.zero(pwd);
            }
        }, result -> {
            sendResult(player, result.success, result.message);
            if (callback != null) callback.accept(result);
        }, ex -> {
            sendResult(player, false, "注销失败，请稍后再试");
            if (callback != null) callback.accept(Result.fail("注销失败，请稍后再试"));
        });
    }

    /**
     * 管理员强制删除玩家密码账号。
     */
    public static void adminUnregister(MinecraftServer server, ServerPlayerEntity target,
                                       Consumer<Result> callback) {
        if (!checkAvailable(server, null, callback)) return;
        java.util.UUID uuid = target.getUuid();
        String targetName = target.getEntityName();

        StorageExecutor.submit(server, () -> {
            try {
                boolean existed = storage.exists(uuid);
                if (!existed) {
                    return Result.failKey("iqclauth.password.error.not_registered");
                }
                storage.delete(uuid);
                LoginAttemptLimiter.reset(uuid);
                IqclAuth.LOGGER.info("[IQCL Auth] 管理员删除玩家 {} 的密码账号", targetName);
                return Result.okKey("iqclauth.password.admin.unregistered");
            } catch (Exception e) {
                IqclAuth.LOGGER.error("[IQCL Auth] 管理员删除玩家 {} 密码账号存储异常", targetName, e);
                return Result.fail("删除失败，请稍后再试");
            }
        }, result -> {
            if (callback != null) callback.accept(result);
        }, ex -> {
            if (callback != null) callback.accept(Result.fail("删除失败，请稍后再试"));
        });
    }

    /**
     * 管理员重置玩家密码为临时随机串。
     * 返回的 {@link Result#tempPassword} 仅传递给管理员，不发送给玩家。
     */
    public static void adminResetPassword(MinecraftServer server, ServerPlayerEntity target,
                                          Consumer<Result> callback) {
        if (!checkAvailable(server, null, callback)) return;

        ModConfig cfg = ModConfig.get();
        int iterations = cfg.passwordHash.iterations;
        int saltBytes = cfg.passwordHash.saltBytes;
        java.util.UUID uuid = target.getUuid();
        String targetName = target.getEntityName();
        long now = System.currentTimeMillis();
        String tempPassword = generateTempPassword(12);
        char[] pwd = tempPassword.toCharArray();

        StorageExecutor.submit(server, () -> {
            try {
                PasswordHasher.HashResult hr = PasswordHasher.hash(pwd, iterations, saltBytes);
                if (storage.exists(uuid)) {
                    storage.updatePassword(uuid, hr.salt, hr.hash, hr.iterations, now);
                } else {
                    AccountRecord record = new AccountRecord(
                            uuid, targetName, hr.salt, hr.hash, hr.iterations, now, now);
                    storage.insert(record);
                }
                LoginAttemptLimiter.reset(uuid);
                IqclAuth.LOGGER.info("[IQCL Auth] 管理员重置玩家 {} 的密码", targetName);
                return Result.okWithTempPassword("密码已重置", tempPassword);
            } catch (Exception e) {
                IqclAuth.LOGGER.error("[IQCL Auth] 管理员重置玩家 {} 密码存储异常", targetName, e);
                return Result.fail("重置失败，请稍后再试");
            } finally {
                PasswordHasher.zero(pwd);
            }
        }, result -> {
            if (callback != null) callback.accept(result);
        }, ex -> {
            if (callback != null) callback.accept(Result.fail("重置失败，请稍后再试"));
        });
    }

    // ========== 登录收尾 ==========

    /**
     * 密码登录成功后的收尾（主线程执行）。
     * <p>
     * 复用与 PIN 登录相同的状态变更链：防多开 → authenticate → 持久会话 → Limbo 恢复 → 远端通知 → 客户端结果。
     * 但发送密码专属成功消息，避免误用 PIN 的 "PIN 验证成功" 文案。
     */
    private static void completePasswordLogin(MinecraftServer server, ServerPlayerEntity player) {
        server.execute(() -> {
            if (player.networkHandler == null || player.isRemoved()) {
                IqclAuth.LOGGER.warn("[IQCL Auth] 密码登录收尾跳过：玩家 {} 已离线", player.getEntityName());
                return;
            }
            String playerName = player.getEntityName();
            java.util.UUID uuid = player.getUuid();

            // 异地登录检测
            if (PlayerSessionManager.isCrossIpLogin(player)) {
                PlayerSessionManager.lockSession(uuid);
                IqclAuth.LOGGER.warn("[IQCL Auth] 玩家 {} 因异地登录被锁定", playerName);
                sendResult(player, false, "检测到异地登录，账号已被临时锁定，请稍后再试");
                player.networkHandler.disconnect(
                        net.minecraft.text.Text.literal("[IQCL] 检测到异地登录，账号已被临时锁定，请稍后再试"));
                return;
            }

            // 标记认证 + 持久会话 + Limbo 恢复
            // （密码登录不设置 displayId，绑定逻辑由 PIN 登录路径完成后端接管）
            AuthState.authenticate(player);
            AuthState.setLoginMethod(uuid, "password");
            PlayerSessionManager.recordAuthenticatedIp(player);
            PlayerSessionManager.bindAuthenticatedIp(player);
            PlayerSessionManager.restoreFromLimbo(player);

            // 通知 game-session login
            ApiGateway.notifyLogin(uuid.toString(), playerName);

            IqclAuth.LOGGER.info("[IQCL Auth] 玩家 {} 已通过密码认证", playerName);

            // 通知客户端
            sendResult(player, true, "密码登录成功，欢迎回来！");

            // 提示关联 IQCL 账号
            if (ModConfig.get().promptIqclLinkAfterPasswordLogin) {
                sendPostLoginGuidancePassword(player, false);
            } else {
                sendPostLoginGuidancePassword(player, true);
            }
        });
    }

    /**
     * 密码登录成功后的引导消息。
     *
     * @param player      玩家
     * @param showIqclTip 是否显示 IQCL 关联提示
     */
    private static void sendPostLoginGuidancePassword(ServerPlayerEntity player,
                                                        boolean showIqclTip) {
        player.sendMessage(
                Text.literal("====================================")
                        .formatted(Formatting.GOLD), false);

        // 引导 PIN 登录
        player.sendMessage(
                Text.literal("[IQCL] 安全建议")
                        .formatted(Formatting.AQUA, Formatting.BOLD), false);
        player.sendMessage(
                Text.literal("  建议同时使用 PIN 登录关联 IQCL 账号")
                        .formatted(Formatting.WHITE), false);
        player.sendMessage(
                Text.literal("  以便跨服统一身份管理")
                        .formatted(Formatting.GRAY), false);

        // TOTP 提示
        player.sendMessage(
                Text.literal("")
                        .formatted(Formatting.RESET), false);
        player.sendMessage(
                Text.literal("  双因素认证(TOTP): /iqcl enablerotp")
                        .formatted(Formatting.GREEN), false);
        player.sendMessage(
                Text.literal("  可为密码登录增加额外安全保护")
                        .formatted(Formatting.GRAY), false);

        // IQCL 关联警告
        if (showIqclTip) {
            player.sendMessage(
                    Text.literal("")
                            .formatted(Formatting.RESET), false);
            player.sendMessage(
                    Text.literal("  ⚠ 只有链接了 IQCL 账号才能重置服务器密码")
                            .formatted(Formatting.RED), false);
            player.sendMessage(
                    Text.literal("  否则忘记密码可能丢失账号管控权")
                            .formatted(Formatting.GRAY), false);
            player.sendMessage(
                    Text.literal("  执行 /iqcl link 通过 PIN 登录关联 IQCL 账号")
                            .formatted(Formatting.YELLOW), false);
        }

        player.sendMessage(
                Text.literal("====================================")
                        .formatted(Formatting.GOLD), false);
    }

    // ========== 内部工具 ==========

    /** 检查存储是否可用，不可用时回调失败。 */
    private static boolean checkAvailable(MinecraftServer server, ServerPlayerEntity player,
                                          Consumer<Result> callback) {
        if (isAvailable()) return true;
        if (callback != null) {
            Result r = Result.failKey("iqclauth.password.error.storage_unavailable");
            if (player != null) sendResult(player, false, r.message);
            callback.accept(r);
        }
        return false;
    }

    /** 发送结果给客户端（复用 S2C_RESULT_ID 通道）。 */
    private static void sendResult(ServerPlayerEntity player, boolean success, String message) {
        if (player.networkHandler == null || player.isRemoved()) return;
        PacketByteBuf buf = PacketByteBufs.create();
        buf.writeBoolean(success);
        buf.writeString(message);
        ServerPlayNetworking.send(player, NetworkConstants.S2C_RESULT_ID, buf);
    }

    /** 生成临时随机密码（避免易混淆字符 0/O/1/l）。 */
    private static String generateTempPassword(int length) {
        char[] buf = new char[length];
        for (int i = 0; i < length; i++) {
            buf[i] = TEMP_PASSWORD_ALPHABET[TEMP_PASSWORD_RANDOM.nextInt(TEMP_PASSWORD_ALPHABET.length)];
        }
        return new String(buf);
    }

    // ========== TOTP 双因素认证 ==========

    /**
     * 启用 TOTP 双因素认证（生成密钥 + 返回 URI 供扫码）。
     */
    public static void enableTotp(MinecraftServer server, ServerPlayerEntity player,
                                   Consumer<TotpEnableResult> callback) {
        if (!checkAvailable(server, player, null)) {
            if (callback != null) callback.accept(TotpEnableResult.fail("密码登录服务暂不可用"));
            return;
        }
        if (!AuthState.isAuthenticated(player.getUuid())) {
            if (callback != null) callback.accept(TotpEnableResult.fail("请先登录后再启用 TOTP"));
            return;
        }
        java.util.UUID uuid = player.getUuid();
        String playerName = player.getEntityName();

        StorageExecutor.submit(server, () -> {
            try {
                AccountRecord record = storage.findByUuid(uuid);
                if (record == null) {
                    return TotpEnableResult.fail("你尚未注册密码账号");
                }
                if (record.totpEnabled) {
                    return TotpEnableResult.fail("你已启用 TOTP，请先 /iqcl disablerotp");
                }
                // 生成新密钥
                String secret = TotpManager.generateSecret();
                String uri = TotpManager.buildOtpAuthUri("IQCL Auth", playerName, secret);
                // 暂存密钥（未启用状态，需确认后才启用）
                storage.updateTotp(uuid, false, secret, null, System.currentTimeMillis());
                IqclAuth.LOGGER.info("[IQCL Auth] 玩家 {} 生成 TOTP 密钥", playerName);
                return TotpEnableResult.ok(secret, uri);
            } catch (Exception e) {
                IqclAuth.LOGGER.error("[IQCL Auth] 玩家 {} 启用 TOTP 异常", playerName, e);
                return TotpEnableResult.fail("启用 TOTP 失败，请稍后再试");
            }
        }, callback, ex -> {
            if (callback != null) callback.accept(TotpEnableResult.fail("启用 TOTP 失败，请稍后再试"));
        });
    }

    /**
     * 确认启用 TOTP（玩家扫码后输入第一个码验证）。
     */
    public static void confirmTotp(MinecraftServer server, ServerPlayerEntity player,
                                    String code, Consumer<Result> callback) {
        if (!checkAvailable(server, player, callback)) return;
        if (!AuthState.isAuthenticated(player.getUuid())) {
            callback.accept(Result.fail("请先登录"));
            return;
        }
        java.util.UUID uuid = player.getUuid();
        String playerName = player.getEntityName();

        StorageExecutor.submit(server, () -> {
            try {
                AccountRecord record = storage.findByUuid(uuid);
                if (record == null) return Result.fail("你尚未注册密码账号");
                if (record.totpEnabled) return Result.fail("你已启用 TOTP");
                if (record.totpSecret == null || record.totpSecret.isEmpty()) {
                    return Result.fail("请先执行 /iqcl enablerotp");
                }
                // 验证码
                boolean valid = TotpManager.verify(record.totpSecret, code, record.totpLastCode);
                if (!valid) {
                    return Result.fail("TOTP 码错误");
                }
                // 正式启用
                storage.updateTotp(uuid, true, record.totpSecret, code, System.currentTimeMillis());
                IqclAuth.LOGGER.info("[IQCL Auth] 玩家 {} 启用 TOTP 成功", playerName);
                return Result.ok("TOTP 双因素认证已启用，请妥善保存密钥");
            } catch (Exception e) {
                IqclAuth.LOGGER.error("[IQCL Auth] 玩家 {} 确认 TOTP 异常", playerName, e);
                return Result.fail("操作失败，请稍后再试");
            }
        }, result -> {
            sendResult(player, result.success, result.message);
            if (callback != null) callback.accept(result);
        }, ex -> {
            sendResult(player, false, "操作失败，请稍后再试");
            if (callback != null) callback.accept(Result.fail("操作失败，请稍后再试"));
        });
    }

    /**
     * 禁用 TOTP（需验证密码）。
     */
    public static void disableTotp(MinecraftServer server, ServerPlayerEntity player,
                                    String password, Consumer<Result> callback) {
        if (!checkAvailable(server, player, callback)) return;
        if (!AuthState.isAuthenticated(player.getUuid())) {
            callback.accept(Result.fail("请先登录"));
            return;
        }
        char[] pwd = password.toCharArray();
        java.util.UUID uuid = player.getUuid();
        String playerName = player.getEntityName();

        StorageExecutor.submit(server, () -> {
            try {
                AccountRecord record = storage.findByUuid(uuid);
                if (record == null) return Result.fail("你尚未注册密码账号");
                if (!record.totpEnabled) return Result.fail("你尚未启用 TOTP");
                // 验证密码
                boolean ok = PasswordHasher.verify(pwd, record.salt, record.hash, record.iterations);
                if (!ok) return Result.fail("密码错误");
                // 禁用 TOTP
                storage.updateTotp(uuid, false, null, null, System.currentTimeMillis());
                IqclAuth.LOGGER.info("[IQCL Auth] 玩家 {} 禁用 TOTP", playerName);
                return Result.ok("TOTP 双因素认证已禁用");
            } catch (Exception e) {
                IqclAuth.LOGGER.error("[IQCL Auth] 玩家 {} 禁用 TOTP 异常", playerName, e);
                return Result.fail("操作失败，请稍后再试");
            } finally {
                PasswordHasher.zero(pwd);
            }
        }, result -> {
            sendResult(player, result.success, result.message);
            if (callback != null) callback.accept(result);
        }, ex -> {
            sendResult(player, false, "操作失败，请稍后再试");
            if (callback != null) callback.accept(Result.fail("操作失败，请稍后再试"));
        });
    }

    /**
     * 验证 TOTP 码（在密码登录成功后调用，若账号启用了 TOTP）。
     *
     * @return true = 验证通过（并更新 lastCode）
     */
    public static boolean verifyTotpForLogin(MinecraftServer server, ServerPlayerEntity player,
                                             AccountRecord record, String code) {
        if (record == null || !record.totpEnabled) return true; // 未启用 TOTP 直接通过
        boolean valid = TotpManager.verify(record.totpSecret, code, record.totpLastCode);
        if (valid) {
            // 更新 lastCode 防重放
            StorageExecutor.submit(server, () -> {
                try {
                    storage.updateTotpLastCode(record.uuid, code);
                } catch (Exception ignored) {
                }
                return null;
            }, result -> {}, ex -> {});
        }
        return valid;
    }

    /** 获取账号的 TOTP 状态（用于 /iqcl status 显示）。 */
    public static boolean isTotpEnabledSync(java.util.UUID uuid) {
        if (storage == null) return false;
        try {
            AccountRecord r = storage.findByUuid(uuid);
            return r != null && r.totpEnabled;
        } catch (Exception e) {
            return false;
        }
    }

    // ========== TOTP 结果载体 ==========

    public static final class TotpEnableResult {
        public final boolean success;
        public final String message;
        /** Base32 密钥（成功时返回）。 */
        public final String secret;
        /** otpauth:// URI（成功时返回，供扫码）。 */
        public final String otpUri;

        private TotpEnableResult(boolean success, String message, String secret, String otpUri) {
            this.success = success;
            this.message = message;
            this.secret = secret;
            this.otpUri = otpUri;
        }

        static TotpEnableResult ok(String secret, String otpUri) {
            return new TotpEnableResult(true, "TOTP 密钥已生成", secret, otpUri);
        }

        static TotpEnableResult fail(String msg) {
            return new TotpEnableResult(false, msg, null, null);
        }
    }

    // ========== 结果载体 ==========

    /**
     * 业务结果载体。
     * {@code message} 已本地化可直接发玩家；{@code messageKey} 用于客户端翻译（阶段2）。
     */
    public static final class Result {
        public final boolean success;
        public final String message;
        public final String messageKey;
        public final String tempPassword;
        public final Kind kind;

        public enum Kind {
            GENERIC,
            LOGIN_OK,
            FAIL_ACCOUNT,
            FAIL_LOCKED,
            NEED_TOTP
        }

        private Result(boolean success, String message, String messageKey,
                       String tempPassword, Kind kind) {
            this.success = success;
            this.message = message;
            this.messageKey = messageKey;
            this.tempPassword = tempPassword;
            this.kind = kind;
        }

        static Result okForLogin() {
            return new Result(true, "密码登录成功", null, null, Kind.LOGIN_OK);
        }

        static Result okNeedTotp() {
            return new Result(true, "需要 TOTP 双因素认证", null, null, Kind.NEED_TOTP);
        }

        static Result ok(String message) {
            return new Result(true, message, null, null, Kind.GENERIC);
        }

        static Result okKey(String messageKey) {
            return new Result(true, localize(messageKey), messageKey, null, Kind.GENERIC);
        }

        static Result okWithTempPassword(String message, String tempPassword) {
            return new Result(true, message, null, tempPassword, Kind.GENERIC);
        }

        static Result fail(String message) {
            return new Result(false, message, null, null, Kind.GENERIC);
        }

        static Result failKey(String messageKey) {
            return new Result(false, localize(messageKey), messageKey, null, Kind.GENERIC);
        }

        static Result failAccount(int remainingAttempts) {
            String msg = remainingAttempts > 0
                    ? "账号或密码错误，剩余尝试次数 " + remainingAttempts
                    : "账号或密码错误";
            return new Result(false, msg, null, null, Kind.FAIL_ACCOUNT);
        }

        static Result failLocked(long remainSec) {
            return new Result(false, "尝试次数过多，请 " + remainSec + " 秒后再试",
                    null, null, Kind.FAIL_LOCKED);
        }
    }

    /** 服务端侧的简单本地化（直接返回中文文案）。阶段2 客户端走 lang 文件翻译。 */
    private static String localize(String key) {
        if (key == null) return "";
        switch (key) {
            case "iqclauth.password.error.null":
                return "密码不能为空";
            case "iqclauth.password.error.too_short":
                return "密码长度不足";
            case "iqclauth.password.error.too_long":
                return "密码长度超出限制";
            case "iqclauth.password.error.no_letter":
                return "密码必须包含字母";
            case "iqclauth.password.error.no_digit":
                return "密码必须包含数字";
            case "iqclauth.password.error.no_special":
                return "密码必须包含特殊字符";
            case "iqclauth.password.error.illegal_char":
                return "密码包含非法字符（控制字符）";
            case "iqclauth.password.error.no_space":
                return "密码不允许包含空格";
            case "iqclauth.password.error.weak":
                return "密码强度不足，请避免使用常见弱密码";
            case "iqclauth.password.error.confirm_mismatch":
                return "两次输入的密码不一致";
            case "iqclauth.password.error.already_registered":
                return "你已经注册过密码账号，请直接登录或使用 /iqcl changepassword 修改";
            case "iqclauth.password.error.not_registered":
                return "你尚未注册密码账号";
            case "iqclauth.password.error.not_authed":
                return "请先登录后再执行此操作";
            case "iqclauth.password.error.same_password":
                return "新密码不能与旧密码相同";
            case "iqclauth.password.error.old_password_wrong":
                return "旧密码错误";
            case "iqclauth.password.error.password_wrong":
                return "密码错误";
            case "iqclauth.password.error.storage_unavailable":
                return "密码登录服务暂不可用，请稍后再试或联系管理员";
            case "iqclauth.password.register.success":
                return "密码账号注册成功，请使用 /iqcl login password <密码> 登录";
            case "iqclauth.password.change_password.success":
                return "密码修改成功";
            case "iqclauth.password.unregister.success":
                return "密码账号已注销";
            case "iqclauth.password.admin.unregistered":
                return "已删除该玩家的密码账号";
            default:
                return key;
        }
    }
}
