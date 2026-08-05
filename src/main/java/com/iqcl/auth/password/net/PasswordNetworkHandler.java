/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.password.net;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.iqcl.auth.IqclAuth;
import com.iqcl.auth.config.ModConfig;
import com.iqcl.auth.network.NetworkConstants;
import com.iqcl.auth.password.PasswordCommandHandler;
import com.iqcl.auth.password.PasswordManager;
import com.iqcl.auth.password.crypto.EcdhEncryptor;
import com.iqcl.auth.password.crypto.ServerKeyStore;
import com.iqcl.auth.password.storage.StorageExecutor;
import net.fabricmc.fabric.api.networking.v1.ServerPlayNetworking;
import net.minecraft.network.PacketByteBuf;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.network.ServerPlayerEntity;
import net.minecraft.text.Text;
import net.minecraft.util.Formatting;

import java.nio.charset.StandardCharsets;

/**
 * 服务端密码操作密文包接收器。
 * <p>
 * 监听 {@code C2S_PASSWORD_ID}，解密客户端密文包，按 {@code op} 分派到：
 * <ul>
 *   <li>{@link PasswordManager#login} — 密码登录</li>
 *   <li>{@link PasswordManager#register} — 注册</li>
 *   <li>{@link PasswordManager#changePassword} — 修改密码</li>
 *   <li>{@link PasswordManager#unregister} — 注销</li>
 * </ul>
 * 所有 DB 操作通过 {@link StorageExecutor} 异步执行，结果通过 {@link net.minecraft.server.MinecraftServer#execute} 回主线程。
 * <p>
 * 降级路径：若客户端未安装 mod，明文命令会作为服务端命令到达
 * {@link PasswordCommandHandler} 的 executes 方法，不经过本接收器。
 */
public final class PasswordNetworkHandler {

    private PasswordNetworkHandler() {
    }

    /** 注册接收器。应在 {@link IqclAuth#onInitialize} 中调用。 */
    public static void register() {
        ServerPlayNetworking.registerGlobalReceiver(NetworkConstants.C2S_PASSWORD_ID,
                (server, player, handler, buf, responseSender) -> {
                    String packetJson = buf.readString();
                    if (packetJson == null) return;
                    handle(server, player, packetJson);
                });
        IqclAuth.LOGGER.info("[IQCL Auth] 已注册 C2S_PASSWORD_ID 接收器");
    }

    private static void handle(MinecraftServer server, ServerPlayerEntity player, String packetJson) {
        ModConfig config = ModConfig.get();
        if (!config.passwordLoginEnabled) {
            sendResult(player, false, "密码登录功能未启用");
            return;
        }
        if (!ServerKeyStore.isAvailable()) {
            sendResult(player, false, "服务端密钥未初始化，无法处理加密包");
            return;
        }
        if (!PasswordManager.isAvailable()) {
            sendResult(player, false, "密码登录服务暂不可用");
            return;
        }

        // 解密 → 分派
        StorageExecutor.submit(server, () -> decryptPayload(packetJson), decrypted -> {
            if (decrypted == null) {
                sendResult(player, false, "解密失败，请重连服务器");
                return;
            }
            dispatch(server, player, decrypted);
        }, ex -> {
            IqclAuth.LOGGER.error("[IQCL Auth] 密码包解密异常", ex);
            sendResult(player, false, "解密失败，请重连服务器");
        });
    }

    /** 解密客户端密文包（IO 线程内执行）。 */
    private static DecryptedRequest decryptPayload(String packetJson) throws Exception {
        JsonObject outer = JsonParser.parseString(packetJson).getAsJsonObject();
        int version = outer.has("v") ? outer.get("v").getAsInt() : 1;
        if (version != 1) {
            throw new IllegalArgumentException("不支持的数据包版本: " + version);
        }
        String op = outer.get("op").getAsString();
        String clientPub = outer.get("clientPub").getAsString();
        String iv = outer.get("iv").getAsString();
        String ct = outer.get("ct").getAsString();
        byte[] plain = EcdhEncryptor.decrypt(clientPub, iv, ct);
        String plaintextJson = new String(plain, StandardCharsets.UTF_8);
        JsonObject inner = JsonParser.parseString(plaintextJson).getAsJsonObject();
        return new DecryptedRequest(op, inner);
    }

    /** 分派到具体业务方法。 */
    private static void dispatch(MinecraftServer server, ServerPlayerEntity player,
                                 DecryptedRequest req) {
        JsonObject inner = req.inner;
        String password = inner.has("password") ? inner.get("password").getAsString() : null;
        String confirm = inner.has("confirm") ? inner.get("confirm").getAsString() : null;

        switch (req.op) {
            case "login":
                PasswordManager.login(server, player, password, null);
                break;
            case "register":
                PasswordManager.register(server, player, password, confirm, null);
                break;
            case "changepassword":
                // 内层 JSON 约定：password=旧密码, confirm=新密码
                PasswordManager.changePassword(server, player, password, confirm, null);
                break;
            case "unregister":
                PasswordManager.unregister(server, player, password, null);
                break;
            default:
                sendResult(player, false, "未知操作类型: " + req.op);
                IqclAuth.LOGGER.warn("[IQCL Auth] 未知密码操作类型: {}", req.op);
        }
    }

    /** 发送结果给客户端（复用 S2C_RESULT_ID 通道）。 */
    private static void sendResult(ServerPlayerEntity player, boolean success, String message) {
        if (player == null || player.networkHandler == null || player.isRemoved()) return;
        PacketByteBuf buf = net.fabricmc.fabric.api.networking.v1.PacketByteBufs.create();
        buf.writeBoolean(success);
        buf.writeString(message);
        ServerPlayNetworking.send(player, NetworkConstants.S2C_RESULT_ID, buf);
    }

    /** 解密后的请求载体。 */
    private static final class DecryptedRequest {
        final String op;
        final JsonObject inner;
        DecryptedRequest(String op, JsonObject inner) {
            this.op = op;
            this.inner = inner;
        }
    }
}
