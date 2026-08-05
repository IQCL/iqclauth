/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.server;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.iqcl.auth.IqclAuth;
import com.iqcl.auth.config.ModConfig;
import com.iqcl.auth.crypto.Base64Utils;
import com.iqcl.auth.crypto.CanonicalJson;
import com.iqcl.auth.crypto.Ed25519Verifier;
import com.iqcl.auth.network.NetworkConstants;
import net.fabricmc.fabric.api.networking.v1.PacketByteBufs;
import net.fabricmc.fabric.api.networking.v1.ServerPlayNetworking;
import net.minecraft.network.PacketByteBuf;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.network.ServerPlayerEntity;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 服务端网络处理器。
 * <p>
 * 职责链（严格遵守不可信转发节点约束）：
 * <ol>
 *   <li>接收客户端 C2S 密文数据包（<b>不解密 ciphertext</b>，MC 服务端无 RSA 私钥）；</li>
 *   <li>异步 POST 转发完整密文包至远程验证服务器
 *       （Content-Type: application/json，X-Server-Key: <配置>，body = 原始密文包 JSON）；</li>
 *   <li>接收验证服务器返回的 Ed25519 签名响应；</li>
 *   <li>对 payload 执行规范化 JSON 序列化后验证 Ed25519 签名；</li>
 *   <li>验签失败 → 直接判定登录失败；验签成功 → 检查 payload.permission，banned 拒绝；</li>
 *   <li>将最终结果通过 S2C 数据包回传客户端。</li>
 * </ol>
 * <p>
 * HTTP 请求在独立线程池执行，避免阻塞服务端主线程；
 * 回传数据包时调度回服务端主线程以保证线程安全。
 */
public final class ServerNetworkHandler {

    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    private static final ExecutorService VERIFY_EXECUTOR = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "IQCL-Verify-Worker");
        t.setDaemon(true);
        t.setUncaughtExceptionHandler((thread, throwable) ->
                IqclAuth.LOGGER.error("[IQCL Auth] 验签工作线程未捕获异常", throwable));
        return t;
    });

    private ServerNetworkHandler() {
    }

    public static void register() {
        try {
            Ed25519Verifier.warmup();
            IqclAuth.LOGGER.info("[IQCL Auth] Ed25519 验签器初始化成功");
        } catch (Throwable t) {
            IqclAuth.LOGGER.error("[IQCL Auth] Ed25519 验签器初始化失败，PIN 验证将无法工作", t);
        }

        ServerPlayNetworking.registerGlobalReceiver(
                NetworkConstants.C2S_VERIFY_ID,
                (server, player, handler, buf, responseSender) -> {
                    String packetJson = buf.readString();
                    String pName = player.getEntityName();
                    IqclAuth.LOGGER.info("[IQCL Auth] 收到玩家 {} 的 PIN 验证请求", pName);
                    VERIFY_EXECUTOR.submit(() -> processVerify(player, server, packetJson));
                });
    }

    private static void processVerify(ServerPlayerEntity player, MinecraftServer server,
                                      String packetJson) {
        String playerName = player.getEntityName();
        try {
            IqclAuth.LOGGER.debug("[IQCL Auth] [{}] processVerify 开始处理", playerName);

            // —— 服务端已认证检查：已登录或待关联玩家拒绝重复验证 ——
            if (AuthState.isAuthenticated(player.getUuid())) {
                IqclAuth.LOGGER.debug("[IQCL Auth] [{}] 已认证，拒绝重复验证", playerName);
                sendResult(server, player, true, "你已经登录成功，无需重复验证");
                return;
            }
            if (AuthState.hasPendingLink(player.getUuid())) {
                IqclAuth.LOGGER.debug("[IQCL Auth] [{}] 待关联，拒绝重复验证", playerName);
                sendResult(server, player, false, "你正在关联确认中，请输入 /iqcl link 完成关联");
                return;
            }

            ModConfig config = ModConfig.get();

            // —— HTTP 请求转发 ——
            IqclAuth.LOGGER.debug("[IQCL Auth] [{}] 准备发送 HTTP 请求至 {}",
                    playerName, ModConfig.VERIFY_API_URL);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(ModConfig.VERIFY_API_URL))
                    .header("Content-Type", "application/json")
                    .header("X-Server-Key", config.serverKey)
                    .POST(HttpRequest.BodyPublishers.ofString(packetJson, StandardCharsets.UTF_8))
                    .timeout(Duration.ofSeconds(15))
                    .build();

            HttpResponse<String> response =
                    HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

            IqclAuth.LOGGER.debug("[IQCL Auth] [{}] HTTP 响应: status={}, bodyLen={}",
                    playerName, response.statusCode(),
                    response.body() != null ? response.body().length() : 0);

            if (response.statusCode() != 200) {
                sendResult(server, player, false, "验证服务器返回异常状态码: " + response.statusCode());
                return;
            }

            JsonElement rootElement;
            try {
                rootElement = JsonParser.parseString(response.body());
            } catch (Exception e) {
                IqclAuth.LOGGER.warn("[IQCL Auth] [{}] 响应解析失败: {}", playerName, e.getMessage());
                sendResult(server, player, false, "验证服务器响应解析失败");
                return;
            }
            if (rootElement == null || !rootElement.isJsonObject()) {
                sendResult(server, player, false, "验证服务器响应格式无效");
                return;
            }
            JsonObject resp = rootElement.getAsJsonObject();

            // —— 按 API 文档严格校验必需字段 ——
            if (!resp.has("success")) {
                sendResult(server, player, false, "验证响应缺少 success 字段");
                return;
            }

            boolean serverSuccess = resp.get("success").getAsBoolean();

            // 失败响应：直接转发错误消息
            if (!serverSuccess) {
                String errMsg = resp.has("message") ? resp.get("message").getAsString() : "PIN 验证失败";
                IqclAuth.LOGGER.info("[IQCL Auth] [{}] 验证失败: {}", playerName, errMsg);
                sendResult(server, player, false, errMsg);
                return;
            }

            // 成功响应：必须包含 payload 和 signature
            if (!resp.has("payload") || !resp.get("payload").isJsonObject()) {
                sendResult(server, player, false, "验证响应缺少 payload 字段");
                return;
            }
            if (!resp.has("signature") || resp.get("signature").getAsString().isEmpty()) {
                sendResult(server, player, false, "验证响应缺少 signature 字段");
                return;
            }

            JsonObject payloadObj = resp.getAsJsonObject("payload");
            String signature = resp.get("signature").getAsString();

            // —— Ed25519 验签（强制，不可跳过）——
            String canonicalPayload = CanonicalJson.stringify(payloadObj);
            byte[] messageBytes = canonicalPayload.getBytes(StandardCharsets.UTF_8);

            byte[] sigBytes;
            try {
                sigBytes = Base64Utils.decode(signature);
            } catch (IllegalArgumentException e) {
                sendResult(server, player, false, "签名格式错误");
                return;
            }

            boolean sigValid;
            try {
                sigValid = Ed25519Verifier.verify(messageBytes, sigBytes);
            } catch (Throwable t) {
                IqclAuth.LOGGER.error("[IQCL Auth] [{}] Ed25519 验签异常", playerName, t);
                sendResult(server, player, false, "验签过程异常");
                return;
            }

            if (!sigValid) {
                IqclAuth.LOGGER.warn("[IQCL Auth] [{}] Ed25519 验签失败", playerName);
                sendResult(server, player, false, "验签失败，拒绝登录");
                return;
            }

            // —— payload.permission 检查 ——
            if (payloadObj.has("permission")) {
                String permission = payloadObj.get("permission").getAsString();
                if ("banned".equalsIgnoreCase(permission)) {
                    sendResult(server, player, false, "账号已被封禁");
                    return;
                }
            }

            // —— payload.mcUUID 回显核对 ——
            if (payloadObj.has("mcUUID") && !payloadObj.get("mcUUID").isJsonNull()) {
                String mcUUID = payloadObj.get("mcUUID").getAsString();
                if (!mcUUID.equals(player.getUuid().toString())) {
                    sendResult(server, player, false, "UUID 不匹配，拒绝登录");
                    return;
                }
            }

            // —— 提取账号信息 ——
            Integer displayId = null;
            String username = null;
            String permission = null;
            if (payloadObj.has("displayId") && !payloadObj.get("displayId").isJsonNull()) {
                displayId = payloadObj.get("displayId").getAsInt();
            }
            if (payloadObj.has("username") && !payloadObj.get("username").isJsonNull()) {
                username = payloadObj.get("username").getAsString();
            }
            if (payloadObj.has("permission")) {
                permission = payloadObj.get("permission").getAsString();
            }

            IqclAuth.LOGGER.info("[IQCL Auth] [{}] PIN 验证通过，displayId={}, username={}",
                    playerName, displayId, username);

            // —— 强制账号关联检查 ——
            if (config.requireLink && (displayId != null || username != null)) {
                // 检查玩家是否已关联
                AuthState.PlayerAuthState existingState = AuthState.getState(player.getUuid());
                boolean alreadyLinked = existingState != null && existingState.linked;

                if (alreadyLinked && existingState.linkedDisplayId != null) {
                    // 已关联：检查是否同一个 displayId
                    if (existingState.linkedDisplayId.equals(displayId)) {
                        // 同一个账号，直接完成登录
                        IqclAuth.LOGGER.info("[IQCL Auth] [{}] 已关联账号匹配，直接登录", playerName);
                        completeLogin(server, player, playerName, displayId, username);
                        return;
                    } else {
                        // 不同账号，拒绝
                        sendResult(server, player, false,
                                "你已关联 IQCL 账号 (ID: " + existingState.linkedDisplayId
                                        + ")，无法使用其他账号登录");
                        return;
                    }
                }

                // 未关联：进入关联确认流程
                String displayLine = (displayId != null ? "ID: " + displayId : "");
                String nameLine = (username != null ? "用户名: " + username : "");
                String msg = "====================================\n"
                        + "[IQCL] 检测到 IQCL 账号信息：\n"
                        + "  " + displayLine + "\n"
                        + "  " + nameLine + "\n"
                        + "\n"
                        + "确定要将此游戏账号与 IQCL 账号关联吗？\n"
                        + "输入 /iqcl link 确认关联\n"
                        + "================================";
                final Integer finalDisplayId = displayId;
                final String finalUsername = username;
                final String finalPermission = permission;
                // 调度到主线程：先记录认证状态（未关联，待 link），再发送提示
                server.execute(() -> {
                    AuthState.authenticateWithAccount(player, finalDisplayId, finalUsername, finalPermission);
                    sendRawMessage(server, player, msg);
                    sendResult(server, player, false, "请输入 /iqcl link 确认关联后完成登录");
                });
                IqclAuth.LOGGER.info("[IQCL Auth] [{}] 等待 /iqcl link 确认关联", playerName);
                return;
            }

            // —— 强制关联关闭或无账号信息，调度到主线程完成登录 ——
            completeLogin(server, player, playerName, displayId, username);

        } catch (java.net.SocketTimeoutException ste) {
            IqclAuth.LOGGER.error("[IQCL Auth] [{}] 验证请求超时", playerName);
            sendResult(server, player, false, "验证服务器请求超时，请稍后重试");
        } catch (java.net.ConnectException ce) {
            IqclAuth.LOGGER.error("[IQCL Auth] [{}] 无法连接到验证服务器", playerName);
            sendResult(server, player, false, "无法连接到验证服务器");
        } catch (Throwable t) {
            IqclAuth.LOGGER.error("[IQCL Auth] [{}] 验证请求处理失败", playerName, t);
            sendResult(server, player, false, "验证请求处理失败: " + t.getMessage());
        }
    }

    /**
     * 完成登录流程（PIN 验证通过 + 账号关联完成后调用）。
     * 所有状态修改调度到主线程执行。
     */
    public static void completeLogin(MinecraftServer server, ServerPlayerEntity player,
                                     String playerName, Integer displayId, String username) {
        server.execute(() -> {
            IqclAuth.LOGGER.debug("[IQCL Auth] [{}] completeLogin 开始执行", playerName);

            // 异地登录检测
            if (PlayerSessionManager.isCrossIpLogin(player)) {
                PlayerSessionManager.lockSession(player.getUuid());
                IqclAuth.LOGGER.warn("[IQCL Auth] 玩家 {} 因异地登录被锁定", playerName);
                sendResult(server, player, false, "检测到异地登录，账号已被临时锁定，请稍后再试");
                player.networkHandler.disconnect(
                        net.minecraft.text.Text.literal("[IQCL] 检测到异地登录，账号已被临时锁定，请稍后再试"));
                return;
            }

            // 防多开检查
            if (displayId != null) {
                ServerPlayerEntity kicked = PlayerSessionManager.enforceSingleAccount(player, displayId);
                if (kicked != null) {
                    IqclAuth.LOGGER.info("[IQCL Auth] 玩家 {} 被踢：账号 {} 已在其他设备登录",
                            kicked.getEntityName(), displayId);
                }
            }

            // 标记认证
            AuthState.authenticate(player);
            PlayerSessionManager.recordAuthenticatedIp(player);
            PlayerSessionManager.bindAuthenticatedIp(player);

            // 恢复物品/位置
            PlayerSessionManager.restoreFromLimbo(player);

            // 发送 game-session login
            ApiGateway.notifyLogin(player.getUuid().toString(),
                    username != null ? username : playerName);

            IqclAuth.LOGGER.info("[IQCL Auth] 玩家 {} 已通过 PIN 认证", playerName);
            sendResult(server, player, true, "PIN 验证成功，登录已放行");
        });
    }

    private static void sendResult(MinecraftServer server, ServerPlayerEntity player,
                                   boolean success, String message) {
        server.execute(() -> {
            if (player.networkHandler != null && !player.isRemoved()) {
                PacketByteBuf buf = PacketByteBufs.create();
                buf.writeBoolean(success);
                buf.writeString(message);
                ServerPlayNetworking.send(player, NetworkConstants.S2C_RESULT_ID, buf);
            } else {
                IqclAuth.LOGGER.warn("[IQCL Auth] [{}] sendResult 跳过: networkHandler={}, removed={}",
                        player.getEntityName(),
                        player.networkHandler != null,
                        player.isRemoved());
            }
        });
    }

    /** 通过服务端主线程向玩家发送纯文本聊天消息（不影响客户端认证状态）。 */
    private static void sendRawMessage(MinecraftServer server, ServerPlayerEntity player,
                                       String message) {
        server.execute(() -> {
            if (player.networkHandler != null && !player.isRemoved()) {
                // 使用聊天消息而非 S2C_RESULT，避免误更新客户端 authenticated 状态
                String[] lines = message.split("\n");
                for (String line : lines) {
                    player.sendMessage(net.minecraft.text.Text.literal(line), false);
                }
            }
        });
    }
}
