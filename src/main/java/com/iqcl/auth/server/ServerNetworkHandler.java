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
 *       （Content-Type: application/json，X-Server-Key: &lt;配置&gt;，body = 原始密文包 JSON）；</li>
 *   <li>接收验证服务器返回的 Ed25519 签名响应；</li>
 *   <li>对 payload 执行规范化 JSON 序列化后验证 Ed25519 签名；</li>
 *   <li>验签失败 → 直接判定登录失败；验签成功 → 检查 payload.permission，banned 拒绝；</li>
 *   <li>将最终结果通过 S2C 数据包回传客户端。</li>
 * </ol>
 * <p>
 * HTTP 请求在独立线程池执行，避免阻塞服务端主线程；
 * 回传数据包时调度回服务端主线程以保证线程安全。
 * <p>
 * Fabric 1.20.1 Networking API v1：使用 {@code PlayChannelHandler} + {@code PacketByteBuf}。
 */
public final class ServerNetworkHandler {

    /** HTTP 客户端（连接超时 10s）。 */
    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    /** 验签请求工作线程池（守护线程，单线程足够，登录非高频操作）。 */
    private static final ExecutorService VERIFY_EXECUTOR = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "IQCL-Verify-Worker");
        t.setDaemon(true);
        return t;
    });

    private ServerNetworkHandler() {
    }

    /** 注册服务端 C2S 接收器。在 main entrypoint 调用，内置/专用服务端均生效。 */
    public static void register() {
        ServerPlayNetworking.registerGlobalReceiver(
                NetworkConstants.C2S_VERIFY_ID,
                (server, player, handler, buf, responseSender) -> {
                    // 读取客户端发来的完整密文包 JSON
                    String packetJson = buf.readString();

                    IqclAuth.LOGGER.info("[IQCL Auth] 收到玩家 {} 的 PIN 验证请求，开始异步转发",
                            player.getEntityName());

                    // 异步执行 HTTP 转发 + 验签，避免阻塞服务端主线程
                    VERIFY_EXECUTOR.submit(() -> processVerify(player, server, packetJson));
                });
    }

    /**
     * 处理一次完整的验证流程：转发 → 验签 → 权限检查。
     * 运行在工作线程，最后通过 server.execute 切回主线程发送结果。
     */
    private static void processVerify(ServerPlayerEntity player, MinecraftServer server,
                                      String packetJson) {
        try {
            ModConfig config = ModConfig.get();

            // —— 1. 透明转发：原样发送客户端密文包 ——
            // 【安全】服务端不解密、不查看 ciphertext 内容，仅作为 HTTP 中转
            // API 地址为硬编码常量，防止被篡改指向恶意服务器
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(ModConfig.VERIFY_API_URL))
                    .header("Content-Type", "application/json")
                    .header("X-Server-Key", config.serverKey)
                    .POST(HttpRequest.BodyPublishers.ofString(packetJson, StandardCharsets.UTF_8))
                    .timeout(Duration.ofSeconds(15))
                    .build();

            HttpResponse<String> response =
                    HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

            if (response.statusCode() != 200) {
                IqclAuth.LOGGER.warn("[IQCL Auth] 验证服务器返回非 200 状态码: {}",
                        response.statusCode());
                sendResult(server, player, false, "验证服务器返回异常状态码: " + response.statusCode());
                return;
            }

            // —— 2. 解析验证服务器响应 ——
            // 期望结构: {"success":bool,"serverTs":number,"payload":object,"signature":"base64"}
            JsonElement rootElement;
            try {
                rootElement = JsonParser.parseString(response.body());
            } catch (Exception e) {
                sendResult(server, player, false, "验证服务器响应解析失败");
                return;
            }
            if (rootElement == null || !rootElement.isJsonObject()) {
                sendResult(server, player, false, "验证服务器响应格式无效");
                return;
            }
            JsonObject resp = rootElement.getAsJsonObject();

            boolean serverSuccess = resp.has("success") && resp.get("success").getAsBoolean();
            String signature = resp.has("signature") ? resp.get("signature").getAsString() : "";

            JsonObject payloadObj;
            if (resp.has("payload") && resp.get("payload").isJsonObject()) {
                payloadObj = resp.getAsJsonObject("payload");
            } else {
                payloadObj = new JsonObject();
            }

            // —— 3. 规范化序列化 payload 并验证 Ed25519 签名 ——
            // 【关键安全步骤】必须先 canonical JSON 再验签，不可跳过
            String canonicalPayload = CanonicalJson.stringify(payloadObj);
            byte[] messageBytes = canonicalPayload.getBytes(StandardCharsets.UTF_8);

            byte[] sigBytes;
            try {
                sigBytes = Base64Utils.decode(signature);
            } catch (IllegalArgumentException e) {
                IqclAuth.LOGGER.warn("[IQCL Auth] 签名 base64 解码失败");
                sendResult(server, player, false, "签名格式错误");
                return;
            }

            boolean sigValid;
            try {
                sigValid = Ed25519Verifier.verify(messageBytes, sigBytes);
            } catch (Exception e) {
                IqclAuth.LOGGER.error("[IQCL Auth] Ed25519 验签异常", e);
                sendResult(server, player, false, "验签过程异常");
                return;
            }

            if (!sigValid) {
                // 【安全】验签失败 → 直接拒绝，不执行任何后续登录逻辑
                IqclAuth.LOGGER.warn("[IQCL Auth] 玩家 {} 验签失败，拒绝登录",
                        player.getEntityName());
                sendResult(server, player, false, "验签失败，拒绝登录");
                return;
            }

            IqclAuth.LOGGER.info("[IQCL Auth] 玩家 {} 验签通过", player.getEntityName());

            // —— 4. 验签成功，检查 payload.permission ——
            if (payloadObj.has("permission")) {
                String permission = payloadObj.get("permission").getAsString();
                if ("banned".equalsIgnoreCase(permission)) {
                    sendResult(server, player, false, "账号已被封禁");
                    return;
                }
            }

            // —— 5. 综合判定 ——
            if (!serverSuccess) {
                sendResult(server, player, false, "PIN 验证失败");
                return;
            }

            sendResult(server, player, true, "PIN 验证成功，登录已放行");

        } catch (Exception e) {
            IqclAuth.LOGGER.error("[IQCL Auth] 验证请求处理失败", e);
            sendResult(server, player, false, "验证请求处理失败: " + e.getMessage());
        }
    }

    /**
     * 将结果调度到服务端主线程后发送 S2C 数据包。
     * 工作线程不能直接操作网络处理器，需切回主线程保证线程安全。
     */
    private static void sendResult(MinecraftServer server, ServerPlayerEntity player,
                                   boolean success, String message) {
        server.execute(() -> {
            // 检查玩家是否仍在线（HTTP 期间可能已下线）
            if (player.networkHandler != null && !player.isRemoved()) {
                PacketByteBuf buf = PacketByteBufs.create();
                buf.writeBoolean(success);
                buf.writeString(message);
                ServerPlayNetworking.send(player, NetworkConstants.S2C_RESULT_ID, buf);
            } else {
                IqclAuth.LOGGER.debug("[IQCL Auth] 玩家 {} 已离线，跳过结果回传",
                        player.getEntityName());
            }
        });
    }
}
