/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.server;

import com.google.gson.JsonObject;
import com.iqcl.auth.IqclAuth;
import com.iqcl.auth.config.ModConfig;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * API 网关：封装 game-session login/logout 接口调用。
 * <p>
 * 按 API 文档 7.5 / 7.6 节规范：
 * <ul>
 *   <li>POST /api/game-session/login — 玩家登录成功后调用</li>
 *   <li>POST /api/game-session/logout — 玩家登出后调用</li>
 * </ul>
 */
public final class ApiGateway {

    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    private static final ExecutorService API_EXECUTOR = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "IQCL-Api-Worker");
        t.setDaemon(true);
        return t;
    });

    private ApiGateway() {
    }

    /**
     * 通知验证服务器玩家已登录。
     */
    public static void notifyLogin(String mcUuid, String username) {
        ModConfig config = ModConfig.get();
        if (!config.enableGameSessionApi) return;

        JsonObject body = new JsonObject();
        body.addProperty("mcUUID", mcUuid);
        if (username != null) {
            body.addProperty("username", username);
        }

        sendPost(ModConfig.GAME_SESSION_LOGIN_URL, body, mcUuid, "login");
    }

    /**
     * 通知验证服务器玩家已登出。
     */
    public static void notifyLogout(String mcUuid) {
        ModConfig config = ModConfig.get();
        if (!config.enableGameSessionApi) return;

        JsonObject body = new JsonObject();
        body.addProperty("mcUUID", mcUuid);

        sendPost(ModConfig.GAME_SESSION_LOGOUT_URL, body, mcUuid, "logout");
    }

    private static void sendPost(String url, JsonObject body, String mcUuid, String action) {
        API_EXECUTOR.submit(() -> {
            try {
                ModConfig config = ModConfig.get();
                String json = body.toString();

                HttpRequest.Builder builder = HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .header("Content-Type", "application/json");

                // —— 鉴权（API 文档 2.3 节）：优先 apiId + apiKey 成套模式，未配置时回退 X-Server-Key ——
                boolean apiIdConfigured = config.apiId != null && !config.apiId.isEmpty()
                        && !config.apiId.startsWith("REPLACE_WITH");
                boolean apiKeyConfigured = config.apiKey != null && !config.apiKey.isEmpty()
                        && !config.apiKey.startsWith("REPLACE_WITH");
                if (apiIdConfigured && apiKeyConfigured) {
                    // 成套模式：X-Api-Id + X-Api-Key（规范 2.3 节优先）
                    builder.header("X-Api-Id", config.apiId);
                    builder.header("X-Api-Key", config.apiKey);
                } else {
                    // 回退模式：X-Server-Key（存量旧密钥）
                    builder.header("X-Server-Key", config.serverKey);
                    if (apiIdConfigured != apiKeyConfigured) {
                        IqclAuth.LOGGER.warn("[IQCL Auth] game-session {} apiId/apiKey 未成套配置，回退 X-Server-Key",
                                action);
                    }
                }
                HttpRequest request = builder
                        .POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8))
                        .timeout(Duration.ofSeconds(10))
                        .build();

                HttpResponse<String> response = HTTP_CLIENT.send(request,
                        HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

                int status = response.statusCode();
                String respBody = response.body();

                if (status == 200) {
                    IqclAuth.LOGGER.debug("[IQCL Auth] game-session {} 成功: {}", action, mcUuid);
                } else if (status == 405 || status == 404) {
                    // 端点尚未在服务端实现，不做警告
                    IqclAuth.LOGGER.debug("[IQCL Auth] game-session {} 端点未就绪: mcUUID={}, status={}, body={}",
                            action, mcUuid, status,
                            respBody != null && respBody.length() > 200 ? respBody.substring(0, 200) : respBody);
                } else {
                    IqclAuth.LOGGER.warn("[IQCL Auth] game-session {} 失败: mcUUID={}, status={}, body={}",
                            action, mcUuid, status,
                            respBody != null && respBody.length() > 200 ? respBody.substring(0, 200) : respBody);
                }
            } catch (Exception e) {
                IqclAuth.LOGGER.error("[IQCL Auth] game-session {} 异常: mcUUID={}", action, mcUuid, e);
            }
        });
    }
}
