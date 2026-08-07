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

                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .header("Content-Type", "application/json")
                        .header("X-Server-Key", config.serverKey)
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
