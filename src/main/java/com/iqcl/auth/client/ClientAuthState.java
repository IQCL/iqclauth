/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.client;

import net.minecraft.client.MinecraftClient;
import net.minecraft.client.network.ClientPlayerEntity;
import net.minecraft.text.Text;
import net.minecraft.util.Formatting;

/**
 * 客户端认证状态集中管理。
 * <p>
 * 原先 {@link PinChatInterceptor} 持有独立 {@code authenticated} 字段，
 * 阶段 2 引入 {@code PasswordChatInterceptor} 后会造成状态分裂。
 * 这里将客户端认证状态提取到单一源，由两个拦截器共同使用。
 */
public final class ClientAuthState {

    private static volatile boolean authenticated = false;

    private ClientAuthState() {
    }

    public static boolean isAuthenticated() {
        return authenticated;
    }

    public static void setAuthenticated(boolean v) {
        authenticated = v;
    }

    public static void reset() {
        authenticated = false;
    }

    /**
     * 判断一条 S2C_RESULT 消息是否为"登录成功"结果。
     * <p>
     * S2C_RESULT 通道同时承载登录结果与非登录操作结果（注册/改密/注销等），
     * 客户端只能通过消息内容识别真正的登录成功，避免把非登录结果误判为已认证，
     * 造成客户端与服务端认证状态脱节（例如登出后被误拦"无需重复操作"）。
     */
    public static boolean isLoginSuccessMessage(String message) {
        if (message == null) return false;
        return message.contains("登录已放行")
                || message.contains("密码登录成功")
                || message.contains("已自动恢复登录状态")
                || message.contains("强行登录");
    }

    /**
     * 统一处理服务端 S2C_RESULT 结果（唯一入口）。
     * <p>
     * 只有真正的"登录成功"结果才会置位本地认证状态；
     * 其余结果（重复登录拒绝、注册/改密/注销结果等）只展示、不改状态，
     * 认证状态的重置统一由 S2C_LOGOUT 通道完成。
     */
    public static void handleResult(boolean success, String message) {
        if (success && isLoginSuccessMessage(message)) {
            authenticated = true;
        }
        ClientPlayerEntity player = MinecraftClient.getInstance().player;
        if (player != null) {
            Formatting color = success ? Formatting.GREEN : Formatting.RED;
            player.sendMessage(
                    Text.literal("[IQCL] " + message).formatted(color),
                    false);
        }
    }
}
