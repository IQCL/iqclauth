/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.client;

import com.iqcl.auth.IqclAuth;
import com.iqcl.auth.network.NetworkConstants;
import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayConnectionEvents;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayNetworking;
import net.minecraft.client.MinecraftClient;
import net.minecraft.network.PacketByteBuf;
import net.minecraft.text.Text;
import net.minecraft.util.Formatting;

/**
 * 客户端入口（client entrypoint）。
 * <p>
 * 职责：
 * <ol>
 *   <li>注册聊天指令拦截器：捕获 {@code /iqcl login pin <pin>}，本地 RSA 加密后通过自定义数据包发送；</li>
 *   <li>注册服务端结果接收器：接收 S2C 结果并在客户端聊天框展示。</li>
 * </ol>
 * <p>
 * Fabric 1.20.1 Networking API v1：使用 {@code PlayChannelHandler} + {@code PacketByteBuf}。
 */
public class IqclAuthClient implements ClientModInitializer {

    @Override
    public void onInitializeClient() {
        IqclAuth.LOGGER.info("[IQCL Auth] 客户端初始化...");

        // 注册 /iqcl login pin <pin> 拦截 + RSA 加密 + 自定义数据包发送
        PinChatInterceptor.register();

        // 注册密码命令拦截器：login/register/changepassword/unregister 均本地 ECDH+AES-GCM 加密
        PasswordChatInterceptor.register();

        // 注册服务端 → 客户端结果接收器（PIN 与密码登录共用，按消息内容区分）
        ClientPlayNetworking.registerGlobalReceiver(
                NetworkConstants.S2C_RESULT_ID,
                (client, handler, buf, responseSender) -> {
                    boolean success = buf.readBoolean();
                    String message = buf.readString();
                    client.execute(() -> {
                        // 两个拦截器的 displayResult 都会更新 ClientAuthState
                        PinChatInterceptor.displayResult(success, message);
                        PasswordChatInterceptor.displayResult(success, message);
                    });
                });

        // 注册服务端 → 客户端登出通知接收器
        ClientPlayNetworking.registerGlobalReceiver(
                NetworkConstants.S2C_LOGOUT_ID,
                (client, handler, buf, responseSender) -> {
                    client.execute(() -> {
                        ClientAuthState.reset();
                        MinecraftClient mc = MinecraftClient.getInstance();
                        if (mc.player != null) {
                            mc.player.sendMessage(
                                    Text.literal("[IQCL] 已登出，请重新登录")
                                            .formatted(Formatting.GRAY),
                                    false);
                        }
                    });
                });

        // 注册服务端 → 客户端 AUTHINFO 接收器：接收服务端 X25519 公钥 + 功能开关
        ClientPlayNetworking.registerGlobalReceiver(
                NetworkConstants.S2C_AUTHINFO_ID,
                (client, handler, buf, responseSender) -> {
                    String pub = buf.readString();
                    boolean passwordEnabled = buf.readBoolean();
                    client.execute(() -> {
                        PasswordChatInterceptor.serverPublicKeyBase64 = pub;
                        IqclAuth.LOGGER.info("[IQCL Auth] 已接收服务端 X25519 公钥，密码登录加密通道可用={}",
                                passwordEnabled);
                    });
                });

        // 客户端环境提示：单人/联机模式时告知用户 IQCL Auth 登录不可用
        ClientPlayConnectionEvents.JOIN.register((handler, sender, client) -> {
            if (IqclAuth.isClientEnvironment()) {
                client.execute(() -> {
                    if (client.player != null) {
                        client.player.sendMessage(
                                Text.literal("====================================")
                                        .formatted(Formatting.GOLD), false);
                        client.player.sendMessage(
                                Text.literal("[IQCL] 当前处于单人/联机模式")
                                        .formatted(Formatting.YELLOW, Formatting.BOLD), false);
                        client.player.sendMessage(
                                Text.literal("IQCL Auth 登录功能仅在安装了该模组的专用服务器上可用")
                                        .formatted(Formatting.GRAY), false);
                        client.player.sendMessage(
                                Text.literal("====================================")
                                        .formatted(Formatting.GOLD), false);
                    }
                });
            }
        });

        IqclAuth.LOGGER.info("[IQCL Auth] 客户端初始化完成");
    }
}
