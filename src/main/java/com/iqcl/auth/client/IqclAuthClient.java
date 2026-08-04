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
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayNetworking;
import net.minecraft.client.MinecraftClient;
import net.minecraft.network.PacketByteBuf;

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

        // 注册服务端 → 客户端结果接收器
        ClientPlayNetworking.registerGlobalReceiver(
                NetworkConstants.S2C_RESULT_ID,
                (client, handler, buf, responseSender) -> {
                    boolean success = buf.readBoolean();
                    String message = buf.readString();
                    client.execute(() -> PinChatInterceptor.displayResult(success, message));
                });

        // 注册服务端 → 客户端登出通知接收器
        ClientPlayNetworking.registerGlobalReceiver(
                NetworkConstants.S2C_LOGOUT_ID,
                (client, handler, buf, responseSender) -> {
                    client.execute(() -> {
                        PinChatInterceptor.resetAuth();
                        MinecraftClient mc = MinecraftClient.getInstance();
                        if (mc.player != null) {
                            mc.player.sendMessage(
                                    net.minecraft.text.Text.literal("[IQCL] 已登出，请重新登录")
                                            .formatted(net.minecraft.util.Formatting.GRAY),
                                    false);
                        }
                    });
                });

        IqclAuth.LOGGER.info("[IQCL Auth] 客户端初始化完成");
    }
}
