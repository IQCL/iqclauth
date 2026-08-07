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

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

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
                    client.execute(() ->
                            // 统一入口：仅"登录成功"结果会置位本地认证状态，避免重复打印与状态误判
                            ClientAuthState.handleResult(success, message));
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

        // 服务端模组检测：延迟检查服务端是否注册了 IQCL Auth 自定义通道
        // （Fabric 的 EnvType.CLIENT 在所有客户端环境下均为 true，无法区分单人/联机与专用服务器，
        //  因此改用 canSend 检测服务端是否实际安装了本模组）
        ClientPlayConnectionEvents.JOIN.register((handler, sender, client) -> {
            client.execute(() -> {
                // 每次（重）连接都重置本地认证状态，避免残留旧会话状态导致误拦登录
                ClientAuthState.reset();
                // 延迟 30 tick（约 1.5 秒），等待服务端通道注册完成
                client.player.sendMessage(
                        Text.literal("[IQCL] 正在检测服务器模组支持...")
                                .formatted(Formatting.GRAY), false);
                scheduleModCheck(client);
            });
        });

        IqclAuth.LOGGER.info("[IQCL Auth] 客户端初始化完成");
    }

    /**
     * 延迟检查服务端是否安装了 IQCL Auth 模组。
     * 使用 canSend 检测自定义通道是否可用，而非 FabricLoader.getEnvironmentType()（后者在客户端永远为 CLIENT）。
     */
    private static void scheduleModCheck(MinecraftClient client) {
        ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
        scheduler.schedule(() -> {
            client.execute(() -> {
                if (client.player == null) return;

                if (!ClientPlayNetworking.canSend(NetworkConstants.C2S_VERIFY_ID)) {
                    client.player.sendMessage(
                            Text.literal("====================================")
                                    .formatted(Formatting.GOLD), false);
                    client.player.sendMessage(
                            Text.literal("[IQCL] 当前服务器未安装 IQCL Auth 模组")
                                    .formatted(Formatting.YELLOW, Formatting.BOLD), false);
                    client.player.sendMessage(
                            Text.literal("IQCL Auth 登录功能仅在安装了该模组的专用服务器上可用")
                                    .formatted(Formatting.GRAY), false);
                    client.player.sendMessage(
                            Text.literal("====================================")
                                    .formatted(Formatting.GOLD), false);
                } else {
                    IqclAuth.LOGGER.info("[IQCL Auth] 服务端模组通道检测成功");
                }
            });
            scheduler.shutdown();
        }, 1500, TimeUnit.MILLISECONDS);
    }
}
