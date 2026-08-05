/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.client;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.iqcl.auth.IqclAuth;
import com.iqcl.auth.crypto.Base64Utils;
import com.iqcl.auth.crypto.HexNonceGenerator;
import com.iqcl.auth.crypto.RsaOaepEncryptor;
import com.iqcl.auth.network.NetworkConstants;
import net.fabricmc.fabric.api.client.message.v1.ClientSendMessageEvents;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayNetworking;
import net.fabricmc.fabric.api.networking.v1.PacketByteBufs;
import net.minecraft.client.MinecraftClient;
import net.minecraft.client.network.ClientPlayerEntity;
import net.minecraft.network.PacketByteBuf;
import net.minecraft.text.Text;
import net.minecraft.util.Formatting;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 聊天指令拦截器（仅客户端）。
 * <p>
 * 【核心安全点】
 * 拦截玩家输入的 {@code /iqcl login pin <pin>} 指令，本地完成 RSA-OAEP 加密后
 * 通过 Fabric 自定义数据包发送密文，<b>取消向 MC 服务端发送明文聊天/指令文本</b>，
 * 从根本上杜绝 PIN 明文出现在服务端日志或网络流量中。
 * <p>
 * 同时注册 ALLOW_COMMAND（命令路径，无前导 /）与 ALLOW_CHAT（聊天路径，含前导 /）双重拦截，
 * 确保任何路径下 PIN 明文都不外泄。
 */
public final class PinChatInterceptor {

    /** 命令路径匹配（无前导 /）：iqcl login pin <pin> */
    private static final Pattern PIN_COMMAND =
            Pattern.compile("^iqcl\\s+login\\s+pin\\s+(\\S+)\\s*$", Pattern.CASE_INSENSITIVE);

    /** 聊天路径匹配（含前导 /）：/iqcl login pin <pin>，作为防御性兜底 */
    private static final Pattern PIN_CHAT =
            Pattern.compile("^/iqcl\\s+login\\s+pin\\s+(\\S+)\\s*$", Pattern.CASE_INSENSITIVE);

    /**
     * PIN 格式校验规则：
     * 允许 4-4-4 格式，如 ABCD-EFGH-JKLM
     * 也允许纯字母数字串（后端自行处理），最小 4 字符
     */
    private static final Pattern PIN_VALIDATION =
            Pattern.compile("^[A-Za-z0-9-]{4,32}$");

    private static final Gson GSON = new Gson();

    private PinChatInterceptor() {
    }

    /** 注册拦截器。 */
    public static void register() {
        // 命令路径：/iqcl login pin <pin>  →  ALLOW_COMMAND 事件，message 不含前导 /
        ClientSendMessageEvents.ALLOW_COMMAND.register(PinChatInterceptor::onCommand);
        // 聊天路径兜底：若某些情况下以聊天消息形式发送 /iqcl ...
        ClientSendMessageEvents.ALLOW_CHAT.register(PinChatInterceptor::onChat);
    }

    private static boolean onCommand(String command) {
        Matcher m = PIN_COMMAND.matcher(command);
        if (!m.matches()) {
            return true; // 非本模组指令，放行
        }
        return handlePin(m.group(1));
    }

    private static boolean onChat(String message) {
        Matcher m = PIN_CHAT.matcher(message);
        if (!m.matches()) {
            return true; // 非本模组指令，放行
        }
        return handlePin(m.group(1));
    }

    /**
     * 核心：本地 RSA 加密 PIN，通过自定义数据包发送密文，取消明文发送。
     *
     * @return 固定返回 false（取消原始消息发送）
     */
    private static boolean handlePin(String pin) {
        ClientPlayerEntity player = MinecraftClient.getInstance().player;
        if (player == null) {
            return false;
        }

        // —— 已登录检查：已认证玩家再次提交 PIN 直接拒绝 ——
        if (ClientAuthState.isAuthenticated()) {
            player.sendMessage(
                    Text.literal("[IQCL] 你已经登录成功，无需重复验证")
                            .formatted(Formatting.YELLOW),
                    false);
            return false;
        }

        // —— PIN 格式校验 ——
        if (!PIN_VALIDATION.matcher(pin).matches()) {
            displayResult(false, "PIN 格式无效，仅允许字母、数字和连字符，长度 4-32 字符");
            return false;
        }

        // 检查与服务端的模组通道是否可用
        if (!ClientPlayNetworking.canSend(NetworkConstants.C2S_VERIFY_ID)) {
            if (IqclAuth.isClientEnvironment()) {
                displayResult(false, "当前处于单人/联机模式，IQCL Auth 登录需在安装了本模组的专用服务器上使用");
            } else {
                displayResult(false, "当前服务器未安装 IQCL Auth 模组，无法验证 PIN");
            }
            return false;
        }

        try {
            // 1. 获取玩家标准带横杠 UUID
            String bindTarget;
            if (player.getUuid() == null) {
                displayResult(false, "无法获取玩家 UUID");
                return false;
            }
            bindTarget = player.getUuid().toString();

            // 2. 构造待加密明文 JSON
            //    {"pin":"<pin>","bindTarget":"<uuid-with-dashes>"}
            JsonObject plaintext = new JsonObject();
            plaintext.addProperty("pin", pin);
            plaintext.addProperty("bindTarget", bindTarget);
            String plaintextJson = GSON.toJson(plaintext);

            // 3. RSA-OAEP-2048 SHA-256 加密（纯非对称，无对称加密）
            //    【安全】PIN 明文在此处加密后即不再以明文形态存在
            byte[] cipherBytes = RsaOaepEncryptor.encrypt(
                    plaintextJson.getBytes(StandardCharsets.UTF_8));

            // 4. 组装上行请求包
            //    {"v":1,"ts":<UTC毫秒>,"nonce":"<32hex>","ciphertext":"<base64>"}
            JsonObject packet = new JsonObject();
            packet.addProperty("v", 1);
            packet.addProperty("ts", Instant.now().toEpochMilli());
            packet.addProperty("nonce", HexNonceGenerator.generate32Hex());
            packet.addProperty("ciphertext", Base64Utils.encode(cipherBytes));

            String packetJson = GSON.toJson(packet);

            // 5. 通过自定义数据包发送密文包至 MC 服务端
            //    【安全】此处仅发送密文，PIN 明文永不离开客户端
            PacketByteBuf buf = PacketByteBufs.create();
            buf.writeString(packetJson);
            ClientPlayNetworking.send(NetworkConstants.C2S_VERIFY_ID, buf);

            displayProgress();
        } catch (Exception e) {
            IqclAuth.LOGGER.error("PIN 加密/发送失败", e);
            displayResult(false, "加密发送失败: " + e.getMessage());
        }

        // 【关键安全点】无论成功与否，均取消原始明文指令发送
        return false;
    }

    /** 显示"验证中"提示。 */
    private static void displayProgress() {
        ClientPlayerEntity player = MinecraftClient.getInstance().player;
        if (player != null) {
            player.sendMessage(
                    Text.literal("[IQCL] 正在验证 PIN...").formatted(Formatting.YELLOW),
                    false);
        }
    }

    /** 在客户端聊天框展示最终结果。 */
    public static void displayResult(boolean success, String message) {
        // 同步本地认证状态
        ClientAuthState.setAuthenticated(success);

        ClientPlayerEntity player = MinecraftClient.getInstance().player;
        if (player != null) {
            Formatting color = success ? Formatting.GREEN : Formatting.RED;
            player.sendMessage(
                    Text.literal("[IQCL] " + message).formatted(color),
                    false);
        }
    }

    /** 是否已在客户端本地记录为已认证。 */
    public static boolean isAuthenticated() {
        return ClientAuthState.isAuthenticated();
    }

    /** 重置本地认证状态（登出时调用）。 */
    public static void resetAuth() {
        ClientAuthState.reset();
    }
}
