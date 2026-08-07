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
import com.iqcl.auth.crypto.HexNonceGenerator;
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
 * 密码命令拦截器（客户端，仅与 {@link PinChatInterceptor} 并列注册）。
 * <p>
 * 拦截玩家输入的密码相关指令（login/register/changepassword/unregister），
 * 本地完成 X25519+AES-256-GCM 加密后通过 {@code C2S_PASSWORD_ID} 发送密文，
 * <b>取消向 MC 服务端发送明文指令</b>，从根本上杜绝密码明文外泄。
 * <p>
 * 与 PIN 拦截器的区别：
 * <ul>
 *   <li>PIN 拦截器：RSA-OAEP 加密 → 远程 IQCL 服务器验证</li>
 *   <li>密码拦截器：X25519+AES-GCM 加密 → 服务端本地验证 PBKDF2 哈希</li>
 * </ul>
 */
public final class PasswordChatInterceptor {

    /** 客户端持有的服务端 X25519 公钥（由 S2C_AUTHINFO_ID 接收器设置）。 */
    public static volatile String serverPublicKeyBase64;

    /** 密码登录命令匹配：iqcl login password <pwd>  — 用 greedy，允许空格（但不推荐）。 */
    private static final Pattern LOGIN_CMD =
            Pattern.compile("^iqcl\\s+login\\s+password\\s+(.+)$",
                    Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    private static final Pattern LOGIN_CHAT =
            Pattern.compile("^/iqcl\\s+login\\s+password\\s+(.+)$",
                    Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    /** 注册密码命令匹配：iqcl register password <pwd> <confirm> — 用 \\S+ 避免贪婪吞并 confirm。 */
    private static final Pattern REGISTER_CMD =
            Pattern.compile("^iqcl\\s+register\\s+password\\s+(\\S+)\\s+(\\S+)\\s*$",
                    Pattern.CASE_INSENSITIVE);
    private static final Pattern REGISTER_CHAT =
            Pattern.compile("^/iqcl\\s+register\\s+password\\s+(\\S+)\\s+(\\S+)\\s*$",
                    Pattern.CASE_INSENSITIVE);

    /** 改密命令：iqcl changepassword <old> <new>。 */
    private static final Pattern CHANGE_CMD =
            Pattern.compile("^iqcl\\s+changepassword\\s+(\\S+)\\s+(\\S+)\\s*$",
                    Pattern.CASE_INSENSITIVE);
    private static final Pattern CHANGE_CHAT =
            Pattern.compile("^/iqcl\\s+changepassword\\s+(\\S+)\\s+(\\S+)\\s*$",
                    Pattern.CASE_INSENSITIVE);

    /** 注销密码命令：iqcl unregister password <pwd>。 */
    private static final Pattern UNREGISTER_CMD =
            Pattern.compile("^iqcl\\s+unregister\\s+password\\s+(\\S+)\\s*$",
                    Pattern.CASE_INSENSITIVE);
    private static final Pattern UNREGISTER_CHAT =
            Pattern.compile("^/iqcl\\s+unregister\\s+password\\s+(\\S+)\\s*$",
                    Pattern.CASE_INSENSITIVE);

    private static final Gson GSON = new Gson();

    private PasswordChatInterceptor() {
    }

    /** 注册拦截器。在 {@link com.iqcl.auth.client.IqclAuthClient#onInitializeClient} 中调用。 */
    public static void register() {
        ClientSendMessageEvents.ALLOW_COMMAND.register(PasswordChatInterceptor::onCommand);
        ClientSendMessageEvents.ALLOW_CHAT.register(PasswordChatInterceptor::onChat);
    }

    private static boolean onCommand(String command) {
        return dispatch(command);
    }

    private static boolean onChat(String message) {
        return dispatch(message);
    }

    /** 分派密码命令。返回 false 取消原始明文发送。 */
    private static boolean dispatch(String msg) {
        // login
        Matcher m = LOGIN_CMD.matcher(msg);
        if (m.matches()) return handle("login", m.group(1), null, "login");
        m = LOGIN_CHAT.matcher(msg);
        if (m.matches()) return handle("login", m.group(1), null, "login");

        // register
        m = REGISTER_CMD.matcher(msg);
        if (m.matches()) return handle("register", m.group(1), m.group(2), "register");
        m = REGISTER_CHAT.matcher(msg);
        if (m.matches()) return handle("register", m.group(1), m.group(2), "register");

        // change
        m = CHANGE_CMD.matcher(msg);
        if (m.matches()) return handle("changepassword", m.group(1), m.group(2), "changepassword");
        m = CHANGE_CHAT.matcher(msg);
        if (m.matches()) return handle("changepassword", m.group(1), m.group(2), "changepassword");

        // unregister
        m = UNREGISTER_CMD.matcher(msg);
        if (m.matches()) return handle("unregister", m.group(1), null, "unregister");
        m = UNREGISTER_CHAT.matcher(msg);
        if (m.matches()) return handle("unregister", m.group(1), null, "unregister");

        return true; // 非密码命令，放行
    }

    /**
     * 核心：构造内层 JSON → X25519+AES-GCM 加密 → 发送 C2S_PASSWORD_ID。
     *
     * @return false（取消原始明文发送）
     */
    private static boolean handle(String op, String arg1, String arg2, String displayOp) {
        ClientPlayerEntity player = MinecraftClient.getInstance().player;
        if (player == null) return false;

        // 仅 login 在已登录后拒绝；register/changepassword/unregister 均需放行
        // （PIN 登录后需允许 register 设置密码，changepassword/unregister 需已登录状态）
        if ("login".equals(op) && ClientAuthState.isAuthenticated()) {
            player.sendMessage(
                    Text.literal("[IQCL] 你已经登录成功，无需重复操作")
                            .formatted(Formatting.YELLOW),
                    false);
            return false;
        }

        if (serverPublicKeyBase64 == null || serverPublicKeyBase64.isEmpty()) {
            displayResult(false, "未收到服务端公钥，请重连服务器");
            return false;
        }

        if (!ClientPlayNetworking.canSend(NetworkConstants.C2S_PASSWORD_ID)) {
            displayResult(false, "当前服务器未安装 IQCL Auth 模组，无法执行密码操作");
            return false;
        }

        try {
            String bindTarget = player.getUuid() != null
                    ? player.getUuid().toString() : "";

            // 构造内层明文 JSON
            JsonObject plaintext = new JsonObject();
            plaintext.addProperty("op", op);
            plaintext.addProperty("password", arg1);
            if (arg2 != null) {
                plaintext.addProperty("confirm", arg2);
            }
            plaintext.addProperty("bindTarget", bindTarget);
            String plaintextJson = GSON.toJson(plaintext);

            // ECDH + AES-GCM 加密
            EcdhClient.EncryptedPayload payload = EcdhClient.encrypt(
                    serverPublicKeyBase64,
                    plaintextJson.getBytes(StandardCharsets.UTF_8));

            // 组装外层包
            JsonObject packet = new JsonObject();
            packet.addProperty("v", 1);
            packet.addProperty("op", op);
            packet.addProperty("ts", Instant.now().toEpochMilli());
            packet.addProperty("nonce", HexNonceGenerator.generate32Hex());
            packet.addProperty("clientPub", payload.clientPub);
            packet.addProperty("iv", payload.iv);
            packet.addProperty("ct", payload.ct);

            String packetJson = GSON.toJson(packet);

            PacketByteBuf buf = PacketByteBufs.create();
            buf.writeString(packetJson);
            ClientPlayNetworking.send(NetworkConstants.C2S_PASSWORD_ID, buf);

            player.sendMessage(
                    Text.literal("[IQCL] " + displayOp + " 处理中...")
                            .formatted(Formatting.YELLOW),
                    false);
        } catch (Exception e) {
            IqclAuth.LOGGER.error("密码命令加密/发送失败", e);
            displayResult(false, "加密发送失败: " + e.getMessage());
        }

        return false; // 取消原始明文命令
    }

    /** 在客户端聊天框展示本地结果（不改动认证状态；服务端结果统一由 ClientAuthState.handleResult 处理）。 */
    public static void displayResult(boolean success, String message) {
        ClientPlayerEntity player = MinecraftClient.getInstance().player;
        if (player != null) {
            Formatting color = success ? Formatting.GREEN : Formatting.RED;
            player.sendMessage(
                    Text.literal("[IQCL] " + message).formatted(color),
                    false);
        }
    }
}
