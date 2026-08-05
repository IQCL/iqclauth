/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.password.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * TOTP (Time-based One-Time Password) 双因素认证管理器。
 * <p>
 * 实现基于 RFC 6238 的 TOTP 算法，兼容 Google Authenticator、Aegis、1Password 等
 * 标准 TOTP 客户端。默认参数：HmacSHA1、30 秒步长、6 位数字码。
 * <p>
 * 安全特性：
 * <ul>
 *   <li>时间窗口验证（±1 步长）：容忍客户端/服务端时钟偏移</li>
 *   <li>重放防护：记录最近一次成功的码，防止同一时间窗口内重复使用</li>
 * </ul>
 */
public final class TotpManager {

    /** TOTP 时间步长（秒）。 */
    private static final int TIME_STEP_SECONDS = 30;
    /** TOTP 码位数。 */
    private static final int CODE_DIGITS = 6;
    /** HMAC 算法。 */
    private static final String HMAC_ALGO = "HmacSHA1";
    /** TOTP 密钥字节长度（20 字节 = 160 位，Base32 编码后 32 字符）。 */
    private static final int SECRET_BYTES = 20;
    /** 验证时容忍的时间步长窗口（±1 步 = ±30 秒）。 */
    private static final int VERIFY_WINDOW = 1;

    private static final SecureRandom RNG = new SecureRandom();
    private static final Base32 BASE32 = new Base32();

    private TotpManager() {
    }

    /**
     * 生成新的 TOTP 密钥（Base32 编码）。
     *
     * @return 32 字符的 Base32 密钥
     */
    public static String generateSecret() {
        byte[] bytes = new byte[SECRET_BYTES];
        RNG.nextBytes(bytes);
        return BASE32.encode(bytes);
    }

    /**
     * 生成当前时间的 TOTP 码。
     *
     * @param base32Secret Base32 编码密钥
     * @return 6 位数字 TOTP 码（补零）
     */
    public static String generateCode(String base32Secret) {
        long timeStep = System.currentTimeMillis() / 1000L / TIME_STEP_SECONDS;
        return generateCode(base32Secret, timeStep);
    }

    /**
     * 生成指定时间步长的 TOTP 码。
     */
    public static String generateCode(String base32Secret, long timeStep) {
        try {
            byte[] secretBytes = BASE32.decode(base32Secret);
            byte[] timeBytes = ByteBuffer.allocate(8).putLong(timeStep).array();

            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(new SecretKeySpec(secretBytes, HMAC_ALGO));
            byte[] hash = mac.doFinal(timeBytes);

            // Dynamic truncation (RFC 6238 Section 4.2)
            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);

            int otp = binary % 1_000_000; // 6 digits
            return String.format("%0" + CODE_DIGITS + "d", otp);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("TOTP 生成失败", e);
        }
    }

    /**
     * 验证 TOTP 码。
     *
     * @param base32Secret  Base32 编码密钥
     * @param code          用户输入的 6 位码
     * @param lastUsedCode  上次使用的码（重放防护，可为 null）
     * @return true = 验证通过
     */
    public static boolean verify(String base32Secret, String code, String lastUsedCode) {
        if (code == null || code.length() != CODE_DIGITS) return false;

        long currentTimeStep = System.currentTimeMillis() / 1000L / TIME_STEP_SECONDS;

        // 检查时间窗口内的所有可能码（±VERIFY_WINDOW 步）
        for (int i = -VERIFY_WINDOW; i <= VERIFY_WINDOW; i++) {
            String expected = generateCode(base32Secret, currentTimeStep + i);
            if (expected.equals(code)) {
                // 重放防护：如果和上次使用的码相同，拒绝
                if (lastUsedCode != null && lastUsedCode.equals(code)) {
                    return false;
                }
                return true;
            }
        }
        return false;
    }

    /**
     * 生成 TOTP 密钥 URI（用于生成二维码）。
     * <p>
     * 格式：{@code otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30}
     *
     * @param issuer  发行者（如 "IQCL Auth"）
     * @param account 账户名（如玩家名或 UUID）
     * @param secret  Base32 密钥
     * @return URI 字符串
     */
    public static String buildOtpAuthUri(String issuer, String account, String secret) {
        // 手动拼接避免 URL 编码问题
        return String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
                issuer, account, secret, issuer);
    }

    /**
     * 简易 Base32 编解码器（RFC 4648，仅覆盖 TOTP 所需的编码/解码）。
     * <p>
     * 使用标准 Base32 字母表（A-Z, 2-7），填充字符 '='。
     */
    private static class Base32 {
        private static final char[] ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();
        private static final int[] DECODE_MAP = new int[128];

        static {
            for (int i = 0; i < ALPHABET.length; i++) {
                DECODE_MAP[ALPHABET[i]] = i;
            }
        }

        /** 将字节数组编码为 Base32 字符串。 */
        String encode(byte[] data) {
            StringBuilder sb = new StringBuilder();
            int bits = 0;
            int buffer = 0;
            for (byte b : data) {
                buffer = (buffer << 8) | (b & 0xFF);
                bits += 8;
                while (bits >= 5) {
                    bits -= 5;
                    sb.append(ALPHABET[(buffer >> bits) & 0x1F]);
                }
            }
            // 填充最后不足 5 位的部分
            if (bits > 0) {
                sb.append(ALPHABET[(buffer << (5 - bits)) & 0x1F]);
            }
            // 添加 '=' 填充到 8 字符边界
            while (sb.length() % 8 != 0) {
                sb.append('=');
            }
            return sb.toString();
        }

        /** 从 Base32 字符串解码为字节数组。 */
        byte[] decode(String encoded) {
            // 去除填充
            int padLen = 0;
            for (int i = encoded.length() - 1; i >= 0; i--) {
                if (encoded.charAt(i) == '=') padLen++;
                else break;
            }
            String clean = encoded.substring(0, encoded.length() - padLen);

            int outputLen = clean.length() * 5 / 8;
            byte[] result = new byte[outputLen];
            int buffer = 0;
            int bits = 0;
            int pos = 0;

            for (int i = 0; i < clean.length(); i++) {
                char c = Character.toUpperCase(clean.charAt(i));
                int val = (c >= 128) ? -1 : DECODE_MAP[c];
                if (val < 0) throw new IllegalArgumentException("非法 Base32 字符: " + c);
                buffer = (buffer << 5) | val;
                bits += 5;
                if (bits >= 8) {
                    bits -= 8;
                    result[pos++] = (byte) (buffer >> bits);
                }
            }
            return result;
        }
    }
}
