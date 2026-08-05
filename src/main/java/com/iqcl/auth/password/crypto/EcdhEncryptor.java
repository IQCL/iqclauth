/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.password.crypto;

import com.iqcl.auth.crypto.Base64Utils;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Arrays;

/**
 * 服务端 ECDH 解密客户端密文包。
 * <p>
 * 加密流程（客户端 ↔ 服务端对称）：
 * <ol>
 *   <li>客户端生成临时 X25519 密钥对，私钥丢弃，公钥发送</li>
 *   <li>双方执行 X25519 ECDH，得到 32 字节 sharedSecret</li>
 *   <li>用 SHA-256("iqclauth-password-v1" || sharedSecret) 作为 KDF 派生出 32 字节 AES-256 Key</li>
 *   <li>客户端用 AES-256-GCM（12 字节随机 IV）加密明文，发送 IV + Tag + 密文</li>
 *   <li>服务端用相同 KDF 派生 key，AES-256-GCM 解密</li>
 * </ol>
 * <p>
 * 与 {@link com.iqcl.auth.crypto.RsaOaepEncryptor} 完全独立——前者用于远程服务器 PIN 验证，
 * 后者用于服务端本地密码验证的传输层加密。
 */
public final class EcdhEncryptor {

    private static final String KDF_LABEL = "iqclauth-password-v1";
    private static final int GCM_IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final int AES_KEY_BYTES = 32;

    private static final NamedParameterSpec X25519_SPEC = new NamedParameterSpec("X25519");

    private EcdhEncryptor() {
    }

    /**
     * 解密客户端密文包。
     *
     * @param clientPubBase64 客户端 X25519 临时公钥（base64，32 字节原始）
     * @param ivBase64         12 字节 IV（base64）
     * @param ctBase64         密文+GCM tag（base64）
     * @return 明文字节
     */
    public static byte[] decrypt(String clientPubBase64, String ivBase64, String ctBase64)
            throws GeneralSecurityException {
        KeyPair server = ServerKeyStore.getKeyPair();
        if (server == null) {
            throw new GeneralSecurityException("服务端密钥对未初始化");
        }

        byte[] clientPubBytes = Base64Utils.decode(clientPubBase64);
        byte[] iv = Base64Utils.decode(ivBase64);
        byte[] ct = Base64Utils.decode(ctBase64);

        if (clientPubBytes.length != 32) {
            throw new GeneralSecurityException("客户端公钥长度应为 32 字节，实际: " + clientPubBytes.length);
        }
        if (iv.length != GCM_IV_BYTES) {
            throw new GeneralSecurityException("IV 长度应为 " + GCM_IV_BYTES + " 字节，实际: " + iv.length);
        }

        // 重建客户端公钥（X25519 32 字节 → BigInteger u → XECPublicKeySpec）
        KeyFactory kf = KeyFactory.getInstance("XDH");
        BigInteger clientU = new BigInteger(1, clientPubBytes);
        XECPublicKeySpec pubSpec = new XECPublicKeySpec(X25519_SPEC, clientU);
        java.security.PublicKey clientPub = kf.generatePublic(pubSpec);

        // ECDH 计算 sharedSecret
        KeyAgreement ka = KeyAgreement.getInstance("XDH");
        ka.init(server.getPrivate());
        ka.doPhase(clientPub, true);
        byte[] sharedSecret = ka.generateSecret();

        // KDF: SHA-256(label || sharedSecret) → 32 字节 AES key
        byte[] aesKey = kdf(sharedSecret);

        // AES-256-GCM 解密
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
        byte[] plain = cipher.doFinal(ct);

        // 清零敏感材料
        Arrays.fill(sharedSecret, (byte) 0);
        Arrays.fill(aesKey, (byte) 0);
        Arrays.fill(clientPubBytes, (byte) 0);
        Arrays.fill(iv, (byte) 0);

        return plain;
    }

    /**
     * KDF：SHA-256(label || sharedSecret)，返回前 32 字节作为 AES key。
     * 使用 HMAC-SHA256 的一次性调用（key=SHA-256(label)）以降低碰撞风险，
     * 避免单纯拼接的长度扩展攻击面。
     */
    private static byte[] kdf(byte[] sharedSecret) throws GeneralSecurityException {
        byte[] labelBytes = KDF_LABEL.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(labelBytes, "HmacSHA256"));
        byte[] derived = hmac.doFinal(sharedSecret);
        byte[] key = Arrays.copyOf(derived, AES_KEY_BYTES);
        Arrays.fill(derived, (byte) 0);
        return key;
    }
}
