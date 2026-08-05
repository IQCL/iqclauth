/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.client;

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
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Arrays;

/**
 * 客户端 ECDH 加密工具（与 {@code com.iqcl.auth.password.crypto.EcdhEncryptor} 对称）。
 * <p>
 * 每个密码操作生成独立临时 X25519 密钥对 → ECDH 派生对称 key → AES-256-GCM 加密。
 * 客户端私钥在加密完成后立即丢弃，实现"前向安全"。
 * <p>
 * Java 11+ 中 X25519 公钥通过 {@link XECPublicKeySpec} + {@link NamedParameterSpec}("X25519")
 * 构造，32 字节原始 X25519 字节映射为 {@link BigInteger} u 坐标。
 */
public final class EcdhClient {

    private static final String KDF_LABEL = "iqclauth-password-v1";
    private static final int GCM_IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final int AES_KEY_BYTES = 32;

    private static final NamedParameterSpec X25519_SPEC = new NamedParameterSpec("X25519");
    private static final SecureRandom RNG = new SecureRandom();

    private EcdhClient() {
    }

    /**
     * 加密明文。
     *
     * @param serverPubBase64 服务端 X25519 公钥（base64，由 S2C_AUTHINFO_ID 提供，32 字节原始）
     * @param plaintext       明文字节
     * @return EncryptedPayload {clientPub, iv, ct}
     */
    public static EncryptedPayload encrypt(String serverPubBase64, byte[] plaintext)
            throws GeneralSecurityException {
        byte[] serverPubBytes = Base64Utils.decode(serverPubBase64);
        if (serverPubBytes.length != 32) {
            throw new GeneralSecurityException("服务端公钥长度非法: " + serverPubBytes.length);
        }

        // 1. 生成客户端临时 X25519 密钥对
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH");
        kpg.initialize(X25519_SPEC);
        KeyPair client = kpg.generateKeyPair();

        // 2. 重建服务端公钥（32 字节 → BigInteger u → XECPublicKeySpec）
        KeyFactory kf = KeyFactory.getInstance("XDH");
        BigInteger serverU = new BigInteger(1, serverPubBytes);
        XECPublicKeySpec pubSpec = new XECPublicKeySpec(X25519_SPEC, serverU);
        java.security.PublicKey serverPub = kf.generatePublic(pubSpec);

        // 3. ECDH 计算 sharedSecret
        KeyAgreement ka = KeyAgreement.getInstance("XDH");
        ka.init(client.getPrivate());
        ka.doPhase(serverPub, true);
        byte[] sharedSecret = ka.generateSecret();

        // 4. KDF 派生 AES key
        byte[] aesKey = kdf(sharedSecret);

        // 5. AES-256-GCM 加密
        byte[] iv = new byte[GCM_IV_BYTES];
        RNG.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        byte[] ct = cipher.doFinal(plaintext);

        // 6. 清零敏感材料
        Arrays.fill(sharedSecret, (byte) 0);
        Arrays.fill(aesKey, (byte) 0);

        return new EncryptedPayload(
                clientPubToRaw(client.getPublic()),
                Base64Utils.encode(iv),
                Base64Utils.encode(ct));
    }

    /** 把 X25519 公钥转为 32 字节原始表示（用于 base64 传输）。 */
    static String clientPubToRaw(java.security.PublicKey pub) throws GeneralSecurityException {
        KeyFactory kf = KeyFactory.getInstance("XDH");
        XECPublicKeySpec spec = (XECPublicKeySpec) kf.getKeySpec(pub, XECPublicKeySpec.class);
        byte[] raw = spec.getU().toByteArray();
        // BigInteger.toByteArray 可能多一个 0 头，确保为 32 字节
        byte[] out = new byte[32];
        int srcLen = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - srcLen, out, 32 - srcLen, srcLen);
        return Base64Utils.encode(out);
    }

    private static byte[] kdf(byte[] sharedSecret) throws GeneralSecurityException {
        byte[] labelBytes = KDF_LABEL.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(labelBytes, "HmacSHA256"));
        byte[] derived = hmac.doFinal(sharedSecret);
        byte[] key = Arrays.copyOf(derived, AES_KEY_BYTES);
        Arrays.fill(derived, (byte) 0);
        return key;
    }

    public static final class EncryptedPayload {
        public final String clientPub;
        public final String iv;
        public final String ct;

        public EncryptedPayload(String clientPub, String iv, String ct) {
            this.clientPub = clientPub;
            this.iv = iv;
            this.ct = ct;
        }
    }
}
