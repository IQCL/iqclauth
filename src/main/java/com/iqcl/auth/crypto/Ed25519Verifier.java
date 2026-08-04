/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.crypto;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;

/**
 * Ed25519 验签工具（仅服务端使用）。
 * <p>
 * 【硬性安全规则】Ed25519 仅用于下行（验证服务器 → MC 服务端）签名验签，
 * 严禁与 RSA 混用、严禁用于加密。
 * <p>
 * 本实现基于 JDK 17 原生 JCE（Ed25519 Signature），不依赖 BouncyCastle，
 * 彻底避免 Fabric 嵌套 JAR 环境下的 JCE Provider 签名认证问题。
 * <p>
 * 公钥为硬编码 raw 32 字节 base64，禁止修改。
 */
public final class Ed25519Verifier {

    /**
     * 硬编码 Ed25519 公钥（raw 32 字节，base64 编码）。禁止修改。
     * 用于验证远程验证服务器对下行响应 payload 的 Ed25519 签名。
     */
    public static final String ED25519_PUBKEY_BASE64 = "mQppG3om4W7A8PQ1e5knrkFAQaOdiWdHEuPrsIYlnIk=";

    /** 解码后的原始 32 字节公钥。 */
    private static final byte[] RAW_PUBLIC_KEY;

    private static final PublicKey PUBLIC_KEY;

    static {
        RAW_PUBLIC_KEY = Base64Utils.decode(ED25519_PUBKEY_BASE64);
        if (RAW_PUBLIC_KEY.length != 32) {
            throw new RuntimeException("Ed25519 public key must be 32 bytes, got " + RAW_PUBLIC_KEY.length);
        }
        try {
            PUBLIC_KEY = decodeEd25519PublicKey(RAW_PUBLIC_KEY);
        } catch (Exception e) {
            throw new RuntimeException("Ed25519 公钥初始化失败", e);
        }
    }

    private Ed25519Verifier() {
    }

    /**
     * 预热：触发静态初始化并预实例化 Signature 引擎。
     * <p>
     * 在服务端启动时调用，可提前暴露 JDK 不支持 Ed25519 等问题，
     * 防止首次 verify 调用时抛 {@link ExceptionInInitializerError} 被吞。
     */
    public static void warmup() {
        // 访问 PUBLIC_KEY 字段触发类初始化
        @SuppressWarnings("unused")
        PublicKey ignored = PUBLIC_KEY;
    }

    /**
     * 从 raw 32 字节解码 Ed25519 公钥为 JCE {@link PublicKey} 对象。
     * <p>
     * JDK 17 的 Ed25519 KeyFactory 接受 X509 格式的 DER 编码公钥，
     * 因此需要将 raw 32 字节包装为 X509 SubjectPublicKeyInfo 结构。
     */
    private static PublicKey decodeEd25519PublicKey(byte[] rawKey) throws Exception {
        // Ed25519 OID: 1.3.101.112
        byte[] algId = {0x06, 0x03, 0x2B, 0x65, 0x70};

        // SubjectPublicKeyInfo DER 结构:
        // SEQUENCE {
        //   AlgorithmIdentifier SEQUENCE { OID 1.3.101.112 }
        //   BIT STRING { unused-bits=0, 32-byte key }
        // }
        int keyLen = rawKey.length; // 32
        int aiTotal = 2 + algId.length; // AlgorithmIdentifier: 2-byte SEQUENCE header + 5-byte OID = 7
        int bsTotal = 2 + 1 + keyLen;   // BIT STRING: 2-byte header + 1 unused byte + 32 key bytes = 35
        int spkiLen = 2 + aiTotal + bsTotal; // outer SEQ header + AI + BS = 2 + 7 + 35 = 44

        byte[] spki = new byte[spkiLen];
        int pos = 0;
        spki[pos++] = 0x30; // SEQUENCE tag
        spki[pos++] = (byte) (spkiLen - 2); // length

        spki[pos++] = 0x30; // AlgorithmIdentifier SEQUENCE tag
        spki[pos++] = (byte) (aiTotal - 2); // length: algId.length = 5
        System.arraycopy(algId, 0, spki, pos, algId.length);
        pos += algId.length;

        spki[pos++] = 0x03; // BIT STRING tag
        spki[pos++] = (byte) (bsTotal - 2); // length: 1 + 32 = 33
        spki[pos++] = 0x00; // unused bits count
        System.arraycopy(rawKey, 0, spki, pos, keyLen);

        return KeyFactory.getInstance("Ed25519")
                .generatePublic(new java.security.spec.X509EncodedKeySpec(spki));
    }

    /**
     * 验证 Ed25519 签名。
     *
     * @param message   待验签的原始消息字节（应为规范化 JSON 的 UTF-8 字节）
     * @param signature 64 字节 Ed25519 签名
     * @return true 表示验签通过，false 表示验签失败
     */
    public static boolean verify(byte[] message, byte[] signature) throws Exception {
        if (signature == null || signature.length != 64) {
            return false;
        }
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(PUBLIC_KEY);
        verifier.update(message);
        return verifier.verify(signature);
    }
}
