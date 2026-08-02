/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.crypto;

import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

/**
 * Ed25519 验签工具（仅服务端使用）。
 * <p>
 * 【硬性安全规则】Ed25519 仅用于下行（验证服务器 → MC 服务端）签名验签，
 * 严禁与 RSA 混用、严禁用于加密。
 * <p>
 * 实现遵循 RFC 8032，使用 BouncyCastle 低层 API（Ed25519Signer），
 * 不依赖 JCE Provider 注册。
 * <p>
 * 公钥为硬编码 raw 32 字节 base64，禁止修改。
 */
public final class Ed25519Verifier {

    /**
     * 硬编码 Ed25519 公钥（raw 32 字节，base64 编码）。禁止修改。
     * 用于验证远程验证服务器对下行响应 payload 的 Ed25519 签名。
     */
    public static final String ED25519_PUBKEY_BASE64 = "mQppG3om4W7A8PQ1e5knrkFAQaOdiWdHEuPrsIYlnIk=";

    private static final Ed25519PublicKeyParameters PUBLIC_KEY_PARAMS;

    static {
        // Ed25519 公钥为 raw 32 字节，直接解码即可
        byte[] raw = Base64Utils.decode(ED25519_PUBKEY_BASE64);
        if (raw.length != 32) {
            throw new ExceptionInInitializerError(
                    "Ed25519 public key must be 32 bytes, got " + raw.length);
        }
        PUBLIC_KEY_PARAMS = new Ed25519PublicKeyParameters(raw, 0);
    }

    private Ed25519Verifier() {
    }

    /**
     * 验证 Ed25519 签名。
     *
     * @param message   待验签的原始消息字节（应为规范化 JSON 的 UTF-8 字节）
     * @param signature 64 字节 Ed25519 签名
     * @return true 表示验签通过，false 表示验签失败
     */
    public static boolean verify(byte[] message, byte[] signature) throws Exception {
        Signer verifier = new Ed25519Signer();
        // false = 验签模式
        verifier.init(false, PUBLIC_KEY_PARAMS);
        verifier.update(message, 0, message.length);
        return verifier.verifySignature(signature);
    }
}
