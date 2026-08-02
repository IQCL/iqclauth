/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * RSA-OAEP 加密工具（仅客户端使用）。
 * <p>
 * 【硬性安全规则】上行通道仅使用 RSA-OAEP-2048 + SHA-256，全程不使用任何对称加密。
 * RSA 公钥硬编码于此，禁止修改。
 * <p>
 * 加密参数（不可改动）：
 * <ul>
 *   <li>算法：RSA</li>
 *   <li>模式：ECB（即单块加密，OAEP 填充自带随机性）</li>
 *   <li>填充：OAEPWithSHA-256AndMGF1Padding</li>
 *   <li>OAEP 哈希：SHA-256</li>
 *   <li>MGF1 哈希：SHA-256（必须显式设置，JCE 默认为 SHA-1 会导致与验证服务器不互通）</li>
 *   <li>Label：空（PSource.PSpecified.DEFAULT）</li>
 * </ul>
 */
public final class RsaOaepEncryptor {

    /**
     * 硬编码 RSA SPKI 公钥（base64，无 PEM 头尾）。禁止修改。
     * RSA-2048，用于客户端加密 PIN 明文。
     */
    public static final String RSA_SPKI_BASE64 =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArzt7zicBvZqetxjcNkWoO9MNcdp/Cf9JAhPJmdm4kDoR6S45fcLzbUP66jGuUYcTUUrpH/cc3JOuLIp03hFgvTe+FnwqMDsAiV4qUN9uv4sg86K4WicuOImNBgzQy0IpuXW3UmQPvsbi1DKWL/p21W9/3/EzgFLCDS8BQgOTUY4GRfFEH8Qn6/KsFUKbdCCs240ShfilEXrGVuTyI0zz3nct74gjR3OmHt/gTMbCMb76ZiX19WQnIzP6q0GewGFcAroYZtcHeaK/BGuFUWo+iG5rwxJSjrk8vK8ofHDPFY0ZHmihQ97xZyG6FoTKi/FFUf/znvgVLCibRietEugB1wIDAQAB";

    private static final PublicKey PUBLIC_KEY;

    static {
        try {
            // 注册 BouncyCastle 作为 JCE Provider
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
            byte[] der = Base64Utils.decode(RSA_SPKI_BASE64);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
            PUBLIC_KEY = KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private RsaOaepEncryptor() {
    }

    /**
     * RSA-OAEP-2048 加密。
     * <p>
     * 【安全】这是 PIN 明文的唯一加密路径，输出 256 字节密文（base64 后约 344 字符）。
     * 全程纯非对称加密，无对称加密参与。
     *
     * @param plaintext 待加密的明文字节（UTF-8 编码的 JSON）
     * @return RSA 密文字节（256 字节）
     */
    public static byte[] encrypt(byte[] plaintext) throws Exception {
        // SECURITY: MGF1 必须显式指定为 SHA-256。
        // JCE 对 "RSA/ECB/OAEPWithSHA-256AndMGF1Padding" 的 MGF1 默认使用 SHA-1，
        // 若不显式设置会导致与验证服务器（使用 SHA-256 MGF1）解密失败。
        OAEPParameterSpec oaepParams = new OAEPParameterSpec(
                "SHA-256",       // OAEP 哈希算法
                "MGF1",          // 掩码生成函数
                MGF1ParameterSpec.SHA256,  // MGF1 哈希（关键：与 OAEP 哈希一致）
                PSource.PSpecified.DEFAULT  // Label 为空
        );
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, PUBLIC_KEY, oaepParams);
        return cipher.doFinal(plaintext);
    }
}
