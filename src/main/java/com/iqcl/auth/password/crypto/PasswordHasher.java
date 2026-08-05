/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.password.crypto;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * 密码哈希工具：PBKDF2WithHmacSHA256。
 * <p>
 * 自主实现，不依赖 BouncyCastle。算法由 JDK 17 内置 SunJCE 提供。
 * <ul>
 *   <li>哈希算法：PBKDF2-HMAC-SHA256</li>
 *   <li>输出长度：256 位（32 字节）</li>
 *   <li>盐长度：可配置（建议 16 字节）</li>
 *   <li>迭代次数：可配置（建议 ≥ 100000）</li>
 * </ul>
 * 安全要点：
 * <ul>
 *   <li>密码使用 {@code char[]} 承载，调用方负责 {@link #zero(char[])} 清零</li>
 *   <li>{@link #verify(char[], byte[], byte[], int)} 使用 {@link MessageDigest#isEqual}
 *       做常量时间比较，防时序攻击</li>
 * </ul>
 */
public final class PasswordHasher {

    /** PBKDF2 算法名（JDK 内置）。 */
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";

    /** 输出哈希位数（固定 256 位 = 32 字节）。 */
    private static final int HASH_BITS = 256;

    private PasswordHasher() {
    }

    /**
     * 哈希密码。
     *
     * @param password   密码字符数组（调用后由调用方清零）
     * @param iterations 迭代次数（来自配置）
     * @param saltBytes  盐长度（来自配置）
     * @return 哈希结果（含 salt/hash/iterations）
     */
    public static HashResult hash(char[] password, int iterations, int saltBytes) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("password must not be empty");
        }
        if (iterations < 1000) {
            throw new IllegalArgumentException("iterations too low: " + iterations);
        }
        byte[] salt = SaltGenerator.generate(saltBytes);
        byte[] hash = derive(password, salt, iterations);
        return new HashResult(salt, hash, iterations);
    }

    /**
     * 验证密码是否匹配已有 salt+hash+iterations。
     * <p>
     * 使用 {@link MessageDigest#isEqual} 做常量时间比较，防止时序攻击。
     *
     * @param password   待验证密码（调用后由调用方清零）
     * @param salt       已存储的盐
     * @param hash       已存储的哈希
     * @param iterations 已存储的迭代次数
     * @return true = 匹配，false = 不匹配
     */
    public static boolean verify(char[] password, byte[] salt, byte[] hash, int iterations) {
        if (password == null || salt == null || hash == null) {
            return false;
        }
        try {
            byte[] derived = derive(password, salt, iterations);
            return MessageDigest.isEqual(derived, hash);
        } catch (Exception e) {
            return false;
        }
    }

    /** 内部：PBKDF2 派生。 */
    private static byte[] derive(char[] password, byte[] salt, int iterations) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, HASH_BITS);
            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
                return factory.generateSecret(spec).getEncoded();
            } finally {
                spec.clearPassword();
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("PBKDF2 derive failed: " + e.getMessage(), e);
        }
    }

    /** 清零密码字符数组（容错）。 */
    public static void zero(char[] password) {
        if (password != null) Arrays.fill(password, '\0');
    }

    /** 哈希结果载体。 */
    public static final class HashResult {
        public final byte[] salt;
        public final byte[] hash;
        public final int iterations;

        public HashResult(byte[] salt, byte[] hash, int iterations) {
            this.salt = salt;
            this.hash = hash;
            this.iterations = iterations;
        }
    }
}
