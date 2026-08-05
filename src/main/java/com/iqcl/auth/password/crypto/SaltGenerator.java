/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.password.crypto;

import java.security.SecureRandom;

/**
 * 密码盐生成器。
 * <p>
 * 使用 JDK 内置 {@link SecureRandom}（默认 SHA1PRNG 或 Nashorn 提供的强随机源）。
 * 单例实例化 {@link SecureRandom} 避免重复初始化开销。
 */
public final class SaltGenerator {

    private static final SecureRandom RANDOM = new SecureRandom();

    private SaltGenerator() {
    }

    /**
     * 生成指定长度的随机盐。
     *
     * @param bytes 盐字节数，建议 ≥ 16
     * @return 随机盐字节数组
     */
    public static byte[] generate(int bytes) {
        if (bytes <= 0) {
            throw new IllegalArgumentException("salt bytes must be positive: " + bytes);
        }
        byte[] salt = new byte[bytes];
        RANDOM.nextBytes(salt);
        return salt;
    }
}
