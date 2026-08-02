/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.crypto;

import java.security.SecureRandom;

/**
 * 随机 nonce 生成器。
 * 生成 32 位十六进制随机字符串（16 字节随机数 → 32 个 hex 字符），用于防重放。
 */
public final class HexNonceGenerator {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private HexNonceGenerator() {
    }

    /**
     * 生成 32 位小写十六进制 nonce。
     * 16 字节随机数 → 32 hex 字符，碰撞概率可忽略，满足防重放要求。
     */
    public static String generate32Hex() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        char[] out = new char[32];
        for (int i = 0; i < 16; i++) {
            out[i * 2] = HEX[(bytes[i] >> 4) & 0xF];
            out[i * 2 + 1] = HEX[bytes[i] & 0xF];
        }
        return new String(out);
    }
}
