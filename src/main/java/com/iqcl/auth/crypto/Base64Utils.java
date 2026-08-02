/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.crypto;

import java.util.Base64;

/**
 * Base64 编解码工具。
 * 使用 JDK 标准 Base64（非 MIME、非 URL-safe），与验证服务器约定一致。
 */
public final class Base64Utils {

    private Base64Utils() {
    }

    /** 将字节数组编码为标准 Base64 字符串（带填充，无换行）。 */
    public static String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    /** 将标准 Base64 字符串解码为字节数组。 */
    public static byte[] decode(String base64) {
        return Base64.getDecoder().decode(base64);
    }
}
