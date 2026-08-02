/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.network;

import net.minecraft.util.Identifier;

/**
 * 网络通道标识常量。
 * <p>
 * 使用 Fabric 1.20.1 自定义 Payload API（PayloadTypeRegistry + ServerPlayNetworking / ClientPlayNetworking）。
 */
public final class NetworkConstants {

    public static final String MOD_ID = "iqclauth";

    private NetworkConstants() {
    }

    /** 客户端 → 服务端：携带 RSA 加密后的 PIN 密文包（完整 JSON 字符串）。 */
    public static final Identifier C2S_VERIFY_ID = new Identifier(MOD_ID, "c2s_verify");

    /** 服务端 → 客户端：返回最终验签结果（成功/失败 + 消息）。 */
    public static final Identifier S2C_RESULT_ID = new Identifier(MOD_ID, "s2c_result");
}
