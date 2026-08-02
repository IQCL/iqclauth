/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth;

import com.iqcl.auth.config.ModConfig;
import com.iqcl.auth.server.ServerNetworkHandler;
import net.fabricmc.api.ModInitializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 模组主入口（main entrypoint）。
 * <p>
 * 在客户端与服务端（含内置服务端）均执行：
 * <ul>
 *   <li>加载配置；</li>
 *   <li>注册服务端数据包接收器（处理客户端密文转发请求）。</li>
 * </ul>
 * 客户端专属逻辑（聊天拦截、RSA 加密）在 client entrypoint 中初始化。
 * <p>
 * Fabric 1.20.1 使用基于 Identifier + PacketByteBuf 的旧版 Networking API v1，
 * 无需 PayloadTypeRegistry 注册。
 */
public class IqclAuth implements ModInitializer {

    public static final String MOD_ID = "iqclauth";
    public static final Logger LOGGER = LoggerFactory.getLogger("IQCLAuth");

    @Override
    public void onInitialize() {
        LOGGER.info("[IQCL Auth] 初始化（公共/服务端侧）...");

        // 加载服务端配置（验证服务器地址 + X-Server-Key）
        ModConfig.load();

        // 注册服务端接收器：在专用服务端与内置服务端均生效
        ServerNetworkHandler.register();

        LOGGER.info("[IQCL Auth] 初始化完成");
    }
}
