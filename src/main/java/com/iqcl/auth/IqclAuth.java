/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth;

import com.iqcl.auth.config.ModConfig;
import com.iqcl.auth.password.PasswordManager;
import com.iqcl.auth.password.crypto.ServerKeyStore;
import com.iqcl.auth.password.net.PasswordNetworkHandler;
import com.iqcl.auth.server.CommandRegistry;
import com.iqcl.auth.server.PlayerRestrictionManager;
import com.iqcl.auth.server.ServerNetworkHandler;
import net.fabricmc.api.ModInitializer;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerLifecycleEvents;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 模组主入口（main entrypoint）。
 * <p>
 * 在客户端与服务端（含内置服务端）均执行：
 * <ul>
 *   <li>加载配置；</li>
 *   <li>注册指令（{@code /iqcl login pin <pin>} 与 {@code /iqcl login password <密码>} 等）；</li>
 *   <li>注册服务端数据包接收器（处理客户端密文转发请求）；</li>
 *   <li>注册玩家行为限制器（未登录限制移动/破坏 + 超时踢出）；</li>
 *   <li>初始化密码登录存储后端（SQLite/MySQL/PostgreSQL/MongoDB）。</li>
 * </ul>
 */
public class IqclAuth implements ModInitializer {

    public static final String MOD_ID = "iqclauth";
    public static final Logger LOGGER = LoggerFactory.getLogger("IQCLAuth");

    @Override
    public void onInitialize() {
        LOGGER.info("[IQCL Auth] 初始化（公共/服务端侧）...");

        // 加载服务端配置
        ModConfig.load();

        // 注册 /iqcl 指令（支持 Tab 补全，不限管理员）
        CommandRegistry.register();

        // 注册服务端数据包接收器（密文转发 + 验签）
        ServerNetworkHandler.register();

        // 注册玩家行为限制器（未登录限制移动/破坏 + 超时踢出）
        PlayerRestrictionManager.register();

        // 初始化密码登录存储后端 + 异步执行器
        PasswordManager.init();

        // 初始化服务端 X25519 密钥对（用于客户端→服务端密码密文 ECDH 密钥交换）
        ServerKeyStore.init();

        // 注册密码密文包接收器
        PasswordNetworkHandler.register();

        // 服务端停机时关闭密码存储连接池
        ServerLifecycleEvents.SERVER_STOPPING.register(server -> {
            LOGGER.info("[IQCL Auth] 服务端停机，关闭密码存储后端...");
            PasswordManager.shutdown();
        });

        LOGGER.info("[IQCL Auth] 初始化完成");
    }
}
