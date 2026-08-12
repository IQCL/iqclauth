/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth;

import com.iqcl.auth.config.ModConfig;
import com.iqcl.auth.password.PasswordManager;
import com.iqcl.auth.context.LuckPermsContextProvider;
import com.iqcl.auth.password.crypto.ServerKeyStore;
import com.iqcl.auth.password.net.PasswordNetworkHandler;
import com.iqcl.auth.server.CommandRegistry;
import com.iqcl.auth.server.PlayerRestrictionManager;
import com.iqcl.auth.server.ServerNetworkHandler;
import net.fabricmc.api.EnvType;
import net.fabricmc.api.ModInitializer;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerLifecycleEvents;
import net.fabricmc.loader.api.FabricLoader;
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

    private static boolean clientEnvironment;

    /** 是否运行在客户端环境（单人游戏/联机模式）。 */
    public static boolean isClientEnvironment() {
        return clientEnvironment;
    }

    @Override
    public void onInitialize() {
        EnvType envType = FabricLoader.getInstance().getEnvironmentType();
        clientEnvironment = (envType == EnvType.CLIENT);

        if (clientEnvironment) {
            LOGGER.warn("[IQCL Auth] 检测到客户端环境（单人游戏/联机模式）");
            LOGGER.warn("[IQCL Auth] IQCL Auth 登录功能仅在安装了该模组的专用服务器上可用");
            LOGGER.warn("[IQCL Auth] 已跳过服务端限制器、密码存储、网络处理器注册");

            ModConfig.load();

            ServerLifecycleEvents.SERVER_STOPPING.register(server ->
                    LOGGER.info("[IQCL Auth] 服务端停机"));

            return;
        }

        // === 专用服务器模式 ===
        LOGGER.info("[IQCL Auth] 初始化（专用服务端）...");

        ModConfig.load();

        // 配置完整性检查：apiId + apiKey 成套鉴权（API 文档 2.3 节）
        ModConfig loadedConfig = ModConfig.get();
        boolean apiIdConfigured = loadedConfig.apiId != null && !loadedConfig.apiId.isEmpty()
                && !loadedConfig.apiId.startsWith("REPLACE_WITH");
        boolean apiKeyConfigured = loadedConfig.apiKey != null && !loadedConfig.apiKey.isEmpty()
                && !loadedConfig.apiKey.startsWith("REPLACE_WITH");
        if (apiIdConfigured && apiKeyConfigured) {
            LOGGER.info("[IQCL Auth] 鉴权模式：apiId + apiKey 成套模式（X-Api-Id + X-Api-Key）");
        } else if (apiIdConfigured || apiKeyConfigured) {
            LOGGER.warn("[IQCL Auth] apiId/apiKey 未成套配置！成套模式需同时提供两者，"
                    + "当前将回退使用 X-Server-Key。请在 config/iqclauth.json 中补全 apiId 和 apiKey");
        } else {
            LOGGER.warn("[IQCL Auth] apiId/apiKey 均未配置，将回退使用 X-Server-Key 鉴权（存量旧密钥兼容模式）。"
                    + "建议在 config/iqclauth.json 中配置 mc_login 用途的 apiId + apiKey 以启用成套鉴权");
        }

        CommandRegistry.register();
        ServerNetworkHandler.register();
        PlayerRestrictionManager.register();
        PasswordManager.init();
        LuckPermsContextProvider.register();
        ServerKeyStore.init();
        PasswordNetworkHandler.register();

        ServerLifecycleEvents.SERVER_STOPPING.register(server -> {
            LOGGER.info("[IQCL Auth] 服务端停机，关闭密码存储后端...");
            PasswordManager.shutdown();
        });

        LOGGER.info("[IQCL Auth] 初始化完成");
    }
}
