/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.config;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.iqcl.auth.IqclAuth;
import net.fabricmc.loader.api.FabricLoader;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * 模组配置。
 * <p>
 * 使用 FabricLoader 的 config 目录，JSON 格式存储。
 * 配置文件位于 {@code config/iqclauth.json}，首次启动自动生成。
 * <p>
 * 仅服务端使用（含内置服务端）：存放 X-Server-Key。
 * 验证服务器 API 地址为硬编码常量，不可修改。
 */
public class ModConfig {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private static final Path CONFIG_PATH =
            FabricLoader.getInstance().getConfigDir().resolve("iqclauth.json");

    /**
     * 远程验证服务器 API 地址（POST /api/verify-pin）。
     * <p>
     * 【硬编码常量】禁止修改，防止被篡改指向恶意服务器。
     */
    public static final String VERIFY_API_URL = "https://www.iqcl.de5.net/api/verify-pin";

    /** 服务端身份密钥，作为 X-Server-Key 请求头发送给验证服务器。 */
    public String serverKey = "REPLACE_WITH_YOUR_X_SERVER_KEY";

    private static volatile ModConfig instance;

    /** 获取配置单例，首次调用时自动加载。 */
    public static ModConfig get() {
        if (instance == null) {
            load();
        }
        return instance;
    }

    /** 从磁盘加载配置；文件不存在则生成默认配置并写盘。 */
    public static synchronized void load() {
        try {
            if (Files.exists(CONFIG_PATH)) {
                ModConfig loaded = GSON.fromJson(Files.readString(CONFIG_PATH), ModConfig.class);
                instance = (loaded != null) ? loaded : new ModConfig();
            } else {
                instance = new ModConfig();
                save();
                IqclAuth.LOGGER.info("Generated default config at {}", CONFIG_PATH);
            }
        } catch (IOException e) {
            IqclAuth.LOGGER.error("Failed to load config, using defaults", e);
            instance = new ModConfig();
        }
    }

    /** 将当前配置写盘。 */
    public static synchronized void save() {
        try {
            ModConfig toSave = (instance != null) ? instance : new ModConfig();
            Files.writeString(CONFIG_PATH, GSON.toJson(toSave));
        } catch (IOException e) {
            IqclAuth.LOGGER.error("Failed to save config", e);
        }
    }
}
