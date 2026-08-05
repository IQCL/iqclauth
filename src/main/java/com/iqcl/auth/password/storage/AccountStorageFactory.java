/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.password.storage;

import com.iqcl.auth.config.ModConfig;
import net.fabricmc.loader.api.FabricLoader;

import java.nio.file.Path;

/**
 * 存储后端工厂。
 * <p>
 * 按 {@link ModConfig.PasswordStorageConfig#backend} 创建对应实现。
 * 阶段 1 仅支持 SQLite；阶段 3 扩展 MySQL/PostgreSQL/MongoDB。
 */
public final class AccountStorageFactory {

    private AccountStorageFactory() {
    }

    /**
     * 创建存储后端实例。
     *
     * @param cfg 存储配置
     * @return 已初始化（未 {@link AccountStorage#init()}）的存储实例
     * @throws Exception 创建失败
     */
    public static AccountStorage create(ModConfig.PasswordStorageConfig cfg) throws Exception {
        String backend = cfg.backend == null ? "sqlite" : cfg.backend.toLowerCase().trim();
        switch (backend) {
            case "sqlite":
                return createSqlite(cfg);
            case "mysql":
            case "mariadb":
                return new MysqlAccountStorage(cfg);
            case "postgres":
            case "postgresql":
                return new PostgresAccountStorage(cfg);
            case "mongo":
            case "mongodb":
                return new MongoAccountStorage(cfg);
            default:
                throw new IllegalArgumentException("未知存储后端: " + backend);
        }
    }

    private static AccountStorage createSqlite(ModConfig.PasswordStorageConfig cfg) throws Exception {
        Path dbFile;
        if (cfg.sqliteFile == null || cfg.sqliteFile.isEmpty()) {
            dbFile = FabricLoader.getInstance().getConfigDir()
                    .resolve("iqclauth").resolve("passwords.db");
        } else {
            // 支持相对路径（相对游戏根目录）与绝对路径
            String p = cfg.sqliteFile.replace('/', java.io.File.separatorChar);
            dbFile = java.nio.file.Paths.get(p);
            if (!dbFile.isAbsolute()) {
                dbFile = FabricLoader.getInstance().getGameDir().resolve(p);
            }
        }
        return new SqliteAccountStorage(dbFile);
    }
}
