/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.password.storage;

import com.iqcl.auth.IqclAuth;
import com.iqcl.auth.password.AccountRecord;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.UUID;

/**
 * SQLite 存储后端实现（默认）。
 * <p>
 * 使用 HikariCP 连接池（连接池大小固定为 1，SQLite 单写入特性使大池无收益）。
 * 表结构：
 * <pre>
 * CREATE TABLE iqclauth_accounts (
 *   uuid           VARCHAR(36) PRIMARY KEY,
 *   username       VARCHAR(64) NOT NULL,
 *   salt           BLOB NOT NULL,
 *   hash           BLOB NOT NULL,
 *   iterations     INTEGER NOT NULL,
 *   created_at_ms  BIGINT NOT NULL,
 *   updated_at_ms  BIGINT NOT NULL
 * );
 * CREATE INDEX idx_accounts_username ON iqclauth_accounts(username);
 * </pre>
 */
public final class SqliteAccountStorage implements AccountStorage {

    private static final String CREATE_TABLE_SQL =
            "CREATE TABLE IF NOT EXISTS iqclauth_accounts (" +
            "  uuid           VARCHAR(36) PRIMARY KEY," +
            "  username       VARCHAR(64) NOT NULL," +
            "  salt           BLOB NOT NULL," +
            "  hash           BLOB NOT NULL," +
            "  iterations     INTEGER NOT NULL," +
            "  created_at_ms  BIGINT NOT NULL," +
            "  updated_at_ms  BIGINT NOT NULL" +
            ")";

    private static final String CREATE_INDEX_SQL =
            "CREATE INDEX IF NOT EXISTS idx_accounts_username ON iqclauth_accounts(username)";

    private static final String SELECT_BY_UUID_SQL =
            "SELECT uuid, username, salt, hash, iterations, created_at_ms, updated_at_ms " +
            "FROM iqclauth_accounts WHERE uuid = ?";

    private static final String SELECT_BY_USERNAME_SQL =
            "SELECT uuid, username, salt, hash, iterations, created_at_ms, updated_at_ms " +
            "FROM iqclauth_accounts WHERE username = ?";

    private static final String INSERT_SQL =
            "INSERT INTO iqclauth_accounts " +
            "(uuid, username, salt, hash, iterations, created_at_ms, updated_at_ms) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?)";

    private static final String UPDATE_PASSWORD_SQL =
            "UPDATE iqclauth_accounts SET salt = ?, hash = ?, iterations = ?, updated_at_ms = ? " +
            "WHERE uuid = ?";

    private static final String DELETE_SQL =
            "DELETE FROM iqclauth_accounts WHERE uuid = ?";

    private static final String EXISTS_SQL =
            "SELECT 1 FROM iqclauth_accounts WHERE uuid = ?";

    private final HikariDataSource dataSource;

    /**
     * @param dbFile 数据库文件路径（如 config/iqclauth/passwords.db）
     */
    public SqliteAccountStorage(Path dbFile) throws Exception {
        // 显式加载驱动（旧版 JDBC 兼容）
        try {
            Class.forName("org.sqlite.JDBC");
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException("SQLite JDBC 驱动未找到，请检查 mod 是否包含 sqlite-jdbc 嵌套 JAR", e);
        }

        Path parent = dbFile.toAbsolutePath().getParent();
        if (parent != null && !Files.exists(parent)) {
            Files.createDirectories(parent);
        }

        HikariConfig config = new HikariConfig();
        config.setJdbcUrl("jdbc:sqlite:" + dbFile.toAbsolutePath().toString().replace('\\', '/'));
        config.setDriverClassName("org.sqlite.JDBC");
        // SQLite 单写入：连接池大小固定为 1，避免锁争用
        config.setMaximumPoolSize(1);
        config.setMinimumIdle(1);
        config.setConnectionTimeout(5000);
        config.setIdleTimeout(60000);
        config.setMaxLifetime(0);
        config.setPoolName("IQCLAuth-SQLite");
        // SQLite 连接初始化：开启 WAL 模式提升并发读，开启外键约束
        config.addDataSourceProperty("journal_mode", "WAL");
        config.addDataSourceProperty("foreign_keys", "true");
        config.addDataSourceProperty("busy_timeout", "5000");

        this.dataSource = new HikariDataSource(config);
        IqclAuth.LOGGER.info("[IQCL Auth] SQLite 存储后端已初始化: {}", dbFile);
    }

    @Override
    public void init() throws Exception {
        try (Connection conn = dataSource.getConnection();
             Statement stmt = conn.createStatement()) {
            stmt.execute(CREATE_TABLE_SQL);
            stmt.execute(CREATE_INDEX_SQL);
        }
    }

    @Override
    public void close() {
        if (dataSource != null && !dataSource.isClosed()) {
            dataSource.close();
            IqclAuth.LOGGER.info("[IQCL Auth] SQLite 存储后端已关闭");
        }
    }

    @Override
    public AccountRecord findByUuid(UUID uuid) throws Exception {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(SELECT_BY_UUID_SQL)) {
            ps.setString(1, uuid.toString());
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return mapRow(rs);
                }
            }
        }
        return null;
    }

    @Override
    public AccountRecord findByUsername(String username) throws Exception {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(SELECT_BY_USERNAME_SQL)) {
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return mapRow(rs);
                }
            }
        }
        return null;
    }

    @Override
    public void insert(AccountRecord record) throws Exception {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(INSERT_SQL)) {
            ps.setString(1, record.uuid.toString());
            ps.setString(2, record.username);
            ps.setBytes(3, record.salt);
            ps.setBytes(4, record.hash);
            ps.setInt(5, record.iterations);
            ps.setLong(6, record.createdAtMs);
            ps.setLong(7, record.updatedAtMs);
            int affected = ps.executeUpdate();
            if (affected == 0) {
                throw new StorageException("插入失败：0 行受影响");
            }
        } catch (Exception e) {
            // SQLite 主键冲突报错信息含 "UNIQUE constraint failed"
            String msg = e.getMessage();
            if (msg != null && msg.contains("UNIQUE constraint failed")) {
                throw new StorageException("账号已存在", e);
            }
            throw e;
        }
    }

    @Override
    public void updatePassword(UUID uuid, byte[] salt, byte[] hash, int iterations, long updatedAtMs) throws Exception {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(UPDATE_PASSWORD_SQL)) {
            ps.setBytes(1, salt);
            ps.setBytes(2, hash);
            ps.setInt(3, iterations);
            ps.setLong(4, updatedAtMs);
            ps.setString(5, uuid.toString());
            int affected = ps.executeUpdate();
            if (affected == 0) {
                throw new StorageException("更新失败：账号不存在");
            }
        }
    }

    @Override
    public void delete(UUID uuid) throws Exception {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(DELETE_SQL)) {
            ps.setString(1, uuid.toString());
            ps.executeUpdate();
        }
    }

    @Override
    public boolean exists(UUID uuid) throws Exception {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(EXISTS_SQL)) {
            ps.setString(1, uuid.toString());
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    /** 将结果集当前行映射为 AccountRecord。 */
    private static AccountRecord mapRow(ResultSet rs) throws Exception {
        return new AccountRecord(
                UUID.fromString(rs.getString("uuid")),
                rs.getString("username"),
                rs.getBytes("salt"),
                rs.getBytes("hash"),
                rs.getInt("iterations"),
                rs.getLong("created_at_ms"),
                rs.getLong("updated_at_ms")
        );
    }
}
