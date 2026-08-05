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
            "  updated_at_ms  BIGINT NOT NULL," +
            "  totp_enabled   INTEGER NOT NULL DEFAULT 0," +
            "  totp_secret    VARCHAR(64)," +
            "  totp_last_code VARCHAR(16)" +
            ")";

    private static final String MIGRATE_TOTP_SQL =
            "ALTER TABLE iqclauth_accounts ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0";
    private static final String MIGRATE_TOTP_SECRET_SQL =
            "ALTER TABLE iqclauth_accounts ADD COLUMN totp_secret VARCHAR(64)";
    private static final String MIGRATE_TOTP_LAST_CODE_SQL =
            "ALTER TABLE iqclauth_accounts ADD COLUMN totp_last_code VARCHAR(16)";

    private static final String CREATE_INDEX_SQL =
            "CREATE INDEX IF NOT EXISTS idx_accounts_username ON iqclauth_accounts(username)";

    private static final String SELECT_BY_UUID_SQL =
            "SELECT uuid, username, salt, hash, iterations, created_at_ms, updated_at_ms, " +
            "totp_enabled, totp_secret, totp_last_code " +
            "FROM iqclauth_accounts WHERE uuid = ?";

    private static final String SELECT_BY_USERNAME_SQL =
            "SELECT uuid, username, salt, hash, iterations, created_at_ms, updated_at_ms, " +
            "totp_enabled, totp_secret, totp_last_code " +
            "FROM iqclauth_accounts WHERE username = ?";

    private static final String INSERT_SQL =
            "INSERT INTO iqclauth_accounts " +
            "(uuid, username, salt, hash, iterations, created_at_ms, updated_at_ms, " +
            "totp_enabled, totp_secret, totp_last_code) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    private static final String UPDATE_PASSWORD_SQL =
            "UPDATE iqclauth_accounts SET salt = ?, hash = ?, iterations = ?, updated_at_ms = ? " +
            "WHERE uuid = ?";

    private static final String UPDATE_TOTP_SQL =
            "UPDATE iqclauth_accounts SET totp_enabled = ?, totp_secret = ?, totp_last_code = ?, " +
            "updated_at_ms = ? WHERE uuid = ?";

    private static final String UPDATE_TOTP_LAST_CODE_SQL =
            "UPDATE iqclauth_accounts SET totp_last_code = ? WHERE uuid = ?";

    private static final String DELETE_SQL =
            "DELETE FROM iqclauth_accounts WHERE uuid = ?";

    private static final String EXISTS_SQL =
            "SELECT 1 FROM iqclauth_accounts WHERE uuid = ?";

    private final HikariDataSource dataSource;

    public SqliteAccountStorage(Path dbFile) throws Exception {
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
        config.setMaximumPoolSize(1);
        config.setMinimumIdle(1);
        config.setConnectionTimeout(5000);
        config.setIdleTimeout(60000);
        config.setMaxLifetime(0);
        config.setPoolName("IQCLAuth-SQLite");
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
            // 迁移：旧表可能没有 TOTP 列
            migrateColumnIfMissing(stmt, "totp_enabled", MIGRATE_TOTP_SQL);
            migrateColumnIfMissing(stmt, "totp_secret", MIGRATE_TOTP_SECRET_SQL);
            migrateColumnIfMissing(stmt, "totp_last_code", MIGRATE_TOTP_LAST_CODE_SQL);
        }
    }

    private void migrateColumnIfMissing(Statement stmt, String column, String alterSql) {
        try {
            stmt.execute(alterSql);
            IqclAuth.LOGGER.info("[IQCL Auth] SQLite 迁移：添加列 {}", column);
        } catch (Exception e) {
            // 列已存在，忽略
            if (!e.getMessage().contains("duplicate column")
                    && !e.getMessage().contains("already exists")) {
                IqclAuth.LOGGER.warn("[IQCL Auth] SQLite 迁移列 {} 失败: {}", column, e.getMessage());
            }
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
                if (rs.next()) return mapRow(rs);
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
                if (rs.next()) return mapRow(rs);
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
            ps.setInt(8, record.totpEnabled ? 1 : 0);
            ps.setString(9, record.totpSecret);
            ps.setString(10, record.totpLastCode);
            int affected = ps.executeUpdate();
            if (affected == 0) throw new StorageException("插入失败：0 行受影响");
        } catch (Exception e) {
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
            if (affected == 0) throw new StorageException("更新失败：账号不存在");
        }
    }

    @Override
    public void updateTotp(UUID uuid, boolean enabled, String secret, String lastCode, long updatedAtMs)
            throws Exception {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(UPDATE_TOTP_SQL)) {
            ps.setInt(1, enabled ? 1 : 0);
            ps.setString(2, secret);
            ps.setString(3, lastCode);
            ps.setLong(4, updatedAtMs);
            ps.setString(5, uuid.toString());
            int affected = ps.executeUpdate();
            if (affected == 0) throw new StorageException("更新 TOTP 失败：账号不存在");
        }
    }

    @Override
    public void updateTotpLastCode(UUID uuid, String lastCode) throws Exception {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(UPDATE_TOTP_LAST_CODE_SQL)) {
            ps.setString(1, lastCode);
            ps.setString(2, uuid.toString());
            ps.executeUpdate();
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

    private static AccountRecord mapRow(ResultSet rs) throws Exception {
        boolean totpEnabled = rs.getInt("totp_enabled") != 0;
        String totpSecret = rs.getString("totp_secret");
        String totpLastCode = rs.getString("totp_last_code");
        return new AccountRecord(
                UUID.fromString(rs.getString("uuid")),
                rs.getString("username"),
                rs.getBytes("salt"),
                rs.getBytes("hash"),
                rs.getInt("iterations"),
                rs.getLong("created_at_ms"),
                rs.getLong("updated_at_ms"),
                totpEnabled, totpSecret, totpLastCode
        );
    }
}
