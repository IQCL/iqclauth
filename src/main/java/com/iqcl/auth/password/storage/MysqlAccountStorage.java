/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.password.storage;

import com.iqcl.auth.IqclAuth;
import com.iqcl.auth.config.ModConfig;
import com.iqcl.auth.password.AccountRecord;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.UUID;

/**
 * MySQL/MariaDB 存储后端实现。
 * <p>
 * 依赖：{@code com.mysql:mysql-connector-j} 嵌套 JAR（需通过 Gradle {@code include}）。
 * 表结构同 SQLite，列类型映射：BLOB → VARBINARY(255)，VARCHAR(36) → VARCHAR(36)。
 */
public final class MysqlAccountStorage implements AccountStorage {

    private static final String CREATE_TABLE_SQL =
            "CREATE TABLE IF NOT EXISTS __prefix__accounts (" +
            "  uuid           VARCHAR(36) PRIMARY KEY," +
            "  username       VARCHAR(64) NOT NULL," +
            "  salt           VARBINARY(255) NOT NULL," +
            "  hash           VARBINARY(255) NOT NULL," +
            "  iterations     INT NOT NULL," +
            "  created_at_ms  BIGINT NOT NULL," +
            "  updated_at_ms  BIGINT NOT NULL," +
            "  totp_enabled   TINYINT(1) NOT NULL DEFAULT 0," +
            "  totp_secret    VARCHAR(64)," +
            "  totp_last_code VARCHAR(16)" +
            ")";

    private static final String CREATE_INDEX_SQL =
            "CREATE INDEX IF NOT EXISTS __prefix__idx_accounts_username ON __prefix__accounts(username)";

    private static final String SELECT_BY_UUID_SQL =
            "SELECT uuid, username, salt, hash, iterations, created_at_ms, updated_at_ms, " +
            "totp_enabled, totp_secret, totp_last_code " +
            "FROM __prefix__accounts WHERE uuid = ?";

    private static final String SELECT_BY_USERNAME_SQL =
            "SELECT uuid, username, salt, hash, iterations, created_at_ms, updated_at_ms, " +
            "totp_enabled, totp_secret, totp_last_code " +
            "FROM __prefix__accounts WHERE username = ?";

    private static final String INSERT_SQL =
            "INSERT INTO __prefix__accounts " +
            "(uuid, username, salt, hash, iterations, created_at_ms, updated_at_ms, " +
            "totp_enabled, totp_secret, totp_last_code) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    private static final String UPDATE_PASSWORD_SQL =
            "UPDATE __prefix__accounts SET salt = ?, hash = ?, iterations = ?, updated_at_ms = ? WHERE uuid = ?";

    private static final String UPDATE_TOTP_SQL =
            "UPDATE __prefix__accounts SET totp_enabled = ?, totp_secret = ?, totp_last_code = ?, " +
            "updated_at_ms = ? WHERE uuid = ?";

    private static final String UPDATE_TOTP_LAST_CODE_SQL =
            "UPDATE __prefix__accounts SET totp_last_code = ? WHERE uuid = ?";

    private static final String DELETE_SQL = "DELETE FROM __prefix__accounts WHERE uuid = ?";

    private static final String EXISTS_SQL = "SELECT 1 FROM __prefix__accounts WHERE uuid = ?";

    private final HikariDataSource dataSource;
    private final String tableName;

    public MysqlAccountStorage(ModConfig.PasswordStorageConfig cfg) throws Exception {
        String prefix = cfg.mysqlTablePrefix != null ? cfg.mysqlTablePrefix : "";
        this.tableName = prefix + "accounts";

        String jdbcUrl = "jdbc:mysql://" + cfg.mysqlHost + ":" + cfg.mysqlPort + "/" + cfg.mysqlDatabase
                + "?useSSL=" + cfg.mysqlUseSsl
                + "&requireSSL=" + cfg.mysqlUseSsl
                + "&serverTimezone=UTC"
                + "&useUnicode=true&characterEncoding=utf8"
                + "&useJDBCCompliantTimezoneShift=true&useLegacyDatetimeCode=false";

        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(jdbcUrl);
        config.setDriverClassName("com.mysql.cj.jdbc.Driver");
        config.setUsername(cfg.mysqlUser);
        config.setPassword(cfg.mysqlPassword);
        config.setMaximumPoolSize(10);
        config.setMinimumIdle(2);
        config.setConnectionTimeout(5000);
        config.setIdleTimeout(60000);
        config.setMaxLifetime(30 * 60 * 1000L);
        config.setPoolName("IQCLAuth-MySQL");

        this.dataSource = new HikariDataSource(config);
        IqclAuth.LOGGER.info("[IQCL Auth] MySQL 存储后端已初始化: {}:{}/{}",
                cfg.mysqlHost, cfg.mysqlPort, cfg.mysqlDatabase);
    }

    @Override
    public void init() throws Exception {
        try (Connection conn = dataSource.getConnection(); Statement stmt = conn.createStatement()) {
            stmt.execute(replacePrefix(CREATE_TABLE_SQL));
            stmt.execute(replacePrefix(CREATE_INDEX_SQL));
        }
    }

    @Override
    public void close() {
        if (dataSource != null && !dataSource.isClosed()) {
            dataSource.close();
            IqclAuth.LOGGER.info("[IQCL Auth] MySQL 存储后端已关闭");
        }
    }

    @Override
    public AccountRecord findByUuid(UUID uuid) throws Exception {
        return queryOne(replacePrefix(SELECT_BY_UUID_SQL), ps -> ps.setString(1, uuid.toString()));
    }

    @Override
    public AccountRecord findByUsername(String username) throws Exception {
        return queryOne(replacePrefix(SELECT_BY_USERNAME_SQL), ps -> ps.setString(1, username));
    }

    @Override
    public void insert(AccountRecord record) throws Exception {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(replacePrefix(INSERT_SQL))) {
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
            if (msg != null && msg.contains("Duplicate entry")) {
                throw new StorageException("账号已存在", e);
            }
            throw e;
        }
    }

    @Override
    public void updatePassword(UUID uuid, byte[] salt, byte[] hash, int iterations, long updatedAtMs) throws Exception {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(replacePrefix(UPDATE_PASSWORD_SQL))) {
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
             PreparedStatement ps = conn.prepareStatement(replacePrefix(UPDATE_TOTP_SQL))) {
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
             PreparedStatement ps = conn.prepareStatement(replacePrefix(UPDATE_TOTP_LAST_CODE_SQL))) {
            ps.setString(1, lastCode);
            ps.setString(2, uuid.toString());
            ps.executeUpdate();
        }
    }

    @Override
    public void delete(UUID uuid) throws Exception {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(replacePrefix(DELETE_SQL))) {
            ps.setString(1, uuid.toString());
            ps.executeUpdate();
        }
    }

    @Override
    public boolean exists(UUID uuid) throws Exception {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(replacePrefix(EXISTS_SQL))) {
            ps.setString(1, uuid.toString());
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    private AccountRecord queryOne(String sql, PreparedBinding binding) throws Exception {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            binding.bind(ps);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return mapRow(rs);
            }
        }
        return null;
    }

    private AccountRecord mapRow(ResultSet rs) throws Exception {
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

    private String replacePrefix(String sql) {
        return sql.replace("__prefix__", tableName);
    }

    @FunctionalInterface
    private interface PreparedBinding {
        void bind(PreparedStatement ps) throws Exception;
    }
}
