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
 * PostgreSQL 存储后端实现。
 * <p>
 * 依赖：{@code org.postgresql:postgresql} 嵌套 JAR。
 * 列类型映射：BLOB → BYTEA，VARCHAR(36) → VARCHAR(36)，BIGINT → BIGINT。
 */
public final class PostgresAccountStorage implements AccountStorage {

    private static final String CREATE_TABLE_SQL =
            "CREATE TABLE IF NOT EXISTS __schema__.accounts (" +
            "  uuid           VARCHAR(36) PRIMARY KEY," +
            "  username       VARCHAR(64) NOT NULL," +
            "  salt           BYTEA NOT NULL," +
            "  hash           BYTEA NOT NULL," +
            "  iterations     INT NOT NULL," +
            "  created_at_ms  BIGINT NOT NULL," +
            "  updated_at_ms  BIGINT NOT NULL," +
            "  totp_enabled   BOOLEAN NOT NULL DEFAULT FALSE," +
            "  totp_secret    VARCHAR(64)," +
            "  totp_last_code VARCHAR(16)" +
            ")";

    private static final String CREATE_INDEX_SQL =
            "CREATE INDEX IF NOT EXISTS __schema__idx_accounts_username ON __schema__.accounts(username)";

    private static final String SELECT_BY_UUID_SQL =
            "SELECT uuid, username, salt, hash, iterations, created_at_ms, updated_at_ms, " +
            "totp_enabled, totp_secret, totp_last_code " +
            "FROM __schema__.accounts WHERE uuid = ?";

    private static final String SELECT_BY_USERNAME_SQL =
            "SELECT uuid, username, salt, hash, iterations, created_at_ms, updated_at_ms, " +
            "totp_enabled, totp_secret, totp_last_code " +
            "FROM __schema__.accounts WHERE username = ?";

    private static final String INSERT_SQL =
            "INSERT INTO __schema__.accounts " +
            "(uuid, username, salt, hash, iterations, created_at_ms, updated_at_ms, " +
            "totp_enabled, totp_secret, totp_last_code) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    private static final String UPDATE_PASSWORD_SQL =
            "UPDATE __schema__.accounts SET salt = ?, hash = ?, iterations = ?, updated_at_ms = ? WHERE uuid = ?";

    private static final String UPDATE_TOTP_SQL =
            "UPDATE __schema__.accounts SET totp_enabled = ?, totp_secret = ?, totp_last_code = ?, " +
            "updated_at_ms = ? WHERE uuid = ?";

    private static final String UPDATE_TOTP_LAST_CODE_SQL =
            "UPDATE __schema__.accounts SET totp_last_code = ? WHERE uuid = ?";

    private static final String DELETE_SQL = "DELETE FROM __schema__.accounts WHERE uuid = ?";

    private static final String EXISTS_SQL = "SELECT 1 FROM __schema__.accounts WHERE uuid = ?";

    private final HikariDataSource dataSource;
    private final String schema;

    public PostgresAccountStorage(ModConfig.PasswordStorageConfig cfg) throws Exception {
        this.schema = cfg.postgresSchema != null ? cfg.postgresSchema : "public";

        String jdbcUrl = "jdbc:postgresql://" + cfg.postgresHost + ":" + cfg.postgresPort
                + "/" + cfg.postgresDatabase
                + "?sslmode=verify-full&stringtype=unspecified";

        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(jdbcUrl);
        config.setDriverClassName("org.postgresql.Driver");
        config.setUsername(cfg.postgresUser);
        config.setPassword(cfg.postgresPassword);
        config.setMaximumPoolSize(10);
        config.setMinimumIdle(2);
        config.setConnectionTimeout(5000);
        config.setIdleTimeout(60000);
        config.setMaxLifetime(30 * 60 * 1000L);
        config.setPoolName("IQCLAuth-Postgres");

        this.dataSource = new HikariDataSource(config);
        IqclAuth.LOGGER.info("[IQCL Auth] PostgreSQL 存储后端已初始化: {}:{}/{}",
                cfg.postgresHost, cfg.postgresPort, cfg.postgresDatabase);
    }

    @Override
    public void init() throws Exception {
        // 确保 schema 存在
        try (Connection conn = dataSource.getConnection()) {
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("CREATE SCHEMA IF NOT EXISTS " + schema);
                stmt.execute(replaceSchema(CREATE_TABLE_SQL));
                stmt.execute(replaceSchema(CREATE_INDEX_SQL));
            }
        }
    }

    @Override
    public void close() {
        if (dataSource != null && !dataSource.isClosed()) {
            dataSource.close();
            IqclAuth.LOGGER.info("[IQCL Auth] PostgreSQL 存储后端已关闭");
        }
    }

    @Override
    public AccountRecord findByUuid(UUID uuid) throws Exception {
        return queryOne(replaceSchema(SELECT_BY_UUID_SQL), ps -> ps.setString(1, uuid.toString()));
    }

    @Override
    public AccountRecord findByUsername(String username) throws Exception {
        return queryOne(replaceSchema(SELECT_BY_USERNAME_SQL), ps -> ps.setString(1, username));
    }

    @Override
    public void insert(AccountRecord record) throws Exception {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(replaceSchema(INSERT_SQL))) {
            ps.setString(1, record.uuid.toString());
            ps.setString(2, record.username);
            ps.setBytes(3, record.salt);
            ps.setBytes(4, record.hash);
            ps.setInt(5, record.iterations);
            ps.setLong(6, record.createdAtMs);
            ps.setLong(7, record.updatedAtMs);
            ps.setBoolean(8, record.totpEnabled);
            ps.setString(9, record.totpSecret);
            ps.setString(10, record.totpLastCode);
            int affected = ps.executeUpdate();
            if (affected == 0) throw new StorageException("插入失败：0 行受影响");
        } catch (Exception e) {
            if (e.getMessage() != null && e.getMessage().contains("duplicate key")) {
                throw new StorageException("账号已存在", e);
            }
            throw e;
        }
    }

    @Override
    public void updatePassword(UUID uuid, byte[] salt, byte[] hash, int iterations, long updatedAtMs) throws Exception {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(replaceSchema(UPDATE_PASSWORD_SQL))) {
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
             PreparedStatement ps = conn.prepareStatement(replaceSchema(UPDATE_TOTP_SQL))) {
            ps.setBoolean(1, enabled);
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
             PreparedStatement ps = conn.prepareStatement(replaceSchema(UPDATE_TOTP_LAST_CODE_SQL))) {
            ps.setString(1, lastCode);
            ps.setString(2, uuid.toString());
            ps.executeUpdate();
        }
    }

    @Override
    public void delete(UUID uuid) throws Exception {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(replaceSchema(DELETE_SQL))) {
            ps.setString(1, uuid.toString());
            ps.executeUpdate();
        }
    }

    @Override
    public boolean exists(UUID uuid) throws Exception {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(replaceSchema(EXISTS_SQL))) {
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
        boolean totpEnabled = rs.getBoolean("totp_enabled");
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

    private String replaceSchema(String sql) {
        return sql.replace("__schema__", schema);
    }

    @FunctionalInterface
    private interface PreparedBinding {
        void bind(PreparedStatement ps) throws Exception;
    }
}
