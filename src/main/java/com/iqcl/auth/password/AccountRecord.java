/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.password;

import java.util.Arrays;
import java.util.UUID;

/**
 * 密码账号数据载体（不可变 POJO）。
 * <p>
 * 表示一条本服密码账号记录，由 {@link com.iqcl.auth.password.storage.AccountStorage}
 * 加载/持久化。密码以 PBKDF2 哈希 + 随机盐存储，{@code hash} 与 {@code salt} 字段
 * 在使用后应由调用方主动清零（{@link #zeroOut()}）以降低内存驻留时间。
 * <p>
 * TOTP 双因素认证字段：
 * <ul>
 *   <li>{@code totpEnabled} - 是否启用 TOTP 双因素认证</li>
 *   <li>{@code totpSecret} - TOTP Base32 编码密钥（null 表示未启用）</li>
 *   <li>{@code totpLastCode} - 上一次使用的 TOTP 码（防止时间窗口内重放）</li>
 * </ul>
 */
public final class AccountRecord {

    /** 玩家 Minecraft UUID（主键）。 */
    public final UUID uuid;
    /** 注册时的游戏名（仅参考，不参与验证）。 */
    public final String username;
    /** 密码盐（建议 16 字节）。 */
    public final byte[] salt;
    /** PBKDF2 输出哈希（32 字节，对应 256 位）。 */
    public final byte[] hash;
    /** 哈希迭代次数。 */
    public final int iterations;
    /** 创建时间（UTC 毫秒）。 */
    public final long createdAtMs;
    /** 最后更新时间（UTC 毫秒）。 */
    public final long updatedAtMs;

    // —— TOTP 双因素认证 ——
    /** 是否启用 TOTP 双因素认证。 */
    public final boolean totpEnabled;
    /** TOTP Base32 编码密钥（null 或空字符串表示未启用）。 */
    public final String totpSecret;
    /** 上一次使用的 TOTP 码（防止同一时间窗口内重放）。 */
    public final String totpLastCode;

    public AccountRecord(UUID uuid, String username, byte[] salt, byte[] hash,
                         int iterations, long createdAtMs, long updatedAtMs) {
        this(uuid, username, salt, hash, iterations, createdAtMs, updatedAtMs,
                false, null, null);
    }

    public AccountRecord(UUID uuid, String username, byte[] salt, byte[] hash,
                         int iterations, long createdAtMs, long updatedAtMs,
                         boolean totpEnabled, String totpSecret, String totpLastCode) {
        this.uuid = uuid;
        this.username = username;
        this.salt = salt;
        this.hash = hash;
        this.iterations = iterations;
        this.createdAtMs = createdAtMs;
        this.updatedAtMs = updatedAtMs;
        this.totpEnabled = totpEnabled;
        this.totpSecret = totpSecret;
        this.totpLastCode = totpLastCode;
    }

    /** 主动清零敏感字段，调用后此对象不应再被使用。 */
    public void zeroOut() {
        if (salt != null) Arrays.fill(salt, (byte) 0);
        if (hash != null) Arrays.fill(hash, (byte) 0);
    }

    /** 返回启用了 TOTP 的新副本（修改 lastCode 字段）。 */
    public AccountRecord withTotpLastCode(String lastCode) {
        return new AccountRecord(uuid, username, salt, hash, iterations,
                createdAtMs, updatedAtMs, totpEnabled, totpSecret, lastCode);
    }

    /** 返回启用/禁用 TOTP 的新副本。 */
    public AccountRecord withTotp(boolean enabled, String secret) {
        return new AccountRecord(uuid, username, salt, hash, iterations,
                createdAtMs, updatedAtMs, enabled, secret, null);
    }
}
