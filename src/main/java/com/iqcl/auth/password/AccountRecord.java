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

    public AccountRecord(UUID uuid, String username, byte[] salt, byte[] hash,
                         int iterations, long createdAtMs, long updatedAtMs) {
        this.uuid = uuid;
        this.username = username;
        this.salt = salt;
        this.hash = hash;
        this.iterations = iterations;
        this.createdAtMs = createdAtMs;
        this.updatedAtMs = updatedAtMs;
    }

    /** 主动清零敏感字段，调用后此对象不应再被使用。 */
    public void zeroOut() {
        if (salt != null) Arrays.fill(salt, (byte) 0);
        if (hash != null) Arrays.fill(hash, (byte) 0);
    }
}
