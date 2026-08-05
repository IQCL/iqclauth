/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.password.storage;

import com.iqcl.auth.password.AccountRecord;

import java.util.UUID;

/**
 * 密码账号存储抽象层。
 * <p>
 * 所有存储后端（SQLite/MySQL/PostgreSQL/MongoDB）实现此接口。
 * 实现需保证线程安全（连接池本身线程安全，{@link StorageExecutor} 串行化调用避免并发写冲突）。
 * <p>
 * 方法可能抛出 {@link Exception}，由 {@link StorageExecutor} 的 onFailure 回调捕获。
 */
public interface AccountStorage {

    /**
     * 初始化表/集合（启动时调用一次）。
     * 幂等：重复调用不应破坏已有数据。
     */
    void init() throws Exception;

    /**
     * 关闭连接池/客户端（停服或 reload 时调用）。
     */
    void close();

    /**
     * 根据 UUID 查找账号。
     *
     * @return 账号记录，或 null（不存在）
     */
    AccountRecord findByUuid(UUID uuid) throws Exception;

    /**
     * 根据 username 查找（用于改名场景，可选实现）。
     * 默认返回 null（不实现）。
     *
     * @return 账号记录，或 null
     */
    default AccountRecord findByUsername(String username) throws Exception {
        return null;
    }

    /**
     * 插入新账号。
     *
     * @throws StorageException 已存在或写入失败
     */
    void insert(AccountRecord record) throws Exception;

    /**
     * 更新密码字段（salt+hash+iterations+updatedAtMs）。
     *
     * @throws StorageException 不存在或写入失败
     */
    void updatePassword(UUID uuid, byte[] salt, byte[] hash, int iterations, long updatedAtMs) throws Exception;

    /**
     * 更新 TOTP 双因素认证配置。
     *
     * @param uuid        玩家 UUID
     * @param enabled     是否启用
     * @param secret      TOTP Base32 密钥（启用时必填，禁用时为 null）
     * @param lastCode    上次使用的码（用于重放防护）
     * @param updatedAtMs 更新时间
     * @throws StorageException 不存在或写入失败
     */
    void updateTotp(UUID uuid, boolean enabled, String secret, String lastCode, long updatedAtMs) throws Exception;

    /**
     * 更新 lastUsedCode（重放防护，每次 TOTP 验证成功后调用）。
     */
    void updateTotpLastCode(UUID uuid, String lastCode) throws Exception;

    /**
     * 删除账号，不存在不报错。
     */
    void delete(UUID uuid) throws Exception;

    /**
     * 是否已存在该 UUID 的账号。
     */
    boolean exists(UUID uuid) throws Exception;

    /**
     * 存储层异常（用于区分业务冲突与系统错误）。
     */
    final class StorageException extends Exception {
        public StorageException(String message) {
            super(message);
        }

        public StorageException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
