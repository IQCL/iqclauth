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
 * 模组配置（仅服务端）。
 * <p>
 * 使用 FabricLoader 的 config 目录，JSON 格式存储。
 * 配置文件位于 {@code config/iqclauth.json}，首次启动自动生成。
 */
public class ModConfig {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private static final Path CONFIG_PATH =
            FabricLoader.getInstance().getConfigDir().resolve("iqclauth.json");

    /**
     * 远程验证服务器 API 地址（POST /api/verify-pin）。
     * 【硬编码常量】禁止修改，防止被篡改指向恶意服务器。
     */
    public static final String VERIFY_API_URL = "https://www.iqcl.de5.net/api/verify-pin";

    /**
     * 远程验证服务器 API 地址（POST /api/game-session/login 和 /api/game-session/logout）。
     * 【硬编码常量】禁止修改。
     */
    public static final String GAME_SESSION_LOGIN_URL = "https://www.iqcl.de5.net/api/game-session/login";
    public static final String GAME_SESSION_LOGOUT_URL = "https://www.iqcl.de5.net/api/game-session/logout";

    // ========== 基础配置 ==========

    /**
     * 服务端身份密钥（存量旧密钥），作为 X-Server-Key 请求头发送给验证服务器。
     * <p>
     * 仅在未配置 apiId/apiKey 成套模式时作为回退鉴权方式使用（API 文档 2.3 节）。
     */
    public String serverKey = "REPLACE_WITH_YOUR_X_SERVER_KEY";

    /**
     * API 调用标识（成套模式），如 {@code mc_login_1}，作为 X-Api-Id 请求头发送给验证服务器。
     * <p>
     * 必须与 {@link #apiKey} 配套使用（API 文档 2.3 节成套模式）。
     * verify-pin 请求体是客户端密文包需原样转发（不可信节点约束），
     * 因此本模组统一用请求头 X-Api-Id + X-Api-Key 传入，不塞进客户端密文包。
     * 必须为 mc_login 用途且与 apiKey 同一所有者。
     * 未配置（保持 REPLACE_WITH 前缀）时回退使用 {@link #serverKey}。
     */
    public String apiId = "REPLACE_WITH_YOUR_API_ID";

    /**
     * API 调用密钥（成套模式），与 {@link #apiId} 配套，作为 X-Api-Key 请求头发送。
     * <p>
     * 【安全】此密钥为服务器凭证，仅由 MC 服务端持有，<b>禁止硬编码到客户端模组</b>。
     * 客户端密文包仅含 v/ts/nonce/ciphertext，由 MC 服务端转发时附加本请求头。
     * 未配置（保持 REPLACE_WITH 前缀）时回退使用 {@link #serverKey}。
     */
    public String apiKey = "REPLACE_WITH_YOUR_API_KEY";

    /**
     * 玩家进服后的宽限时间（秒）。
     * 宽限期内玩家可自由活动，不受未登录限制。
     * -1 = 关闭宽限（立即限制），0 = 立即限制，>0 = 宽限秒数。
     */
    public int gracePeriodSeconds = 15;

    /**
     * 未认证玩家的登录超时时间（秒）。
     * 玩家进服后必须在此时间内完成 PIN 登录，否则自动踢出。
     * 0 = 不限制。
     */
    public int loginTimeoutSeconds = 300;

    /**
     * 会话保留时限（秒），仅对离线玩家生效。
     * 已认证玩家在线期间始终视为活动中，绝不会因 session 超时被踢；
     * 退出游戏后从此时刻开始计时，时限内重连可自动恢复登录，
     * 超过后持久会话失效，需重新输入凭证。
     * 0 = 不限制（离线会话沿用 sessionMaxAgeSeconds 过期时间）。
     */
    public int sessionTimeoutSeconds = 1800;

    // ========== Limbo 隔离区 ==========

    /**
     * 是否启用 Limbo 隔离区模式。
     * true: 未登录玩家被传送至隔离区，物品/位置被清空
     * false: 使用原地冻结模式
     */
    public boolean limboEnabled = true;

    /** Limbo 隔离区维度（空岛维度 ID）。 */
    public String limboDimension = "minecraft:overworld";

    /** Limbo 隔离区坐标（X）。 */
    public int limboX = 0;

    /** Limbo 隔离区坐标（Y）。建议在天空上方（如 200），防止跌落。 */
    public int limboY = 200;

    /** Limbo 隔离区坐标（Z）。 */
    public int limboZ = 0;

    /**
     * 是否在 Limbo 隔离区下方生成垫脚方块平台（5×5 石头 + 中心玻璃）。
     * true: 生成安全平台防止玩家跌落虚空
     * false: 不生成平台（适用于已有现成平台的隔离区）
     */
    public boolean limboGeneratePlatform = true;

    /**
     * 登录成功后是否恢复玩家物品和位置。
     * true: 从进服时快照恢复物品和位置
     * false: 保持 Limbo 状态
     */
    public boolean restoreOnLogin = true;

    /**
     * 玩家进服时是否强制清空背包。
     * true: 进服立即清空背包（防止物品丢失风险）
     * false: 保留背包直到登录成功
     */
    public boolean clearInventoryOnJoin = true;

    // ========== 持久会话 ==========

    /**
     * 是否启用持久会话（自动登录）。
     * true: 同 IP 重连自动恢复登录状态
     * false: 每次都需重新输入 PIN
     */
    public boolean persistentSession = true;

    /**
     * 会话有效期（秒）。超过此时间后需重新登录。
     * 默认 28800 秒（8 小时）。0 = 永不过期。
     */
    public int sessionMaxAgeSeconds = 28800;

    /**
     * 是否信任 IP（同 IP 重连自动登录）。
     * true: 只要 IP 相同就自动恢复
     * false: 即使 IP 相同也需重新验证
     */
    public boolean trustIp = true;

    /**
     * 是否启用 IP 绑定检测（防异地登录）。
     * true: 记录登录 IP，下次登录 IP 不一致时触发锁定
     * false: 不检查 IP 变化
     */
    public boolean enableIpBinding = true;

    // ========== 单账号唯一在线 ==========

    /**
     * 是否启用单账号唯一在线（防多开）。
     * true: 同一 IQCL 账号禁止多人同时登录，异地登录踢掉旧连接
     * false: 允许多设备同时登录
     */
    public boolean singleAccountOnline = true;

    // ========== 未登录限制（宽限期后生效，均为布尔开关） ==========

    /** 限制视角转动（yaw/pitch 锁定在安全范围）。 */
    public boolean restrictViewRotation = true;

    /** 限制移动（每 tick 回拉到出生点附近）。 */
    public boolean restrictMovement = true;

    /** 禁止破坏方块。 */
    public boolean restrictBlockBreak = true;

    /** 禁止攻击/击打方块。 */
    public boolean restrictBlockAttack = true;

    /** 禁止放置/使用方块（含打开容器）。 */
    public boolean restrictBlockUse = true;

    /** 禁止与实体交互（右键实体）。 */
    public boolean restrictEntityInteract = true;

    /** 禁止攻击实体（砍怪/打玩家）。 */
    public boolean restrictEntityAttack = true;

    /** 禁止使用物品（吃/喝/投掷等）。 */
    public boolean restrictItemUse = true;

    /** 强制关闭容器/GUI。 */
    public boolean restrictContainerOpen = true;

    /** 未登录玩家禁止执行除 /iqcl 以外的聊天/命令。 */
    public boolean restrictChatAndCommands = true;

    // ========== game-session API ==========

    /**
     * 是否启用 game-session 登录/登出通知。
     * true: 玩家登录/登出时通知验证服务器
     * false: 不调用 API
     */
    public boolean enableGameSessionApi = true;

    // ========== 密码登录（借鉴 EasyAuth 思路，自主实现） ==========

    /**
     * 是否启用密码登录功能。
     * true: /iqcl login password / register / changepassword / unregister 等子命令可用
     * false: 拒绝执行所有密码相关命令
     */
    public boolean passwordLoginEnabled = true;

    /**
     * 密码登录成功后是否提示玩家关联 IQCL 账号（不强制）。
     * true: 未关联 IQCL 的玩家密码登录成功后发送提示消息
     * false: 不提示
     */
    public boolean promptIqclLinkAfterPasswordLogin = true;

    /**
     * 是否启用 TOTP 双因素认证。
     * true: 密码登录成功后若账号配置了 TOTP 会触发二次验证
     * false: 完全跳过 TOTP（即使账号配置了 TOTP 也直接放行）
     */
    public boolean totpEnabled = true;

    /** 密码策略配置。 */
    public PasswordPolicyConfig passwordPolicy = new PasswordPolicyConfig();

    /** 密码哈希参数配置。 */
    public PasswordHashConfig passwordHash = new PasswordHashConfig();

    /** 登录爆破防护配置。 */
    public LoginAttemptConfig loginAttempt = new LoginAttemptConfig();

    /** 密码存储后端配置。 */
    public PasswordStorageConfig passwordStorage = new PasswordStorageConfig();

    /** 密码策略配置。 */
    public static class PasswordPolicyConfig {
        /** 密码最小长度。 */
        public int minPasswordLength = 8;
        /** 密码最大长度。 */
        public int maxPasswordLength = 64;
        /** 必须包含字母。 */
        public boolean requireLetter = true;
        /** 必须包含数字。 */
        public boolean requireDigit = true;
        /** 必须包含特殊字符。 */
        public boolean requireSpecialChar = false;
        /** 是否允许空格。 */
        public boolean allowSpace = false;
        /** 弱密码检查级别：0=关闭，1=基础黑名单。 */
        public int weakPasswordCheckLevel = 1;
    }

    /** 密码哈希参数配置。 */
    public static class PasswordHashConfig {
        /** PBKDF2 迭代次数（建议 ≥ 100000）。 */
        public int iterations = 100000;
        /** 盐长度（字节，建议 16）。 */
        public int saltBytes = 16;
        /** 输出哈希位数（固定 256，对应 PBKDF2WithHmacSHA256）。 */
        public int hashBits = 256;
    }

    /** 登录爆破防护配置。 */
    public static class LoginAttemptConfig {
        /** 最大失败尝试次数。 */
        public int maxLoginAttempts = 5;
        /** 锁定时长（秒）。 */
        public int lockSeconds = 300;
        /** 是否启用指数退避（每次连续锁定时长翻倍）。 */
        public boolean exponentialBackoff = true;
        /** 单次锁定上限（秒）。 */
        public int maxLockSeconds = 3600;
    }

    /** 密码存储后端配置。 */
    public static class PasswordStorageConfig {
        /** 存储后端类型：sqlite | mysql | postgres | mongo。 */
        public String backend = "sqlite";
        /** SQLite 数据库文件路径。 */
        public String sqliteFile = "config/iqclauth/passwords.db";

        // —— MySQL ——
        public String mysqlHost = "localhost";
        public int mysqlPort = 3306;
        public String mysqlDatabase = "iqclauth";
        public String mysqlUser = "iqclauth";
        public String mysqlPassword = "";
        public String mysqlTablePrefix = "iqclauth_";
        public boolean mysqlUseSsl = true;

        // —— PostgreSQL ——
        public String postgresHost = "localhost";
        public int postgresPort = 5432;
        public String postgresDatabase = "iqclauth";
        public String postgresSchema = "public";
        public String postgresUser = "iqclauth";
        public String postgresPassword = "";

        // —— MongoDB ——
        public String mongoUri = "";
        public String mongoHost = "localhost";
        public int mongoPort = 27017;
        public String mongoDatabase = "iqclauth";
        public String mongoCollection = "accounts";
    }

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
