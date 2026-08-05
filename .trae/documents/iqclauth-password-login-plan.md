# IQCLAuth 密码登录功能实现方案

## Context

IQCLAuth 是 Fabric 1.20.1 双端认证模组，现有登录方式是基于 PIN 码 + 远程 IQCL 验证服务（RSA-OAEP 上行加密 + Ed25519 下行验签）。用户希望借鉴 [EasyAuth](https://github.com/nikitacartes/EasyAuth) 的密码登录思路，在 `/iqcl` 命令下新增一套**服务端本地验证**的密码登录体系，与现有 PIN 登录并列共存、互通，且支持多存储后端（SQLite/MySQL/PostgreSQL/MongoDB）。

**核心约束**（用户明确）：

* 借鉴思路，**禁止抄袭** EasyAuth 代码，加密方案自主设计

* 功能只能加不能减：现有 PIN 登录、Limbo、限制、持久会话、单账号在线等全部保留

* 所有新源文件加 MPL 2.0 版权头（`Copyright (c) 2026 IQCL`）

* 新功能要审批后实施

* 传输方式：**混合方案**（客户端装 mod 走加密通道；未装降级为直接服务端命令）

* 与 PIN 关系：**互通**（密码登录推荐绑 IQCL 账号；PIN 登录也建议设密码，二者独立但都标记 `authenticated=true`）

* 存储：**多后端**（SQLite 默认，可选 MySQL/PostgreSQL/MongoDB）

* 推进方式：**分 3 阶段实施**

* 依赖：**全部 include** 4 个驱动 + **引入 HikariCP**

**自主加密设计**：X25519 ECDH + AES-256-GCM（与 PIN 的 RSA-OAEP 用途区分：PIN 指向远程服务器，密码登录是服务端本地验证）。X25519/AES-GCM/PBKDF2WithHmacSHA256 均由 JDK 17 内置 SunJCE/SunEC 提供，**不引入 BouncyCastle**。

***

## 阶段划分

### 阶段 1：核心密码登录（SQLite + 服务端命令 + 互通）

可独立编译运行。客户端不装 mod 也能用（降级路径）。

### 阶段 2：混合传输（客户端 ECDH+AES-GCM 加密 + 降级路径防护）

客户端装 mod 时拦截命令本地加密；未装走降级。

### 阶段 3：多存储后端（MySQL/PostgreSQL/MongoDB）

扩展 `AccountStorage` 实现 + `/iqcl admin reloadstorage` 热切换。

***

## A. 命令结构设计

### 新增子命令（注册到 `/iqcl` 根下）

| 命令                                  | 参数                          | 权限         | 行为                                                                    |
| ----------------------------------- | --------------------------- | ---------- | --------------------------------------------------------------------- |
| `/iqcl login password <密码>`         | `greedyString`              | 所有玩家       | 阶段2: 客户端拦截走 `C2S_PASSWORD_ID`；阶段1/降级: 服务端 `executeLoginPassword` 异步验证 |
| `/iqcl register password <密码> <确认>` | 两个 `string`                 | 所有玩家       | 注册本服密码账号（与 mcUUID 绑定）。已注册则报错。提示可执行 `/iqcl link` 关联 IQCL               |
| `/iqcl changepassword <旧> <新>`      | 两个 `string`                 | 所有玩家，必须已认证 | 先验旧密码再写入新哈希                                                           |
| `/iqcl unregister password <密码>`    | `string`                    | 所有玩家，必须已认证 | 注销本服密码账号（需确认密码）                                                       |
| `/iqcl account`                     | 无                           | 所有玩家       | 显示自身状态：是否已注册密码、是否已关联 IQCL、当前认证方式                                      |
| `/iqcl cancel`                      | 无                           | 所有玩家       | 取消 PIN 待关联状态（`hasPendingLink=true` 时用）                                |
| `/iqcl admin unregister <玩家>`       | `EntityArgumentType.player` | OP 2       | 强制删除玩家密码账号                                                            |
| `/iqcl admin resetpassword <玩家>`    | `EntityArgumentType.player` | OP 2       | 重置为临时随机串，输出给管理员                                                       |
| `/iqcl admin reloadstorage`         | 无                           | OP 2       | 重载存储后端配置（阶段3）                                                         |

### 修改的现有子命令

| 命令                      | 修改点                                                                        |
| ----------------------- | -------------------------------------------------------------------------- |
| `/iqcl login pin <pin>` | **不变**                                                                     |
| `/iqcl status [player]` | 输出增加"密码账号: 已注册/未注册"行                                                       |
| `/iqcl logout [player]` | 增加：清除 `LoginAttemptLimiter` 计数                                             |
| `/iqcl force <player>`  | **不变**                                                                     |
| `/iqcl link`            | 放宽前置：密码已认证也算通过；若密码登录玩家执行 link 且无 pending，提示需先 `/iqcl login pin` 触发 IQCL 关联 |

### 协调规则

1. `AuthState.isAuthenticated=true` 时拒绝任何 `login/register` 子命令
2. `AuthState.hasPendingLink=true` 时拒绝 `login password`（提示先 `/iqcl link` 或 `/iqcl cancel`）
3. PIN 与密码账号独立并存，登录方式任选
4. `/iqcl logout` 同时清除两种登录痕迹，但保留 IQCL 关联（持久化）和密码账号（数据库持久化）

***

## B. 模块划分与文件清单

### 新增包结构

```
com.iqcl.auth.password                — 业务编排
com.iqcl.auth.password.crypto         — PBKDF2 哈希 + X25519/AES-GCM
com.iqcl.auth.password.storage        — 存储抽象层 + 4 实现
com.iqcl.auth.password.net            — 服务端密码数据包处理（阶段2）
com.iqcl.auth.client                  — 新增 PasswordChatInterceptor / EcdhClient（阶段2）
```

### 阶段 1 新增文件

| 文件                                            | 职责                         | 关键方法                                                                                                                                                                                |
| --------------------------------------------- | -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `password/AccountRecord.java`                 | 密码账号 POJO（不可变）             | `uuid/username/salt/hash/iterations/createdAtMs/updatedAtMs`                                                                                                                        |
| `password/crypto/SaltGenerator.java`          | 盐生成                        | `byte[] generate(int bytes)` 默认 16 字节                                                                                                                                               |
| `password/crypto/PasswordHasher.java`         | PBKDF2WithHmacSHA256 哈希与验证 | `HashResult hash(char[], int iter, int saltBytes)`；`boolean verify(char[], byte[] salt, byte[] hash, int iter)`；用 `MessageDigest.isEqual` 常量时间比较；密码 `char[]` 用后 `Arrays.fill('\0')` |
| `password/LoginAttemptLimiter.java`           | 爆破防护                       | `recordFailure/reset/isLocked/remainingLockMs/cleanup`，`ConcurrentHashMap<UUID, AttemptState>`，支持指数退避                                                                               |
| `password/PasswordPolicy.java`                | 密码强度校验                     | `ValidationResult validate(String)`，规则配置驱动                                                                                                                                          |
| `password/storage/AccountStorage.java`        | 存储抽象接口                     | `init/close/findByUuid/findByUsername/insert/updatePassword/delete/exists`                                                                                                          |
| `password/storage/AccountStorageFactory.java` | 工厂                         | `create(ModConfig.PasswordStorageConfig)`                                                                                                                                           |
| `password/storage/SqliteAccountStorage.java`  | SQLite 实现                  | 用 HikariCP 连接池；表 `iqclauth_accounts(uuid PK, username, salt BLOB, hash BLOB, iterations, created_at_ms, updated_at_ms)` + username 索引                                               |
| `password/storage/StorageExecutor.java`       | 异步执行器                      | 单线程 `ExecutorService`；`submit(server, task, onSuccess, onFailure)`；回调通过 `server.execute(...)` 调度回主线程                                                                                |
| `password/PasswordManager.java`               | 业务编排核心                     | `init/shutdown/login/register/changePassword/unregister/adminUnregister/adminResetPassword`；含 `completePasswordLogin`（复用 `ServerNetworkHandler.completeLogin`）                      |
| `password/PasswordCommandHandler.java`        | 命令 `executes` 集中地          | `executeLoginPassword/RegisterPassword/ChangePassword/UnregisterPassword/Account/Cancel/AdminUnregister/AdminResetPassword/AdminReloadStorage`                                      |

### 阶段 2 新增文件

| 文件                                         | 职责                                                              |
| ------------------------------------------ | --------------------------------------------------------------- |
| `password/crypto/ServerKeyStore.java`      | 服务端 X25519 密钥对生成与持久化（`config/iqclauth/keys/server_x25519.json`） |
| `password/crypto/EcdhEncryptor.java`       | 服务端 ECDH 解密（X25519 + SHA-256 KDF + AES-256-GCM）                 |
| `password/net/PasswordNetworkHandler.java` | 注册 `C2S_PASSWORD_ID` 接收器，解密 + 分派到 `PasswordManager`             |
| `client/EcdhClient.java`                   | 客户端 ECDH 加密（对应 `EcdhEncryptor`）                                 |
| `client/PasswordChatInterceptor.java`      | 客户端拦截 4 个密码命令，本地加密发送                                            |
| `client/ClientAuthState.java`              | 客户端认证状态集中管理（重构 `PinChatInterceptor.authenticated`）              |

### 阶段 3 新增文件

| 文件                                             | 职责                                             |
| ---------------------------------------------- | ---------------------------------------------- |
| `password/storage/MysqlAccountStorage.java`    | MySQL 实现，HikariCP，`VARBINARY(255)` 类型          |
| `password/storage/PostgresAccountStorage.java` | PostgreSQL 实现，`BYTEA` 类型，`sslmode=verify-full` |
| `password/storage/MongoAccountStorage.java`    | MongoDB 实现，二进制 base64 存储，username 唯一索引         |

### 修改的现有文件

| 文件                                                        | 修改点                                                                                                                                                          |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `server/CommandRegistry.java`                             | `registerIqclRoot` 追加 `login/password`、`register/password`、`changepassword`、`unregister/password`、`account`、`cancel`、`admin/*` 子命令                           |
| `config/ModConfig.java`                                   | 新增 `passwordLoginEnabled` + 嵌套 `PasswordPolicyConfig`/`PasswordHashConfig`/`LoginAttemptConfig`/`PasswordStorageConfig` + `promptIqclLinkAfterPasswordLogin` |
| `network/NetworkConstants.java`                           | 阶段2 新增 `C2S_PASSWORD_ID` + `S2C_AUTHINFO_ID`                                                                                                                 |
| `IqclAuth.java`                                           | `onInitialize` 加 `PasswordManager.init()`；阶段2 加 `ServerKeyStore.init()` + `PasswordNetworkHandler.register()`                                                |
| `client/IqclAuthClient.java`                              | 阶段2 注册 `PasswordChatInterceptor` + `S2C_AUTHINFO_ID` 接收器                                                                                                     |
| `server/PlayerRestrictionManager.java`                    | `handlePlayerJoin` 引导消息更新（提示两种登录方式）；阶段2 末尾发送 `S2C_AUTHINFO_ID`                                                                                               |
| `server/AuthState.java`                                   | 确认 `cancelPendingLink` 可见（已有）；如无可见性则调整                                                                                                                       |
| `server/CommandRegistry.java` 的 `executeStatusSelf/Other` | `showStatus` 输出增加密码账号状态行（调 `PasswordManager` 查询，需异步→主线程）                                                                                                     |
| `assets/iqclauth/lang/zh_cn.json` + `en_us.json`          | 新增所有密码相关消息 key                                                                                                                                               |
| `build.gradle`                                            | 阶段1: `sqlite-jdbc` + `HikariCP`；阶段3: `mysql-connector-j` + `postgresql` + `mongodb-driver-sync`+`bson`+`mongodb-driver-core`，全部 `include`                    |
| `README.md`                                               | 阶段1 完成后更新命令列表与配置说明                                                                                                                                           |

***

## C. 配置项新增（ModConfig）

```java
// ========== 密码登录总开关 ==========
public boolean passwordLoginEnabled = true;

// ========== 密码策略 ==========
public PasswordPolicyConfig passwordPolicy = new PasswordPolicyConfig();
public static class PasswordPolicyConfig {
    public int minPasswordLength = 8;
    public int maxPasswordLength = 64;
    public boolean requireLetter = true;
    public boolean requireDigit = true;
    public boolean requireSpecialChar = false;
    public boolean allowSpace = false;
    public int weakPasswordCheckLevel = 1;  // 0=关, 1=基础黑名单
}

// ========== 哈希参数 ==========
public PasswordHashConfig passwordHash = new PasswordHashConfig();
public static class PasswordHashConfig {
    public int iterations = 100000;
    public int saltBytes = 16;
    public int hashBits = 256;  // 固定 256
}

// ========== 登录爆破防护 ==========
public LoginAttemptConfig loginAttempt = new LoginAttemptConfig();
public static class LoginAttemptConfig {
    public int maxLoginAttempts = 5;
    public int lockSeconds = 300;
    public boolean exponentialBackoff = true;
    public int maxLockSeconds = 3600;
}

// ========== 存储后端 ==========
public PasswordStorageConfig passwordStorage = new PasswordStorageConfig();
public static class PasswordStorageConfig {
    public String backend = "sqlite";  // sqlite|mysql|postgres|mongo
    public String sqliteFile = "config/iqclauth/passwords.db";
    public String mysqlHost = "localhost";
    public int mysqlPort = 3306;
    public String mysqlDatabase = "iqclauth";
    public String mysqlUser = "iqclauth";
    public String mysqlPassword = "";
    public String mysqlTablePrefix = "iqclauth_";
    public boolean mysqlUseSsl = true;
    public String postgresHost = "localhost";
    public int postgresPort = 5432;
    public String postgresDatabase = "iqclauth";
    public String postgresSchema = "public";
    public String postgresUser = "iqclauth";
    public String postgresPassword = "";
    public String mongoUri = "mongodb://localhost:27017";
    public String mongoDatabase = "iqclauth";
    public String mongoCollection = "accounts";
}

// ========== 互通提示 ==========
public boolean promptIqclLinkAfterPasswordLogin = true;
```

***

## D. build.gradle 依赖新增

### 阶段 1

```gradle
implementation "org.xerial:sqlite-jdbc:3.46.1.3"
include "org.xerial:sqlite-jdbc:3.46.1.3"
implementation "com.zaxxer:HikariCP:5.1.0"
include "com.zaxxer:HikariCP:5.1.0"
```

### 阶段 3

```gradle
implementation "com.mysql:mysql-connector-j:8.4.0"
include "com.mysql:mysql-connector-j:8.4.0"
implementation "org.postgresql:postgresql:42.7.3"
include "org.postgresql:postgresql:42.7.3"
implementation "org.mongodb:mongodb-driver-sync:5.1.2"
include "org.mongodb:mongodb-driver-sync:5.1.2"
include "org.mongodb:bson:5.1.2"
include "org.mongodb:mongodb-driver-core:5.1.2"
```

**不引入 BouncyCastle**——PBKDF2/X25519/AES-GCM 均由 JDK 17 内置。Fabric Loom `include` 自动处理嵌套 JAR，**不需要 shadow 插件**，`fabric.mod.json` 的 `depends` 不需修改。

***

## E. 与现有模块的集成点

### E.1 密码登录成功后的调用链

`PasswordManager.completePasswordLogin`（主线程，**复用** **`ServerNetworkHandler.completeLogin(server, player, name, null, null)`**）：

| 调用                                                   | 作用                                           |
| ---------------------------------------------------- | -------------------------------------------- |
| `PlayerSessionManager.enforceSingleAccount`          | `completeLogin` 内部已处理（displayId=null 时跳过防多开） |
| `AuthState.authenticate(player)`                     | 置 `authenticated=true`，与 PIN 登录一致            |
| `PlayerSessionManager.recordAuthenticatedIp(player)` | 记录持久会话 IP                                    |
| `PlayerSessionManager.restoreFromLimbo(player)`      | 恢复物品快照 + 位置 + 解除 Limbo                       |
| `ApiGateway.notifyLogin(mcUuid, username)`           | 通知 IQCL 远端（用户名优先用 IQCL 关联名，否则游戏名）            |
| `ServerPlayNetworking.send(S2C_RESULT_ID, ...)`      | 通知客户端同步认证状态                                  |

### E.2 PlayerRestrictionManager

* **判定逻辑不动**：`isRestricted` 依赖 `AuthState.isAuthenticated`，密码登录通过后同样置 true，所有限制自动解除

* `handlePlayerJoin` 引导消息更新：提示 PIN 与密码两种登录方式

* 阶段2 末尾发送 `S2C_AUTHINFO_ID`（推送服务端公钥 + 功能开关）

### E.3 持久会话

**无需扩展**。`PlayerSessionManager.tryPersistentSession` 只检查 IP 记录是否未过期，与登录方式无关。密码登录成功后调 `recordAuthenticatedIp`，与 PIN 走同一记录。

### E.4 客户端 PinChatInterceptor

**不修改** **`PinChatInterceptor`**，新增并列的 `PasswordChatInterceptor`。二者注册不同的 `ClientSendMessageEvents.ALLOW_COMMAND` 回调。共享 `S2C_RESULT_ID` 通道（消息内容区分）。

* 阶段2 重构：提取 `ClientAuthState` 集中管理客户端认证状态，`PinChatInterceptor` 与 `PasswordChatInterceptor` 均调用，避免两份状态。

### E.5 与 IQCL 关联流程衔接

| 玩家状态                                    | 衔接行为                                                                                                                              |
| --------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `LinkStore.load(uuid)` 非 null（已关联 IQCL） | 直接 `completePasswordLogin`，`notifyLogin` 用关联 username                                                                             |
| `LinkStore.load(uuid)` null（未关联）        | 仅 `authenticate`，`notifyLogin` 用游戏名。若 `promptIqclLinkAfterPasswordLogin=true`，发送提示"建议执行 `/iqcl login pin <PIN>` 关联 IQCL 账号以便跨服找回" |

密码登录**不会**自动产生 `pendingDisplayId`，所以密码登录后直接 `/iqcl link` 会失败（期望行为）——要关联 IQCL 必须走 PIN 流程。

***

## F. 异步与线程安全

### 异步架构

```
主线程（命令执行）
  └─ PasswordCommandHandler.executeLoginPassword
      └─ PasswordManager.login(server, player, pwd, callback)
          └─ StorageExecutor.submit(server, dbTask, onSuccess, onFailure)
              ↓
          IO 线程（单线程池）
              ├─ storage.findByUuid(uuid)
              ├─ PasswordHasher.verify(...)
              └─ 构造 Result
              ↓
          回调（IO 线程内调 callback）
              └─ server.execute(() -> {
                  // 主线程：AuthState.authenticate + restoreFromLimbo + send S2C_RESULT
              })
```

### 线程安全要点

1. **`AccountStorage`** **实现**：HikariCP/MongoClient 本身线程安全；`StorageExecutor` 用单线程池串行化所有 DB 操作避免并发写冲突
2. **`AuthState`/`PlayerSessionManager`** **写操作**：必须在主线程，`StorageExecutor` 回调用 `server.execute(...)` 调度
3. **`LoginAttemptLimiter`**：`ConcurrentHashMap`，可在 IO 线程读写
4. **玩家等待期间**：`AuthState.isAuthenticated=false`，自然受所有限制（正确行为，DB 验证未完成前不放权）
5. **回调首行检查**：`player.networkHandler != null && !player.isRemoved()`（防玩家断线后回调）
6. **超时**：HikariCP `connectionTimeout=5s`，JDBC `queryTimeout=3s`

***

## G. 阶段 1 实施步骤（首次交付）

1. `build.gradle` 加 sqlite-jdbc + HikariCP（`include`）
2. 新增 `password/AccountRecord.java`
3. 新增 `password/crypto/SaltGenerator.java` + `PasswordHasher.java`
4. 新增 `password/LoginAttemptLimiter.java` + `PasswordPolicy.java`
5. 新增 `password/storage/AccountStorage.java` 接口 + `AccountStorageFactory.java` + `SqliteAccountStorage.java` + `StorageExecutor.java`
6. 新增 `password/PasswordManager.java`（含 `completePasswordLogin` 复用 `ServerNetworkHandler.completeLogin`）
7. 新增 `password/PasswordCommandHandler.java`
8. 修改 `config/ModConfig.java` 新增配置项
9. 修改 `server/CommandRegistry.java` 注册新子命令
10. 修改 `server/PlayerRestrictionManager.java` 引导消息
11. 修改 `IqclAuth.java` 加 `PasswordManager.init()` + `shutdown` hook（`ServerLifecycleEvents.SERVER_STOPPING`）
12. 修改 `lang/zh_cn.json` + `en_us.json` 新增消息 key
13. 修改 `README.md` 更新命令与配置说明
14. 编译验证 `gradlew.bat build`

***

## H. 风险与注意事项

1. **数据库驱动体积**：阶段1 +1.7MB（sqlite+HikariCP）；阶段3 累计 \~8MB。已确认全部 include
2. **异步 DB 访问**：玩家断线回调 null check；DB 长时间无响应 `onFailure` 通知玩家"验证服务暂时不可用"
3. **降级路径安全**：服务端严禁 `LOGGER.info`/`sendFeedback` 包含密码；用 `greedyString`；启动时若检测到 EssentialsX/CoreProtect 等已知 log 插件输出 WARN
4. **爆破防护**：在线 `LoginAttemptLimiter` 5 次失败锁 5 分钟（指数退避）；离线 PBKDF2 100k 迭代 + 16 字节盐；错误消息统一"账号或密码错误"防账号枚举
5. **与 PIN 流程协调**：`PasswordManager.login/register` 首行检查 `hasPendingLink`，冲突则提示先 `/iqcl link` 或 `/iqcl cancel`
6. **服务端 X25519 私钥**（阶段2）：存 `config/iqclauth/keys/server_x25519.json`，文件权限 600（best-effort）；密钥泄露风险=攻击者可解密传输中密码（但数据库哈希仍需爆破）；文档推荐定期轮换
7. **MongoDB 传递依赖**：`mongodb-driver-sync` 依赖 `bson` + `mongodb-driver-core`，需分别 `include` 三个 JAR
8. **配置热重载**（阶段3）：`/iqcl admin reloadstorage` 切换后端时先 `shutdown` 旧池再 `init` 新池，切换期间返回"存储正在重载"

***

## 验证方案

### 阶段 1 验收

1. 编译：`gradlew.bat build` 通过
2. 启动服务端 + 客户端（客户端**不装** mod）
3. 玩家进服 → 显示"PIN 登录/密码登录"两种引导
4. `/iqcl register password abc123 abc123` → 注册成功
5. `/iqcl register password abc123 abc123` → 报错"已注册"
6. `/iqcl login password abc123` → 登录成功，限制解除，从 Limbo 恢复
7. 重连 → 持久会话自动恢复
8. `/iqcl logout` → 重新受限
9. `/iqcl login password wrong` → 5 次后锁定 5 分钟
10. `/iqcl changepassword abc123 newpass123` → 改密成功
11. `/iqcl account` → 显示状态
12. `/iqcl admin unregister <player>` → 管理员删除账号
13. 检查 `config/iqclauth/passwords.db` 表结构与数据
14. 检查服务端日志**无密码明文**
15. 现有 PIN 登录 `/iqcl login pin <pin>` 仍正常工作

### 阶段 2 验收

1. 客户端装 mod，执行 `/iqcl login password abc123`，抓包确认 `c2s_password` 是密文
2. 客户端不装 mod，降级路径正常
3. 服务端日志无密码明文

### 阶段 3 验收

1. 切换 `passwordStorage.backend=mysql/postgres/mongo`，重启服务器
2. `/iqcl admin reloadstorage` 热切换
3. 4 种后端都能 register/login/changepassword/unregister

