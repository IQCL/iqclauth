# IQCL Auth — Fabric 1.20.1 双端认证模组

> 官方站点：<https://www.iqcl.de5.net> ｜ 源码仓库：<https://github.com/IQCL/iqclauth> ｜ 当前版本：`0.1.0-beta`

基于 Fabric Loader 的双端（客户端 + 服务端）认证模组，提供两种互相打通的登录方式，并内置会话治理、防多开、TOTP 2FA、Limbo 隔离区、坐标保护等完整安全栈。所有远程验证服务均由 **IQCL 官方域 `www.iqcl.de5.net`** 提供。

| 登录方式 | 加密通道 | 凭证存储 | 适用场景 |
| --- | --- | --- | --- |
| **PIN 登录**（远程验证） | 客户端 **RSA-OAEP-2048/SHA-256** 加密 PIN，服务端透明转发至 `https://www.iqcl.de5.net/api/verify-pin`，对返回的 **Ed25519** 签名执行规范化 JSON 验签 | 远程 IQCL 账号 | 与 IQCL 账号体系打通，跨服统一身份 |
| **密码登录**（本地验证，借鉴 EasyAuth 思路自主实现） | 客户端 / 服务端 **X25519 ECDH + AES-256-GCM** 加密通道 | 服务端本地 **PBKDF2WithHmacSHA256**（100k 迭代 + 16 字节盐），多存储后端 | 单服独立账号，无需 IQCL 账号即可使用 |

任一方式登录后即解锁所有限制，并写入持久会话；同 IP 重连可自动恢复，无需再次输入凭证。

## ⚠️ 重要安全声明

1. 模组内置固定 RSA 公钥、Ed25519 公钥、X25519 服务端公钥，仅适配 IQCL 官方验证服务 `https://www.iqcl.de5.net`；
2. 技术上任何人可修改源码替换内置公钥、把 API 指向仿冒验证服务器。开源协议仅约束代码版权，无法阻止此类篡改；
3. 客户端未安装本模组时，`/iqcl login pin` 指令会以明文经 MC 加密通道发送 PIN，存在严重安全风险，**强制要求双端均安装本模组**；
4. 模组仅提供通信加密方案，整体安全根基依赖：
   - PIN 登录路径：IQCL 远程验证服务器 + Ed25519 验签
   - 密码登录路径：服务端 PBKDF2 哈希 + X25519/AES-GCM 传输加密
5. **不使用 BouncyCastle**：Fabric Loader 嵌套 JAR 环境下 BouncyCastle JCE Provider 会导致认证失败，本模组全部加密原语（RSA-OAEP、Ed25519、X25519、AES-GCM、PBKDF2）均由 **JDK 17 内置 JCE** 提供。

## 安全模型

### PIN 登录（远程 IQCL 账号验证）

```
MC 客户端(模组)
  │  ① 本地拦截 /iqcl login pin <pin>，取消明文发送
  │  ② RSA-OAEP-2048/SHA-256 加密 {pin, bindTarget}
  │  ③ 组装 {v, ts, nonce, ciphertext} 通过自定义数据包发送
  ▼
MC 服务端(模组)   ← 不可信转发节点，无 RSA 私钥，不解密 ciphertext
  │  ④ 原样 POST 密文包 → https://www.iqcl.de5.net/api/verify-pin
  │     Header: Content-Type: application/json
  │            鉴权优先 X-Api-Id + X-Api-Key（成套模式），未配置时回退 X-Server-Key
  ▼
IQCL 验证服务器 (www.iqcl.de5.net)
  │  ⑤ RSA 解密 → 校验 PIN → 生成 Ed25519 签名响应
  ▼
MC 服务端(模组)
  │  ⑥ 规范化 JSON 序列化 payload → Ed25519 验签
  │  ⑦ 验签失败直接拒绝；成功则检查 permission，banned 拒绝
  ▼
MC 客户端(模组)   → 聊天框展示成功/失败
```

**硬性规则**：PIN 明文仅存在客户端本地；上行纯 RSA 非对称加密；下行 Ed25519 验签；两套密钥职责分离；MC 服务端永不持有 RSA 私钥。

### 密码登录（服务端本地验证）

```
玩家加入 → 服务端推送 s2c_authinfo（X25519 公钥 + 功能开关）
        ↓
客户端拦截 /iqcl login password / register / changepassword / unregister
        │  ① 生成临时 X25519 密钥对，与服务端静态公钥协商出共享密钥
        │  ② AES-256-GCM 加密 {op, payload, nonce}
        │  ③ 通过 c2s_password 通道发送
        ▼
服务端 PasswordNetworkHandler
  ① 用自身 X25519 静态私钥协商出同一共享密钥
  ② AES-GCM 解密（认证标签失败直接拒绝）
  ③ 在异步线程池执行 PBKDF2 校验 / 写库
  ④ 通过 s2c_result 回传结果
```

密码登录与 PIN 登录互通：任一方式登录后即解锁所有限制，并触发持久会话；密码登录成功后会提示执行 `/iqcl link` 通过 PIN 登录绑定 IQCL 账号（不强制）。绑定逻辑由 IQCL 后端接管，本地不存储 UUID↔displayId 关系。

## 功能矩阵

| 模块 | 功能 | 默认值 / 说明 |
| --- | --- | --- |
| **登录** | PIN 远程验证 | 强制双端模组 |
|  | 密码本地登录（注册 / 登录 / 改密 / 注销） | `passwordLoginEnabled=true` |
| **2FA** | TOTP（RFC 6238，兼容 Google Authenticator） | 30 秒步长、6 位、含重放防护；`totpEnabled=true` 总开关 |
| **会话** | 持久会话自动登录（同 IP 重连） | `persistentSession=true`，`sessionMaxAgeSeconds=28800`（8h） |
|  | 异地登录检测（IP 绑定） | `enableIpBinding=true` |
|  | 单账号唯一在线（防多开，异地登录踢旧连接） | `singleAccountOnline=true` |
|  | Session 保留时限（仅离线生效，在线玩家永不因 session 超时被踢） | `sessionTimeoutSeconds=1800` |
| **隔离** | Limbo 隔离区（清空背包 + 传送至天空平台） | `limboEnabled=true`，默认 (0, 200, 0) |
|  | 登录后恢复物品 / 位置 / 朝向 | `restoreOnLogin=true` |
|  | 坐标保护（登录时快照防离线篡改） | 内置实现 |
|  | 进服清空背包（防丢失） | `clearInventoryOnJoin=true` |
| **限制** | 视角 / 移动 / 破坏 / 攻击方块 / 放置 / 实体交互 / 实体攻击 / 物品使用 / 容器 / 聊天命令 | 全部独立布尔开关，宽限期后生效 |
|  | 登录超时自动踢出 | `loginTimeoutSeconds=300` |
|  | 宽限期 | `gracePeriodSeconds=15`，`-1` 关闭 |
| **存储** | SQLite / MySQL / PostgreSQL / MongoDB | 默认 SQLite，可热重载 |
| **防护** | 爆破锁定（5 次失败锁 5 分钟，指数退避封顶 1h） | `loginAttempt.*` |
|  | 密码策略（长度 / 复杂度 / 弱密码黑名单） | `passwordPolicy.*` |
| **集成** | game-session API（登录 / 登出通知 `www.iqcl.de5.net`） | `enableGameSessionApi=true` |
|  | LuckPerms 上下文（认证状态注入权限上下文） | 自动探测，未安装则跳过 |
|  | 多语言（zh_cn / en_us） | 跟随客户端语言 |
| **状态一致性** | 客户端/服务端认证状态同步 | 仅"登录成功"结果置位客户端状态；登出由 `s2c_logout` 通道统一重置；（重）进服自动清零本地状态 |
| **管理** | `/iqcl force` 强行登录、`/iqcl admin *` 管理、`/iqcl status/logout` | OP 2 级权限 |
| **环境检测** | 自动识别 CLIENT/SERVER 环境，单人/联机模式跳过服务端限制 | 基于 `EnvType` 检测 |

## 项目结构

```
iqclauth/
├── build.gradle                         # Loom 构建脚本，含数据库驱动嵌套 JAR
├── settings.gradle
├── gradle.properties                    # 版本与依赖配置（mod_version=0.1.0-beta）
├── gradle/wrapper/gradle-wrapper.properties
├── LICENSE                             # MPL-2.0
└── src/main/
    ├── resources/
    │   ├── fabric.mod.json              # 模组元数据，区分 main/client entrypoint
    │   └── assets/iqclauth/lang/
    │       ├── zh_cn.json               # 简体中文
    │       └── en_us.json               # 英文
    └── java/com/iqcl/auth/
        ├── IqclAuth.java                # 主入口（公共/服务端初始化）
        ├── client/
        │   ├── IqclAuthClient.java       # 客户端入口
        │   ├── PinChatInterceptor.java   # PIN 拦截 + RSA-OAEP 加密 + 发包
        │   ├── PasswordChatInterceptor.java # 密码命令拦截 + X25519/AES-GCM 加密
        │   ├── EcdhClient.java           # 客户端 X25519 密钥协商
        │   └── ClientAuthState.java      # 客户端本地认证状态
        ├── config/
        │   └── ModConfig.java           # JSON 配置（API 地址常量 + 全部开关）
        ├── context/
        │   └── LuckPermsContextProvider.java # LuckPerms 上下文注入
        ├── crypto/
        │   ├── Base64Utils.java
        │   ├── HexNonceGenerator.java   # 32 位 hex nonce
        │   ├── CanonicalJson.java       # 规范化 JSON 序列化（验签前必须使用）
        │   ├── RsaOaepEncryptor.java    # RSA-OAEP-2048/SHA-256（硬编码公钥）
        │   └── Ed25519Verifier.java     # Ed25519 验签（硬编码公钥，启动预热）
        ├── network/
        │   └── NetworkConstants.java    # 5 个通道 Identifier 常量
        ├── password/
        │   ├── AccountRecord.java
        │   ├── LoginAttemptLimiter.java # 爆破防护
        │   ├── PasswordCommandHandler.java # 密码命令处理
        │   ├── PasswordManager.java     # 密码管理 + TOTP 开关
        │   ├── PasswordPolicy.java      # 密码策略校验
        │   ├── crypto/
        │   │   ├── EcdhEncryptor.java   # X25519 + AES-256-GCM
        │   │   ├── PasswordHasher.java  # PBKDF2WithHmacSHA256
        │   │   ├── SaltGenerator.java
        │   │   ├── ServerKeyStore.java  # 服务端 X25519 静态密钥对
        │   │   └── TotpManager.java     # RFC 6238 TOTP
        │   ├── net/
        │   │   └── PasswordNetworkHandler.java # c2s_password 解密 + 派发
        │   └── storage/
        │       ├── AccountStorage.java          # 存储接口
        │       ├── AccountStorageFactory.java   # 工厂（按 backend 字段选择）
        │       ├── SqliteAccountStorage.java    # SQLite（默认）
        │       ├── MysqlAccountStorage.java
        │       ├── PostgresAccountStorage.java
        │       ├── MongoAccountStorage.java
        │       └── StorageExecutor.java         # 异步线程池
        └── server/
            ├── ApiGateway.java          # 远程 API 调用封装（成套鉴权 X-Api-Id/X-Api-Key，回退 X-Server-Key）
            ├── AuthState.java           # 玩家认证状态机
            ├── CommandRegistry.java     # /iqcl 全部指令注册
            ├── PlayerRestrictionManager.java # 行为限制（事件 + 包级双层）
            ├── PlayerSessionManager.java # Limbo / 持久会话 / 防多开 / 坐标快照
            ├── ServerNetworkHandler.java # PIN 密文转发 + Ed25519 验签
            └── SnapshotStore.java       # 物品 / 位置快照
```

> Fabric 1.20.1 使用旧版 Networking API v1（`Identifier` + `PacketByteBuf` + `ServerPlayNetworking.send`），不使用 1.20.2+ 的 `CustomPayload` / `PacketCodec` / `PayloadTypeRegistry` API。

### 自定义网络通道

| 通道 Identifier | 方向 | 用途 |
| --- | --- | --- |
| `iqclauth:c2s_verify` | C→S | RSA 加密后的 PIN 密文包 |
| `iqclauth:s2c_result` | S→C | 验签结果（成功/失败 + 消息） |
| `iqclauth:s2c_logout` | S→C | 登出通知（客户端重置本地状态） |
| `iqclauth:c2s_password` | C→S | X25519+AES-GCM 加密的密码操作包 |
| `iqclauth:s2c_authinfo` | S→C | 玩家加入时推送服务端 X25519 公钥 + 功能开关 |

## 编译

### 前置要求

- **JDK 17+**（Minecraft 1.20.1 最低要求，实测 JDK 21 可用；提供全部加密原语）
- **Gradle 8.6+**（或使用项目 wrapper）

### 生成 Gradle Wrapper（非必要）

项目附带 `gradle-wrapper.jar`（二进制文件）。若损坏请重新初始化：

```bash
cd f:\iqclauth
gradle wrapper --gradle-version 8.6
```

### 编译打包

```bash
# Windows
gradlew.bat build

# Linux/macOS
./gradlew build
```

产物位于 `build/libs/`：

- `iqclauth-0.1.0-beta.jar` — 模组主包（内含全部驱动嵌套 JAR：SQLite/MySQL/Postgres/MongoDB + HikariCP）
- `iqclauth-0.1.0-beta-sources.jar` — 源码包

## 部署

### 1. 安装模组

将 `iqclauth-0.1.0-beta.jar` 放入：

| 端 | mods 目录 |
| --- | --- |
| 客户端 | `.minecraft/mods/` |
| 服务端 | `<服务端目录>/mods/` |

> 客户端与服务端均需安装本模组，且均需安装 [Fabric API](https://modrinth.com/mod/fabric-api)。
> 客户端未安装本模组时，`/iqcl login pin` 指令将以明文发送至服务端，存在安全风险。

### 2. 配置服务端

首次启动服务端后，会在 `config/iqclauth.json` 生成默认配置。

#### 2.1 必填：服务端鉴权凭证（apiId + apiKey 成套模式，推荐）

模组对 `https://www.iqcl.de5.net` 的所有 API 调用（verify-pin、game-session/login、game-session/logout）均需鉴权，按 API 文档 2.3 节优先级：

1. **成套模式（推荐）**：`apiId` + `apiKey` 同时配置 → 请求头携带 `X-Api-Id` + `X-Api-Key`
2. **回退模式（兼容存量旧部署）**：未配置 apiId/apiKey → 请求头携带 `X-Server-Key`

```json
{
  "apiId": "REPLACE_WITH_YOUR_API_ID",
  "apiKey": "REPLACE_WITH_YOUR_API_KEY",
  "serverKey": "REPLACE_WITH_YOUR_X_SERVER_KEY"
}
```

凭证获取流程：

1. 在 **[IQCL | API 中心](https://www.iqcl.de5.net/developer/)**（官网页脚点击"开发者"或"API 管理"）申请 API 调用凭证（成套的 `apiId` + `apiKey`，或存量 `serverKey`）；
2. 若需走工单审核，请在 **[IQCL | 工单中心](https://www.iqcl.de5.net/tickets/)** 提交工单，填入服务器信息及能证明你是所有人的详尽材料；
3. 等待审核通过，在 **[IQCL | API 中心](https://www.iqcl.de5.net/developer/)** 查看并复制你的凭证；
4. 填入 `config/iqclauth.json` 后重启服务端。

字段说明：

| 字段 | 鉴权模式 | 请求头 | 说明 |
| --- | --- | --- | --- |
| `apiId` | 成套模式（优先） | `X-Api-Id` | API 调用标识（如 `mc_login_1`），必须为 `mc_login` 用途 |
| `apiKey` | 成套模式（优先） | `X-Api-Key` | 与 `apiId` 配套的密钥，必须同时配置才能启用成套模式 |
| `serverKey` | 回退模式（兼容） | `X-Server-Key` | 存量旧密钥，仅在 apiId/apiKey 未成套配置时使用 |

> **鉴权规则**：
> - `apiId` 与 `apiKey` 必须成套配置（两者同时提供），缺一不可；
> - 仅配置其中之一时启动会告警，并自动回退使用 `serverKey`；
> - 两者均未配置（保持 `REPLACE_WITH` 前缀）时使用 `serverKey`；
> - **`apiKey` 为服务器凭证，仅由 MC 服务端持有，禁止硬编码到客户端模组**。客户端密文包仅含 `v/ts/nonce/ciphertext`，由 MC 服务端转发时附加鉴权请求头（符合"MC 服务端为不可信转发节点，仅透明转发密文包"的架构约束）。

#### 2.2 远程 API 地址（硬编码常量，不可修改）

```java
public static final String VERIFY_API_URL        = "https://www.iqcl.de5.net/api/verify-pin";
public static final String GAME_SESSION_LOGIN_URL = "https://www.iqcl.de5.net/api/game-session/login";
public static final String GAME_SESSION_LOGOUT_URL = "https://www.iqcl.de5.net/api/game-session/logout";
```

> 以上常量硬编码于 `ModConfig.java`，禁止修改，防止被篡改指向恶意服务器。客户端不需要配置（RSA / Ed25519 / X25519 公钥已硬编码于代码中）。

#### 2.3 完整配置项

| 分组 | 字段 | 默认值 | 说明 |
| --- | --- | --- | --- |
| 基础 | `serverKey` | `REPLACE_WITH_YOUR_X_SERVER_KEY` | 存量旧密钥，作为 `X-Server-Key` 请求头；仅在 apiId/apiKey 未成套配置时回退使用 |
|  | `apiId` | `REPLACE_WITH_YOUR_API_ID` | API 调用标识（如 `mc_login_1`），作为 `X-Api-Id` 请求头；必须为 `mc_login` 用途且与 `apiKey` 同一所有者 |
|  | `apiKey` | `REPLACE_WITH_YOUR_API_KEY` | 与 `apiId` 配套的密钥，作为 `X-Api-Key` 请求头；必须与 `apiId` 成套配置才能启用成套鉴权模式 |
|  | `gracePeriodSeconds` | `15` | 进服宽限期（秒）。`-1`=关闭，`0`=立即限制 |
|  | `loginTimeoutSeconds` | `300` | 未登录超时踢出（秒）。`0`=不限制 |
|  | `sessionTimeoutSeconds` | `1800` | 会话保留时限（秒），仅对离线玩家生效：在线玩家绝不因 session 超时被踢；退出游戏后开始计时，时限内重连自动恢复登录，超过后需重新输入凭证。`0`=不限制 |
| 账号关联 | `requireLink` | 已移除 | 绑定逻辑已由 IQCL 后端接管，本地不再存储 UUID↔displayId 关系 |
| Limbo 隔离区 | `limboEnabled` | `true` | 启用 Limbo（false 则原地冻结） |
|  | `limboDimension` | `minecraft:overworld` | 隔离区维度 |
|  | `limboX` / `limboY` / `limboZ` | `0` / `200` / `0` | 隔离区坐标（Y 建议 ≥200） |
|  | `limboGeneratePlatform` | `true` | 是否在隔离区下方生成 5×5 石头+玻璃垫脚平台（关闭适用于已有现成平台的隔离区） |
|  | `restoreOnLogin` | `true` | 登录后恢复物品 / 位置 / 朝向 |
|  | `clearInventoryOnJoin` | `true` | 进服立即清空背包 |
| 持久会话 | `persistentSession` | `true` | 同 IP 重连自动登录 |
|  | `sessionMaxAgeSeconds` | `28800` | 会话有效期（8h）。`0`=永不过期 |
|  | `trustIp` | `true` | 同 IP 自动恢复 |
|  | `enableIpBinding` | `true` | IP 绑定（防异地登录） |
| 单账号在线 | `singleAccountOnline` | `true` | 同账号禁止多设备同时在线 |
| 未登录限制 | `restrictViewRotation` | `true` | 锁定视角 |
|  | `restrictMovement` | `true` | 禁止移动 |
|  | `restrictBlockBreak` | `true` | 禁止破坏方块 |
|  | `restrictBlockAttack` | `true` | 禁止攻击方块 |
|  | `restrictBlockUse` | `true` | 禁止放置 / 使用方块 / 打开容器 |
|  | `restrictEntityInteract` | `true` | 禁止右键实体 |
|  | `restrictEntityAttack` | `true` | 禁止攻击实体 |
|  | `restrictItemUse` | `true` | 禁止使用物品 |
|  | `restrictContainerOpen` | `true` | 强制关闭容器 GUI |
|  | `restrictChatAndCommands` | `true` | 禁止除 `/iqcl` 外的聊天 / 命令 |
| Game Session | `enableGameSessionApi` | `true` | 玩家登录 / 登出时通知 `www.iqcl.de5.net` |
| 密码登录 | `passwordLoginEnabled` | `true` | 启用密码登录子命令 |
|  | `promptIqclLinkAfterPasswordLogin` | `true` | 密码登录成功后提示关联 IQCL 账号 |
|  | `totpEnabled` | `true` | TOTP 总开关。`false` 时所有 TOTP 命令拒绝执行，密码登录跳过 TOTP 步骤（即使账号已配置 TOTP） |
| 密码策略 | `passwordPolicy.minPasswordLength` | `8` | 密码最小长度 |
|  | `passwordPolicy.maxPasswordLength` | `64` | 密码最大长度 |
|  | `passwordPolicy.requireLetter` | `true` | 必须包含字母 |
|  | `passwordPolicy.requireDigit` | `true` | 必须包含数字 |
|  | `passwordPolicy.requireSpecialChar` | `false` | 必须包含特殊字符 |
|  | `passwordPolicy.allowSpace` | `false` | 是否允许空格 |
|  | `passwordPolicy.weakPasswordCheckLevel` | `1` | 弱密码检查（0=关，1=基础黑名单） |
| 密码哈希 | `passwordHash.iterations` | `100000` | PBKDF2 迭代次数 |
|  | `passwordHash.saltBytes` | `16` | 盐长度（字节） |
|  | `passwordHash.hashBits` | `256` | 哈希位数（PBKDF2WithHmacSHA256） |
| 爆破防护 | `loginAttempt.maxLoginAttempts` | `5` | 最大失败次数 |
|  | `loginAttempt.lockSeconds` | `300` | 锁定时长（秒） |
|  | `loginAttempt.exponentialBackoff` | `true` | 指数退避 |
|  | `loginAttempt.maxLockSeconds` | `3600` | 单次锁定上限（秒） |
| 存储后端 | `passwordStorage.backend` | `sqlite` | `sqlite` / `mysql` / `postgres` / `mongo` |
|  | `passwordStorage.sqliteFile` | `config/iqclauth/passwords.db` | SQLite 文件路径 |
|  | `passwordStorage.mysqlHost` / `mysqlPort` / `mysqlDatabase` / `mysqlUser` / `mysqlPassword` / `mysqlTablePrefix` / `mysqlUseSsl` | `localhost` / `3306` / `iqclauth` / `iqclauth` / `""` / `iqclauth_` / `true` | MySQL 连接参数 |
|  | `passwordStorage.postgresHost` / `postgresPort` / `postgresDatabase` / `postgresSchema` / `postgresUser` / `postgresPassword` | `localhost` / `5432` / `iqclauth` / `public` / `iqclauth` / `""` | PostgreSQL 连接参数 |
|  | `passwordStorage.mongoUri` / `mongoHost` / `mongoPort` / `mongoDatabase` / `mongoCollection` | `""` / `localhost` / `27017` / `iqclauth` / `accounts` | MongoDB 连接参数（`mongoUri` 非空时优先） |

### 3. 使用

#### 3.0 命令速查表

| 命令 | 说明 | 权限 |
| --- | --- | --- |
| `/iqcl login pin <PIN码>` | PIN 登录（客户端 RSA 加密，远程 IQCL 验证），成功后自动绑定 IQCL 账号 | 所有玩家 |
| `/iqcl login password <密码>` | 密码登录（本服本地验证，ECDH+AES-GCM 加密通道） | 所有玩家 |
| `/iqcl login confirmtotp <验证码>` | 密码登录后的 TOTP 二次验证确认 | 所有玩家 |
| `/iqcl register password <密码> <确认密码>` | 注册本服密码账号（与游戏 UUID 绑定） | 所有玩家 |
| `/iqcl changepassword <旧密码> <新密码>` | 修改密码 | 需已登录 |
| `/iqcl unregister password <密码>` | 注销密码账号 | 需已登录 |
| `/iqcl enablerotp` | 开启 TOTP 双因素认证（输出二维码/secret） | 需已登录，`totpEnabled=true` |
| `/iqcl confirmtotp <验证码>` | 确认开启 TOTP | 需已登录 |
| `/iqcl disablerotp <密码>` | 关闭 TOTP（需密码确认） | 需已登录 |
| `/iqcl account` | 查看自身账号状态（认证 / 密码账号 / TOTP） | 所有玩家 |
| `/iqcl link` | 绑定 IQCL 账号引导（详见 [3.2](#32-密码登录本服本地验证) 与关键行为规则） | 所有玩家 |
| `/iqcl status` | 查看自己的认证状态 | 所有玩家 |
| `/iqcl status <player>` | 查看指定玩家认证状态 | OP 2 |
| `/iqcl logout` | 主动登出（送回 Limbo，下次登录回到登出前位置） | 所有玩家 |
| `/iqcl logout <player>` | 管理员登出指定玩家 | OP 2 |
| `/iqcl force <player>` | 绕过验证强行登录玩家 | OP 2 |
| `/iqcl admin unregister <player>` | 强制删除玩家密码账号 | OP 2 |
| `/iqcl admin resetpassword <player>` | 重置玩家密码为临时随机串 | OP 2 |
| `/iqcl admin reloadstorage` | 热重载存储后端配置 | OP 2 |

> PIN / 密码 / TOTP 相关凭证均由客户端拦截器加密后通过自定义数据包发送，明文不会进入服务端日志或命令记录。

#### 3.1 PIN 登录（远程 IQCL 账号验证）

```
/iqcl login pin ABCD-EFGH-JKLM
```

模组将：

1. 客户端本地拦截该指令（明文不发送至服务端）；
2. RSA-OAEP 加密后通过 `iqclauth:c2s_verify` 通道发送；
3. 服务端转发至 `https://www.iqcl.de5.net/api/verify-pin`；
4. 服务端对响应执行 Ed25519 验签后回传客户端；
5. 聊天框显示 `[IQCL] PIN 验证成功，登录已放行` 或失败信息；
6. PIN 登录成功后若返回 displayId，自动显示绑定信息（可在 IQCL 安全中心（用户中心进入）查看或解绑）。

#### 3.2 密码登录（本服本地验证）

```
# 首次使用：注册密码账号（与游戏 UUID 绑定）
/iqcl register password <密码> <确认密码>

# 登录
/iqcl login password <密码>

# 修改密码（需已登录）
/iqcl changepassword <旧密码> <新密码>

# 注销密码账号（需已登录，需确认密码）
/iqcl unregister password <密码>

# 查看自身账号状态（密码账号 / 当前认证 / TOTP）
/iqcl account

# 绑定 IQCL 账号：
#   未登录 → 提示用 PIN 登录
#   已 PIN 登录 → 展示当前绑定信息，不登出
#   已密码/TOTP 登录 → 自动登出并送回隔离区，要求 PIN 重新登录绑定
/iqcl link
```

#### 3.3 TOTP 二次验证（RFC 6238，兼容 Google Authenticator）

```
# 开启 TOTP（输出二维码 / secret，扫码导入 Authenticator）
/iqcl enablerotp

# 确认开启（输入 Authenticator 当前 6 位码）
/iqcl confirmtotp <code>

# 关闭 TOTP（需密码确认）
/iqcl disablerotp <密码>
```

启用后，密码登录成功不会立即放行，会要求输入 `/iqcl login confirmtotp <code>`；PIN 登录若关联账号开启了 TOTP 也会触发。将 `totpEnabled` 设为 `false` 可全局关闭 TOTP：所有 TOTP 命令拒绝执行，密码登录直接放行。

#### 3.4 会话与登出

```
# 主动登出（送回 Limbo，下次登录回到登出前位置）
/iqcl logout

# 查看自己 / 他人状态
/iqcl status
/iqcl status <player>      # OP 2

# 管理员登出他人
/iqcl logout <player>      # OP 2
```

> 启用 `persistentSession` 后，同 IP 在 `sessionMaxAgeSeconds` 内重连将自动恢复登录状态，无需再次输入凭证。若同时启用 `enableIpBinding`，IP 不一致会触发会话锁定，要求重新认证。

#### 3.5 管理员命令（需 OP 2 级或服务端控制台）

```
/iqcl force <player>               # 绕过 PIN 验证强行登录
/iqcl admin unregister <player>    # 强制删除玩家密码账号
/iqcl admin resetpassword <player> # 重置玩家密码为临时随机串（输出给管理员）
/iqcl admin reloadstorage          # 热重载存储后端配置（切换 SQLite→MySQL 等）
```

#### 3.6 关键行为规则

- **单人/联机模式兼容**：模组自动检测运行环境（`EnvType.CLIENT` vs `EnvType.SERVER`）。在单人游戏或联机模式（集成服务器）下，模组会跳过所有服务端限制器、密码存储和网络处理器的注册，玩家不会被强制要求登录。进入游戏时会显示提示：
  ```
  ====================================
  [IQCL] 当前处于单人/联机模式
  IQCL Auth 登录功能仅在安装了该模组的专用服务器上可用
  ====================================
  ```
  尝试 `/iqcl login` 等命令时会提示"当前处于单人/联机模式，IQCL Auth 登录需在安装了本模组的专用服务器上使用"。
- **进服流程**：玩家加入 → 进服清空背包（若启用） → 传送至 Limbo 隔离区 → 宽限期内可自由活动 → 超过宽限期触发全部限制 → 登录超时未登录则踢出。
- **在线玩家永不因 session 超时被踢**：已认证玩家在线期间始终视为活动中（每 tick 刷新活动时间），无论是否在移动都不会被 session 超时踢出；`sessionTimeoutSeconds` 仅在玩家退出游戏后开始计时：时限内重连可自动恢复登录，超过后持久会话失效，需重新输入凭证。
- **登录恢复**：登录成功后，从快照恢复物品、坐标、朝向（不会丢失钻石装备，也不会被传送到出生点）。
- **登出流程**：先快照当前位置 / 物品 → 通知客户端重置 → 传送回 Limbo。下次登录会回到登出前位置。登出后未登录超时与宽限期从登出时刻重新起算，不会被立即踢出。
- **登录状态一致性**：客户端本地认证状态仅由真正的"登录成功"结果置位（PIN 放行 / 密码登录成功 / 持久会话自动恢复 / 管理员强行登录）；注册、改密、重复登录拒绝等结果只展示不改变状态；登出统一由 `s2c_logout` 通道重置双端状态；玩家（重）进服时客户端自动清零本地状态，避免残留旧状态导致误拦登录。
- **防多开**：同一 IQCL 账号 / 同一 UUID 在新设备登录时，旧连接被踢下线。
- **game-session 通知**：登录调用 `POST /api/game-session/login`，登出 / 断线调用 `POST /api/game-session/logout`，请求头鉴权与 verify-pin 一致（优先 `X-Api-Id` + `X-Api-Key` 成套模式，回退 `X-Server-Key`），请求体包含 `mcUUID` 与可选 `username`。
- **爆破防护**：5 次失败后锁定 5 分钟，指数退避封顶 1 小时。
- **重复登录拦截**：登录成功后再次执行登录命令在客户端与服务端双层拦截；拒绝结果以失败状态回传，不会被客户端误判为登录成功。
- **IQCL 账号绑定**：绑定逻辑由 IQCL 后端接管，本地不存储 UUID↔displayId 关系。PIN 登录成功后自动展示绑定信息，可在 [IQCL 安全中心](https://www.iqcl.de5.net/auth/user/#security)（用户中心进入）查看或解绑。若后端返回 UUID 绑定冲突（MC UUID 已绑定其他用户），模组会显示友好提示。
- **`/iqcl link`**：引导玩家通过 PIN 登录绑定 IQCL 账号，按当前登录方式分三种行为：
  - 未登录 → 提示使用 `/iqcl login pin` 登录；
  - 已通过 PIN 登录（会话内有 displayId）→ 展示当前绑定信息，不登出；
  - 已通过密码/TOTP 登录 → 真正执行登出（清除服务端认证状态 + 防多开绑定清理 + 通知客户端重置 + 送回隔离区），并明确提示用 PIN 重新登录完成绑定。

## 验证服务器接口约定

### 请求（MC 服务端 → `https://www.iqcl.de5.net/api/verify-pin`）

```
POST /api/verify-pin
Content-Type: application/json
# 鉴权（API 文档 2.3 节，按优先级）：
#   优先：X-Api-Id: <配置的 apiId>  +  X-Api-Key: <配置的 apiKey>   （成套模式）
#   回退：X-Server-Key: <配置的 serverKey>                            （存量旧密钥）
```

请求体（客户端构造的完整密文包，MC 服务端原样转发，不插入任何字段）：

```json
{
  "v": 1,
  "ts": 1785665824000,
  "nonce": "a1b2c3d4e5f67890a1b2c3d4e5f67890",
  "ciphertext": "<base64 编码的 256 字节 RSA 密文>"
}
```

验证服务器使用对应 RSA-OAEP 私钥解密 `ciphertext`，得到：

```json
{"pin":"ABCD-EFGH-JKLM","bindTarget":"069a79f4-44e9-4726-a5be-fca90e38aaf5"}
```

> `bindTarget` 即 PIN 绑定的 MC 玩家 UUID（用户生成 PIN 时填写），服务器解密后与 `temp_pin.bind_target` 严格相等比较。

### 响应（验证服务器 → MC 服务端）

```json
{
  "success": true,
  "serverTs": 1785665824123,
  "payload": {
    "v": 1,
    "ts": 1785665824123,
    "nonce": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
    "displayId": 1024,
    "username": "Steve",
    "permission": "formal",
    "mcUUID": "069a79f4-44e9-4726-a5be-fca90e38aaf5",
    "pinFingerprint": "5e884898da2804715"
  },
  "signature": "<base64 编码的 64 字节 Ed25519 签名>"
}
```

**payload 字段**（API 文档 2.6 节）：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `v` | number | 协议版本 `1` |
| `ts` | number | 服务器时间戳（与 `serverTs` 一致） |
| `nonce` | string | 服务器新生成的 32 位随机串，供下行防重放 |
| `displayId` | number \| null | 用户显示 ID |
| `username` | string \| null | 用户名 |
| `permission` | string | 权限等级：`trial` / `formal` / `banned` |
| `mcUUID` | string | PIN 绑定的 MC 玩家 UUID（回显，供服务端核对） |
| `pinFingerprint` | string | PIN 的 SHA-256 前 16 位 hex（不泄露 PIN 明文） |

**签名规则**：对 `payload` 对象执行规范化 JSON 序列化（key 字典序升序、无多余空格、无换行）后，用 Ed25519 私钥对 UTF-8 字节签名。

MC 服务端使用硬编码 Ed25519 公钥验签，验签失败直接拒绝登录。验签成功后额外检查：`permission` 为 `banned` 拒绝；`mcUUID` 回显与当前玩家 UUID 不一致拒绝。

### game-session 接口

```
POST /api/game-session/login     # 玩家登录成功时调用
POST /api/game-session/logout    # 玩家登出 / 断线时调用
# 鉴权（与 verify-pin 一致，按优先级）：
#   优先：X-Api-Id: <apiId>  +  X-Api-Key: <apiKey>   （成套模式）
#   回退：X-Server-Key: <serverKey>                      （存量旧密钥）
Body:  { "mcUUID": "<玩家UUID>", "username": "<可选，玩家名>" }
```

## 加密参数（不可修改）

| 参数 | 值 |
| --- | --- |
| RSA 模长 | 2048 bit |
| RSA 填充 | OAEP |
| OAEP 哈希 | SHA-256 |
| MGF1 哈希 | SHA-256 |
| OAEP Label | 空 |
| Ed25519 | RFC 8032 标准 |
| X25519 | RFC 7748 标准 |
| AES-GCM | 256 位密钥 + 96 位 IV + 128 位认证标签 |
| PBKDF2 | HmacSHA256，100k 迭代，16 字节盐 |
| TOTP | RFC 6238，30 秒步长，6 位数字 |
| Nonce | 32 位十六进制随机串（16 字节） |
| 时间戳 | UTC 毫秒 |

## 依赖

| 依赖 | 版本 | 用途 | 打包方式 |
| --- | --- | --- | --- |
| Minecraft | 1.20.1 | — | — |
| Fabric Loader | ≥0.15.0 | 模组加载器 | — |
| Fabric API | 0.92.2+1.20.1 | 事件、网络、命令 API | — |
| SQLite JDBC | 3.46.1.3 | 密码默认存储后端 | 嵌套 JAR |
| HikariCP | 5.1.0 | JDBC 连接池 | 嵌套 JAR |
| MySQL Connector/J | 8.3.0 | MySQL 存储后端 | 嵌套 JAR |
| PostgreSQL JDBC | 42.7.3 | PostgreSQL 存储后端 | 嵌套 JAR |
| MongoDB Driver Sync | 4.11.1 | MongoDB 存储后端 | 嵌套 JAR |
| Java | ≥17 | RSA-OAEP / Ed25519 / X25519 / AES-GCM / PBKDF2 均由 JDK 内置 JCE 提供 | — |

## 相关链接

| 名称 | 地址 |
| --- | --- |
| 官方站点 / 主页 | <https://www.iqcl.de5.net> |
| GitHub 仓库 | <https://github.com/IQCL/iqclauth> |
| 工单中心（申请 API 凭证 ） | <https://www.iqcl.de5.net/tickets/> |
| 用户中心（兑换凭证 / 进入安全中心） | <https://www.iqcl.de5.net/auth/user/> |
| API 中心（兑换/查看 apiId + apiKey 成套凭证） | <https://www.iqcl.de5.net/api-center/> |
| 安全中心（查看/解绑账号关联） | <https://www.iqcl.de5.net/auth/user/#security> |
| PIN 验证 API | `https://www.iqcl.de5.net/api/verify-pin` |
| Game Session API | `https://www.iqcl.de5.net/api/game-session/login`、`/api/game-session/logout` |
| Issue 反馈 | <https://github.com/IQCL/iqclauth/issues> |

## 开源协议

本项目 **IQCLAuth** 采用 **Mozilla Public License 2.0 (MPL-2.0)**。

简单通俗说明：

1. 任何人可以自由修改、分发、商用本项目代码；
2. **如果你修改了本项目原有源码文件**，修改后的源码必须公开，保持 MPL-2.0 协议；
3. **独立新增的代码、新增类、拓展模块（全新文件）不受传染，可以闭源、私有、商用；**
4. 衍生作品不强制整体开源，仅改动过的原始文件需要开源；
5. 不允许移除源码内版权与协议声明。

完整协议文本见项目根目录 `LICENSE`：<https://mozilla.org/MPL/2.0/>

### 额外社区约束（非协议强制条款）

禁止未经作者许可，修改内置 RSA / Ed25519 / X25519 公钥搭建仿冒 IQCLAuth 验证服务（指向非 `www.iqcl.de5.net` 的域名）用于盈利。

## 免责声明

本模组按照「原样」提供，不附带任何明示或隐含担保。
开发者不对因使用、二次修改本模组产生的账号被盗、服务器入侵、数据泄露等一切损失承担责任。
