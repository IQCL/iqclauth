# IQCL Auth — Fabric 1.20.1 双端认证模组

基于 Fabric Loader 的双端（客户端 + 服务端）PIN 认证模组。
客户端使用 **RSA-OAEP-2048/SHA-256** 加密 PIN，服务端作为不可信透明转发节点将密文 POST 至远程验证服务器，并对验证服务器返回的 **Ed25519** 签名执行规范化 JSON 验签。

## ⚠️ 重要安全声明
1. 模组内置固定 RSA 公钥、Ed25519 公钥，仅适配 IQCL 官方验证服务；
2. 技术上任何人可修改源码替换内置公钥，搭建仿冒验证服务。开源协议仅约束代码版权，无法阻止此类篡改；
3. 客户端未安装本模组时，`/iqcl login pin` 指令会明文发送 PIN，存在严重安全风险；
4. 模组仅提供通信加密方案，整体安全根基依赖远程验证服务器。

## 安全模型

```
MC 客户端(模组)
  │  ① 本地拦截 /iqcl login pin <pin>，取消明文发送
  │  ② RSA-OAEP-2048/SHA-256 加密 {pin, bindTarget}
  │  ③ 组装 {v, ts, nonce, ciphertext} 通过自定义数据包发送
  ▼
MC 服务端(模组)   ← 不可信转发节点，无 RSA 私钥，不解密 ciphertext
  │  ④ 原样 POST 密文包 → 验证服务器 /api/verify-pin
  │     Header: Content-Type: application/json, X-Server-Key: <配置>
  ▼
远程验证服务器
  │  ⑤ RSA 解密 → 校验 PIN → 生成 Ed25519 签名响应
  ▼
MC 服务端(模组)
  │  ⑥ 规范化 JSON 序列化 payload → Ed25519 验签
  │  ⑦ 验签失败直接拒绝；成功则检查 permission，banned 拒绝
  ▼
MC 客户端(模组)   → 聊天框展示成功/失败
```

**硬性规则**：PIN 明文仅存在客户端本地；上行纯 RSA 非对称加密；下行 Ed25519 验签；两套密钥职责分离；MC 服务端永不持有 RSA 私钥。

## 项目结构

```
iqclauth/
├── build.gradle                         # Loom 构建脚本，含 BouncyCastle 依赖
├── settings.gradle
├── gradle.properties                    # 版本与依赖配置
├── gradle/wrapper/gradle-wrapper.properties
├── LICENSE
└── src/main/
    ├── resources/
    │   └── fabric.mod.json              # 模组元数据，区分 main/client entrypoint
    └── java/com/iqcl/auth/
        ├── IqclAuth.java                # 主入口（公共/服务端初始化）
        ├── client/
        │   ├── IqclAuthClient.java      # 客户端入口
        │   └── PinChatInterceptor.java  # 聊天拦截 + RSA 加密 + 发包
        ├── server/
        │   └── ServerNetworkHandler.java# 密文转发 + Ed25519 验签 + 结果回传
        ├── config/
        │   └── ModConfig.java           # JSON 配置（API 地址 + X-Server-Key）
        ├── crypto/
        │   ├── Base64Utils.java         # Base64 编解码
        │   ├── HexNonceGenerator.java   # 32 位 hex nonce 生成
        │   ├── CanonicalJson.java       # 规范化 JSON 序列化（验签前必须使用）
        │   ├── RsaOaepEncryptor.java    # RSA-OAEP-2048/SHA-256 加密（含硬编码公钥）
        │   └── Ed25519Verifier.java     # Ed25519 验签（含硬编码公钥）
        └── network/
            └── NetworkConstants.java    # 通道 Identifier 常量
```

> Fabric 1.20.1 使用旧版 Networking API v1（`Identifier` + `PacketByteBuf` + `PlayChannelHandler`），
> 不使用 1.20.2+ 的 `CustomPayload` / `PacketCodec` / `PayloadTypeRegistry` API。

## 编译

### 前置要求

- **JDK 17+**（Minecraft 1.20.1 最低要求，实测 JDK 21 可用）
- **Gradle 8.6+**（或使用项目 wrapper）

### 生成 Gradle Wrapper（首次）

项目未附带 `gradle-wrapper.jar`（二进制文件）。若系统已安装 Gradle：

```bash
cd f:\iqclauth
gradle wrapper --gradle-version 8.6
```

生成后即可使用 `gradlew` / `gradlew.bat`。

### 编译打包

```bash
# Windows
gradlew.bat build

# Linux/macOS
./gradlew build
```

产物位于 `build/libs/`：
- `iqclauth-0.0.1-alpha.jar` — 模组主包（内含 BouncyCastle 嵌套 JAR）
- `iqclauth-0.0.1-alpha-sources.jar` — 源码包

## 部署

### 1. 安装模组

将 `iqclauth-0.0.1-alpha.jar` 放入：

| 端 | mods 目录 |
|---|---|
| 客户端 | `.minecraft/mods/` |
| 服务端 | `<服务端目录>/mods/` |

> 客户端与服务端均需安装本模组，且均需安装 [Fabric API](https://modrinth.com/mod/fabric-api)。
> 客户端未安装本模组时，`/iqcl login pin` 指令将以明文发送至服务端，存在安全风险。

### 2. 配置服务端

首次启动服务端后，会在 `config/iqclauth.json` 生成默认配置：

```json
{
  "verifyApiUrl": "https://your-verify-server.example.com/api/verify-pin",
  "serverKey": "REPLACE_WITH_YOUR_X_SERVER_KEY"
}
```

修改为实际值后重启服务端：

| 字段 | 说明 |
|---|---|
| `verifyApiUrl` | 远程验证服务器 `/api/verify-pin` 完整 URL |
| `serverKey` | 服务端身份密钥，作为 `X-Server-Key` 请求头发送 |

> 配置仅服务端读取。客户端不需要配置（RSA 公钥与 Ed25519 公钥已硬编码于代码中）。

### 3. 使用

在游戏内聊天框输入：

```
/iqcl login pin ABCD-EFGH-JKLM
```

模组将：
1. 本地拦截该指令（明文不发送至服务端）
2. RSA-OAEP 加密后通过自定义数据包发送
3. 服务端转发至验证服务器
4. 服务端验签后将结果回传客户端
5. 聊天框显示 `[IQCL] PIN 验证成功，登录已放行` 或失败信息

## 验证服务器接口约定

### 请求（MC 服务端 → 验证服务器）

```
POST /api/verify-pin
Content-Type: application/json
X-Server-Key: <配置的服务端密钥>
```

请求体（客户端构造的完整密文包，原样转发）：

```json
{
  "v": 1,
  "ts": 1785665824000,
  "nonce": "a1b2c3d4e5f67890a1b2c3d4e5f67890",
  "ciphertext": "<base64 编码的 256 字节 RSA 密文>"
}
```

验证服务器需使用对应的 RSA-OAEP 私钥解密 `ciphertext`，得到：

```json
{"pin":"ABCD-EFGH-JKLM","bindTarget":"069a79f4-44e9-4726-a5be-fca90e38aaf5"}
```

### 响应（验证服务器 → MC 服务端）

```json
{
  "success": true,
  "serverTs": 1785665824123,
  "payload": {
    "permission": "default",
    "playerName": "Notch",
    "expireAt": 1798761600000
  },
  "signature": "<base64 编码的 64 字节 Ed25519 签名>"
}
```

**签名规则**：对 `payload` 对象执行规范化 JSON 序列化（key 字典序升序、无多余空格、无换行）后，用 Ed25519 私钥对 UTF-8 字节签名。

MC 服务端使用硬编码 Ed25519 公钥验签，验签失败直接拒绝登录。

## 加密参数（不可修改）

| 参数 | 值 |
|---|---|
| RSA 模长 | 2048 bit |
| RSA 填充 | OAEP |
| OAEP 哈希 | SHA-256 |
| MGF1 哈希 | SHA-256 |
| OAEP Label | 空 |
| Ed25519 | RFC 8032 标准 |
| Nonce | 32 位十六进制随机串（16 字节） |
| 时间戳 | UTC 毫秒 |

## 依赖

| 依赖 | 版本 | 用途 |
|---|---|---|
| Minecraft | 1.20.1 | — |
| Fabric Loader | ≥0.15.11 | 模组加载器 |
| Fabric API | 0.92.2+1.20.1 | 事件、网络 API |
| BouncyCastle | 1.78.1 (jdk18on) | RSA-OAEP + Ed25519 |
| Java | ≥17 | — |

## 开源协议
本项目 
**IQCLAuth** 采用 **Mozilla Public License 2.0 (MPL-2.0)**

简单通俗说明：
1. 任何人可以自由修改、分发、商用本项目代码；
2. **如果你修改了本项目原有源码文件**，修改后的源码必须公开，保持MPL-2.0协议；
3. **独立新增的代码、新增类、拓展模块（全新文件）不受传染，可以闭源、私有、商用；**
4. 衍生作品不强制整体开源，仅改动过的原始文件需要开源；
5. 不允许移除源码内版权与协议声明。

完整协议文本见项目根目录 LICENSE
https://mozilla.org/MPL/2.0/

### 额外社区约束（非协议强制条款）
禁止未经作者许可，修改内置公钥搭建仿冒IQCLAuth验证服务用于盈利。

## 免责声明
本模组按照「原样」提供，不附带任何明示或隐含担保。
开发者不对因使用、二次修改本模组产生的账号被盗、服务器入侵、数据泄露等一切损失承担责任。