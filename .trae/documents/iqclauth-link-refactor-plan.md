# IQCL Auth 关联逻辑重构与配置增强方案

## Context（背景）

后端已实现 IQCL 账号绑定逻辑，会在 PIN 验证时返回 UUID 绑定冲突错误。当前模组在本地用 `LinkStore` 持久化 UUID↔displayId 绑定关系，这会导致用户在 IQCL 安全中心解绑后本地仍残留旧数据。需要：

1. 捕获验证服务器下发的"UUID 绑定冲突"错误并给出友好提示
2. 重构 `/iqcl link` 指令：仅密码/TOTP 登录的用户执行时自动登出，要求用 PIN 重新登录
3. 删除本地绑定持久化（LinkStore），改为 PIN 登录后临时显示绑定信息，不落盘
4. 新增配置项：Limbo 垫脚方块开关、TOTP 开关
5. 补全缺失版权头，更新 README

## 实施步骤

### 1. 删除 LinkStore.java

删除 `src/main/java/com/iqcl/auth/server/LinkStore.java`（本地 UUID↔displayId 持久化存储，后端已接管该逻辑）。

### 2. 重构 AuthState.java

**移除**：`linked`/`pendingDisplayId`/`pendingUsername`/`linkedDisplayId`/`linkedUsername` 字段及 `authenticateWithAccount`/`confirmLink`/`cancelPendingLink`/`hasPendingLink`/`isLinked` 方法、`onPlayerJoin` 中从磁盘加载关联的逻辑。

**新增**（非持久化，仅当前会话内存）：

* `currentDisplayId`（Integer）、`currentUsername`（String）字段

* `setCurrentAccount(player, displayId, username, permission)` —— PIN 登录成功后设置

* `getCurrentDisplayId(uuid)` —— 供防多开使用

* `getCurrentUsername(uuid)` —— 供 game-session 通知使用

* `logout` 时清除 currentDisplayId/currentUsername

**保留**：`authenticated`/`joinMs`/`lastActivityMs`/`permission`/`pendingTotp`/`totpPendingAction`。

**补版权头**。

### 3. 重构 ServerNetworkHandler.java

**processVerify**：

* 移除 `hasPendingLink` 检查

* 失败响应（success=false）处理中：识别 `message` 是否含"已绑定"/"绑定冲突"/"UUID"等关键词，若是则替换为友好提示：

  ```
  此游戏账号(UUID)已被绑定其他 IQCL 账户。
  你可在 IQCL 安全中心查看或解绑：https://www.iqcl.de5.net/auth/user
  ```

  原始消息仍记入日志。

* 成功响应：移除 `requireLink` 关联确认流程（`authenticateWithAccount` 调用块），改为：

  * 调用 `AuthState.setCurrentAccount(player, displayId, username, permission)` 记录会话信息

  * 调用 `completeLogin` 完成登录

  * 若 `displayId != null`，发送提示消息（不落盘）：

    ```
    [IQCL] 本账号已绑定 IQCL 账户 (ID: xxx, 用户名: xxx)
    你可在 IQCL 安全中心查看或解绑：https://www.iqcl.de5.net/auth/user
    ```

### 4. 重构 CommandRegistry.java —— `/iqcl link` 新逻辑

`executeLink` 新行为：

1. 玩家未登录 → 提示"请先通过 /iqcl login pin 登录后关联"
2. 玩家已登录且 `AuthState.getCurrentDisplayId(uuid) != null`（PIN 登录）→ 显示当前绑定账户信息 + 安全中心链接
3. 玩家已登录但 `currentDisplayId == null`（密码/TOTP 登录）→ **自动登出**：

   * 发送 S2C\_LOGOUT 通知客户端重置

   * 调用 `PlayerSessionManager.logoutToLimbo(player, clearInventoryOnJoin)`

   * 调用 `AuthState.logout(player)`

   * 提示"你当前通过密码/TOTP 登录，关联 IQCL 账户需使用 PIN 登录。已自动登出，请输入 /iqcl login pin \<PIN码>"

移除对 `isLinked`/`hasPendingLink`/`confirmLink`/`state.pendingDisplayId` 等的引用。

**移除** **`/iqcl cancel`** **指令注册**（待关联状态已不存在）。

**补版权头**。

### 5. 重构 PlayerSessionManager.java

* `enforceSingleAccount` / `removeAccountBinding` / `cleanupSession` 中 `state.linkedDisplayId` → `AuthState.getCurrentDisplayId(uuid)`

* `sendToLimbo` / `sendToLimboInternal`：垫脚方块生成逻辑外层加 `if (config.limboGeneratePlatform)` 守卫

* `logoutToLimbo` 中 `removeAccountBinding` 调用保留（内部改用 getCurrentDisplayId）

**补版权头**。

### 6. 重构 PlayerRestrictionManager.java

* `handlePlayerJoin`：移除 `state.linked` 检查块（提示已关联账号用 PIN 登录），因为不再有本地关联状态

* `handlePlayerJoin` 自动登录分支中 `st.linkedUsername` → `AuthState.getCurrentUsername(uuid)`

* `sendLoginPrompt`/`notifyBlocked` 中 `passwordLoginEnabled` 判断保持不变

**补版权头**。

### 7. 重构 PasswordManager.java

* 移除 `import LinkStore`

* `completePasswordLogin` 中移除 `LinkStore.load(uuid)` 调用；防多开改用 `AuthState.getCurrentDisplayId(uuid)`（密码登录时为 null，不参与防多开，符合预期）

* `login` 方法中 `hasPendingLink` 检查移除

* TOTP 相关方法（`enableTotp`/`confirmTotp`/`disableTotp`/`confirmTotpLogin`/`verifyTotpForLogin`）入口加 `if (!ModConfig.get().totpEnabled)` 拒绝；`login` 中 `record.totpEnabled` 检查前加 `&& config.totpEnabled`

* `register` 中 `hasPendingLink` 检查移除

### 8. 重构 PasswordCommandHandler.java

* `executeAccount`：移除 `linked`/`isLinked` 显示行

* 移除 `executeCancel` 方法（指令已删）

* `executeEnableTotp`/`executeConfirmTotp`/`executeDisableTotp`/`executeLoginConfirmTotp` 入口加 `totpEnabled` 检查

### 9. 重构 LuckPermsContextProvider.java

* L119/L153 `AuthState.isLinked(uuid)` → `AuthState.getCurrentDisplayId(uuid) != null`（语义：当前会话是否通过 PIN 登录且绑定了 IQCL 账户）

### 10. ModConfig.java 新增配置项

```java
// ========== Limbo 隔离区 ==========
/** 是否在 Limbo 隔离区下方生成垫脚方块平台（5×5 石头+中心玻璃）。 */
public boolean limboGeneratePlatform = true;

// ========== TOTP 双因素认证 ==========
/** 是否启用 TOTP 双因素认证（关闭后即使账号配置了 TOTP 也跳过验证）。 */
public boolean totpEnabled = true;
```

移除 `requireLink` 字段（本地关联逻辑已删）。

### 11. 补全版权头

为以下文件添加标准版权头（`/* Copyright (c) 2026 IQCL ... MPL-2.0 ... */`）：

* `ApiGateway.java`

* `AuthState.java`

* `CommandRegistry.java`

* `PlayerRestrictionManager.java`

* `PlayerSessionManager.java`

### 12. 更新 README.md

* 功能矩阵：移除"账号关联 requireLink"行；新增 TOTP 开关、Limbo 垫脚方块开关

* 配置项表：移除 `requireLink`；新增 `limboGeneratePlatform`、`totpEnabled`

* 指令说明：更新 `/iqcl link` 行为；移除 `/iqcl cancel`

* PIN 登录流程：移除"requireLink 时需 /iqcl link 确认关联"步骤；新增"返回 displayId 时提示绑定信息 + 安全中心链接"

* 新增"UUID 绑定冲突"错误处理说明

## 关键设计决策

1. **防多开保留**：`AuthState.currentDisplayId` 内存字段（非持久化）供防多开使用，PIN 登录设置、登出清除，不落盘。
2. **密码登录不参与防多开**：密码登录无 displayId，删除 LinkStore 后密码登录玩家不触发防多开（符合预期，密码账号本身是本地账号）。
3. **TOTP 开关**：`totpEnabled=false` 时，所有 TOTP 命令拒绝执行、密码登录跳过 TOTP 步骤。`passwordLoginEnabled=false` 时 TOTP 自然不可用。
4. **错误识别策略**：检查 `message` 是否包含"已绑定"/"绑定冲突"/"UUID"关键词（不依赖精确字符串匹配，更鲁棒）。
5. 记得删掉之前的PIN登录后必须用命令绑定才能登陆成功，现在后端已接管

## 验证方式

1. `gradlew.bat build` 编译通过，无诊断错误
2. 检查 `config/iqclauth.json` 新配置项正确生成
3. 逻辑走查：PIN 登录 → 设置 currentDisplayId → 防多开 → 登出清除
4. 逻辑走查：密码登录 → 执行 `/iqcl link` → 自动登出 → 提示 PIN 登录
5. 逻辑走查：验证服务器返回绑定冲突错误 → 显示友好提示 + 安全中心链接
6. 确认无残留 LinkStore 引用（`grep -r LinkStore src/`）

