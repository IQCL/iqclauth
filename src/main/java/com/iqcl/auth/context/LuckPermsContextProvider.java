/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.context;

import com.iqcl.auth.IqclAuth;
import com.iqcl.auth.server.AuthState;
import com.iqcl.auth.server.PlayerSessionManager;
import net.minecraft.server.network.ServerPlayerEntity;

import java.util.*;

/**
 * LuckPerms 上下文提供者（可选集成）。
 * <p>
 * 向 LuckPerms 暴露 IQCL 认证相关的上下文变量，服务器管理员可基于这些上下文
 * 创建权限规则（例如：只有已登录玩家才能使用某命令）。
 * <p>
 * 提供的上下文：
 * <ul>
 *   <li>{@code iqcl_authenticated} — 是否已通过认证 (true/false)</li>
 *   <li>{@code iqcl_linked} — 是否已关联 IQCL 账号 (true/false)</li>
 *   <li>{@code iqcl_session_locked} — 会话是否被锁定 (true/false)</li>
 *   <li>{@code iqcl_auth_ip} — 玩家绑定的认证 IP</li>
 *   <li>{@code iqcl_auth_permission} — 玩家的 IQCL 权限等级 (trial/formal/banned)</li>
 * </ul>
 * <p>
 * 使用反射调用 LuckPerms API，确保未安装 LuckPerms 时不会导致编译/运行错误。
 */
public final class LuckPermsContextProvider {

    private LuckPermsContextProvider() {
    }

    private static volatile boolean registered = false;
    private static volatile boolean available = false;

    /**
     * 注册 IQCL 上下文到 LuckPerms。如果 LuckPerms 未安装则静默跳过。
     */
    public static synchronized void register() {
        if (registered) return;

        try {
            // 检测 LuckPerms 是否存在
            Class.forName("net.luckperms.api.LuckPermsApi");
            available = true;
        } catch (ClassNotFoundException e) {
            IqclAuth.LOGGER.debug("[IQCL Auth] 未检测到 LuckPerms，跳过上下文注册");
            return;
        }

        try {
            // 注册 ContextProvider
            // LuckPerms API: ContextManager.registerProvider(Plugin, ContextProvider)
            // 我们实现一个简化版的 ContextProvider

            // 查找 FabricLoader 获取 LuckPerms 插件
            Class<?> fabricLoaderClass = Class.forName("net.fabricmc.loader.api.FabricLoader");
            Object fabricLoader = fabricLoaderClass.getMethod("getInstance").invoke(null);
            Object pluginContainer = fabricLoaderClass.getMethod("getPluginContainer", String.class)
                    .invoke(fabricLoader, "luckperms");

            if (pluginContainer == null) {
                IqclAuth.LOGGER.warn("[IQCL Auth] 未找到 LuckPerms 插件容器");
                return;
            }

            // ContextManager.registerProvider(Plugin plugin, ContextProvider provider)
            Class<?> contextManagerClass = Class.forName("net.luckperms.api.context.ContextManager");
            Class<?> contextProviderClass = Class.forName("net.luckperms.api.context.ContextProvider");
            Class<?> immutableContextClass = Class.forName("net.luckperms.api.context.ImmutableContext");

            // 创建 ContextProvider 实现
            Object provider = java.lang.reflect.Proxy.newProxyInstance(
                    contextProviderClass.getClassLoader(),
                    new Class<?>[]{contextProviderClass},
                    (proxy, method, args) -> {
                        if ("getContexts".equals(method.getName()) && args.length == 2) {
                            ServerPlayerEntity player = (ServerPlayerEntity) args[1];
                            return buildImmutableContexts(player, immutableContextClass);
                        }
                        return Collections.emptySet();
                    });

            // 调用 ContextManager.registerProvider
            java.lang.reflect.Method registerMethod = contextManagerClass.getMethod(
                    "registerProvider",
                    Class.forName("net.luckperms.api.plugin.Plugin"),
                    contextProviderClass);

            // 获取 LuckPerms 插件实例
            Object lpApi = Class.forName("net.luckperms.api.LuckPermsApi")
                    .getMethod("getInstance").invoke(null);
            Object plugin = lpApi.getClass().getMethod("getPlugin").invoke(lpApi);

            registerMethod.invoke(null, plugin, provider);

            IqclAuth.LOGGER.info("[IQCL Auth] LuckPerms 上下文支持已启用");
            registered = true;
        } catch (Exception e) {
            IqclAuth.LOGGER.warn("[IQCL Auth] LuckPerms 上下文注册失败: {}", e.getMessage());
        }
    }

    /**
     * 构建玩家的 IQCL 上下文集合（ImmutableContext 实例）。
     */
    @SuppressWarnings("unchecked")
    private static Set<Object> buildImmutableContexts(ServerPlayerEntity player, Class<?> immutableContextClass) {
        Set<Object> contexts = new HashSet<>();
        try {
            java.util.UUID uuid = player.getUuid();
            boolean authed = AuthState.isAuthenticated(uuid);
            boolean linked = AuthState.isLinked(uuid);
            boolean sessionLocked = PlayerSessionManager.isSessionLocked(uuid);

            // ImmutableContext.of(key, value)
            java.lang.reflect.Method ofMethod = immutableContextClass.getMethod("of", String.class, String.class);

            contexts.add(ofMethod.invoke(null, "iqcl_authenticated", String.valueOf(authed)));
            contexts.add(ofMethod.invoke(null, "iqcl_linked", String.valueOf(linked)));
            contexts.add(ofMethod.invoke(null, "iqcl_session_locked", String.valueOf(sessionLocked)));

            if (authed) {
                String boundIp = PlayerSessionManager.getBoundIp(uuid);
                if (boundIp != null) {
                    contexts.add(ofMethod.invoke(null, "iqcl_auth_ip", boundIp));
                }
                String permission = AuthState.getPermission(uuid);
                if (permission != null) {
                    contexts.add(ofMethod.invoke(null, "iqcl_auth_permission", permission));
                }
            }
        } catch (Exception e) {
            IqclAuth.LOGGER.debug("[IQCL Auth] 构建 LuckPerms 上下文失败: {}", e.getMessage());
        }
        return contexts;
    }

    /**
     * 构建玩家的 IQCL 上下文集合（Map 版本，用于非 LuckPerms 环境）。
     * 可被其他权限系统（如自定义权限）复用。
     */
    public static Map<String, String> buildContextMap(ServerPlayerEntity player) {
        Map<String, String> contexts = new HashMap<>();
        java.util.UUID uuid = player.getUuid();
        boolean authed = AuthState.isAuthenticated(uuid);
        boolean linked = AuthState.isLinked(uuid);
        boolean sessionLocked = PlayerSessionManager.isSessionLocked(uuid);

        contexts.put("iqcl_authenticated", String.valueOf(authed));
        contexts.put("iqcl_linked", String.valueOf(linked));
        contexts.put("iqcl_session_locked", String.valueOf(sessionLocked));

        if (authed) {
            String boundIp = PlayerSessionManager.getBoundIp(uuid);
            if (boundIp != null) {
                contexts.put("iqcl_auth_ip", boundIp);
            }
            String permission = AuthState.getPermission(uuid);
            if (permission != null) {
                contexts.put("iqcl_auth_permission", permission);
            }
        }
        return contexts;
    }

    /** LuckPerms 上下文是否可用。 */
    public static boolean isAvailable() {
        return available && registered;
    }
}
