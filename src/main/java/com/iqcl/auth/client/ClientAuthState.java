/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.client;

/**
 * 客户端认证状态集中管理。
 * <p>
 * 原先 {@link PinChatInterceptor} 持有独立 {@code authenticated} 字段，
 * 阶段 2 引入 {@code PasswordChatInterceptor} 后会造成状态分裂。
 * 这里将客户端认证状态提取到单一源，由两个拦截器共同使用。
 */
public final class ClientAuthState {

    private static volatile boolean authenticated = false;

    private ClientAuthState() {
    }

    public static boolean isAuthenticated() {
        return authenticated;
    }

    public static void setAuthenticated(boolean v) {
        authenticated = v;
    }

    public static void reset() {
        authenticated = false;
    }
}
