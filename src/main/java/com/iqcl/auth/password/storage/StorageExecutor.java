/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.password.storage;

import com.iqcl.auth.IqclAuth;
import net.minecraft.server.MinecraftServer;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * 异步数据库执行器。
 * <p>
 * 单线程 {@link ExecutorService} 串行化所有 DB 操作，避免并发写冲突。
 * 回调通过 {@link MinecraftServer#execute(Runnable)} 调度回主线程，
 * 保证对 {@link com.iqcl.auth.server.AuthState} /
 * {@link com.iqcl.auth.server.PlayerSessionManager} 的修改线程安全。
 * <p>
 * server=null 时回调在 IO 线程内直接执行（仅用于无主线程依赖的场景，如测试）。
 */
public final class StorageExecutor {

    private static final AtomicBoolean RELOADING = new AtomicBoolean(false);
    private static ExecutorService executor;

    private StorageExecutor() {
    }

    /** 初始化执行器。 */
    public static synchronized void init() {
        if (executor != null && !executor.isShutdown()) {
            return;
        }
        executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "IQCL-Storage-Worker");
            t.setDaemon(true);
            t.setUncaughtExceptionHandler((thread, throwable) ->
                    IqclAuth.LOGGER.error("[IQCL Auth] 存储工作线程未捕获异常", throwable));
            return t;
        });
        RELOADING.set(false);
        IqclAuth.LOGGER.info("[IQCL Auth] 存储执行器已启动");
    }

    /** 关闭执行器（停服或 reload 时调用）。 */
    public static synchronized void shutdown() {
        if (executor != null) {
            executor.shutdown();
            executor = null;
        }
    }

    /** 标记进入重载状态（拒绝新任务）。 */
    public static void enterReloading() {
        RELOADING.set(true);
    }

    /** 清除重载状态。 */
    public static void exitReloading() {
        RELOADING.set(false);
    }

    /** 当前是否可接受任务。 */
    public static boolean isAvailable() {
        return executor != null && !executor.isShutdown() && !RELOADING.get();
    }

    /**
     * 提交一个数据库任务，回调在 MinecraftServer 主线程执行。
     *
     * @param server    用于调度回主线程；null 则回调在 IO 线程
     * @param task      数据库任务
     * @param onSuccess 主线程回调（成功）
     * @param onFailure 主线程回调（失败）
     * @param <T>       结果类型
     * @return Future（可用于取消），不可用时返回 null
     */
    public static <T> Future<?> submit(MinecraftServer server,
                                       Callable<T> task,
                                       Consumer<T> onSuccess,
                                       Consumer<Exception> onFailure) {
        if (!isAvailable()) {
            if (onFailure != null) {
                if (server != null) {
                    server.execute(() -> onFailure.accept(
                            new IllegalStateException("存储正在重载，请稍后再试")));
                } else {
                    onFailure.accept(new IllegalStateException("存储正在重载，请稍后再试"));
                }
            }
            return null;
        }
        return executor.submit(() -> {
            T result;
            try {
                result = task.call();
            } catch (Exception e) {
                IqclAuth.LOGGER.error("[IQCL Auth] 存储任务执行失败", e);
                if (onFailure != null) {
                    if (server != null) {
                        server.execute(() -> onFailure.accept(e));
                    } else {
                        onFailure.accept(e);
                    }
                }
                return;
            }
            if (onSuccess != null) {
                if (server != null) {
                    server.execute(() -> onSuccess.accept(result));
                } else {
                    onSuccess.accept(result);
                }
            }
        });
    }
}
