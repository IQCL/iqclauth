/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.server;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.iqcl.auth.IqclAuth;
import com.iqcl.auth.crypto.Base64Utils;
import net.fabricmc.loader.api.FabricLoader;
import net.minecraft.item.ItemStack;
import net.minecraft.nbt.NbtCompound;
import net.minecraft.nbt.NbtIo;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/**
 * 玩家快照持久化存储。
 * <p>
 * 解决的核心问题：当玩家在 Limbo 中未登录就断开连接时，Minecraft 的 playerdata 会保存 Limbo 位置
 * 和空背包，导致下次进入时物品/位置丢失。SnapshotStore 在登出时把玩家的完整状态持久化到磁盘，
 * 下次进入时优先从磁盘恢复，确保物品和位置永不丢失。
 * <p>
 * 存储路径：{@code config/iqclauth/snapshots/} 目录下按 UUID 命名的 JSON 文件。
 * 物品栏使用 NBT 二进制序列化 → Base64 编码存储，确保跨版本兼容性。
 */
public final class SnapshotStore {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private static final Path SNAPSHOTS_DIR =
            FabricLoader.getInstance().getConfigDir().resolve("iqclauth").resolve("snapshots");

    /** 当前快照格式版本，用于未来迁移。 */
    private static final int FORMAT_VERSION = 1;

    /** 快照有效期（毫秒）——超过此时间的快照视为过期，不再自动恢复。默认 30 天。 */
    private static final long SNAPSHOT_TTL_MS = 30L * 24 * 60 * 60 * 1000L;

    private SnapshotStore() {
    }

    /** 快照数据（磁盘格式）。 */
    public static class SnapshotData {
        public double posX;
        public double posY;
        public double posZ;
        public float yaw;
        public float pitch;
        public String worldId;
        public int heldItemIndex;
        /** ItemStack 的 NBT 二进制序列化 Base64 字符串列表。 */
        public List<String> itemsBase64;
        public long savedAtMs;
        public int version = FORMAT_VERSION;
    }

    /**
     * 保存玩家快照到磁盘（在 {@code logoutToLimbo} 中调用）。
     */
    public static void save(UUID uuid, PlayerSessionManager.PlayerSnapshot snapshot) {
        if (snapshot == null || snapshot.items == null) return;

        SnapshotData data = new SnapshotData();
        data.posX = snapshot.pos.x;
        data.posY = snapshot.pos.y;
        data.posZ = snapshot.pos.z;
        data.yaw = snapshot.yaw;
        data.pitch = snapshot.pitch;
        data.worldId = snapshot.worldId;
        data.heldItemIndex = snapshot.heldItemIndex;
        data.savedAtMs = System.currentTimeMillis();

        // 序列化物品栏：每个 ItemStack → NBT Compound → 二进制 → Base64
        data.itemsBase64 = new ArrayList<>(snapshot.items.size());
        for (ItemStack stack : snapshot.items) {
            try {
                NbtCompound nbt = new NbtCompound();
                stack.writeNbt(nbt);
                byte[] binary = nbtToBinary(nbt);
                data.itemsBase64.add(Base64Utils.encode(binary));
            } catch (Exception e) {
                IqclAuth.LOGGER.warn("[IQCL Auth] 序列化物品失败，写入空物品: {}", e.getMessage());
                data.itemsBase64.add("");
            }
        }

        writeDisk(uuid, data);
        IqclAuth.LOGGER.debug("[IQCL Auth] 快照已保存: UUID={}, 物品数={}, 位置={}",
                uuid, data.itemsBase64.size(), snapshot.pos);
    }

    /**
     * 从磁盘加载玩家快照。
     */
    public static SnapshotData load(UUID uuid) {
        SnapshotData data = readDisk(uuid);
        if (data == null) return null;

        if (data.version != FORMAT_VERSION) {
            IqclAuth.LOGGER.warn("[IQCL Auth] 快照版本不匹配: UUID={}, expected={}, actual={}",
                    uuid, FORMAT_VERSION, data.version);
            return null;
        }

        long now = System.currentTimeMillis();
        if (now - data.savedAtMs > SNAPSHOT_TTL_MS) {
            IqclAuth.LOGGER.info("[IQCL Auth] 快照已过期: UUID={}, ageDays={}",
                    uuid, (now - data.savedAtMs) / (24 * 3600 * 1000));
            deleteDisk(uuid);
            return null;
        }

        return data;
    }

    /**
     * 将加载的快照数据恢复为 PlayerSnapshot。
     */
    public static PlayerSessionManager.PlayerSnapshot toPlayerSnapshot(SnapshotData data) {
        PlayerSessionManager.PlayerSnapshot snapshot = new PlayerSessionManager.PlayerSnapshot();
        snapshot.pos = new net.minecraft.util.math.Vec3d(data.posX, data.posY, data.posZ);
        snapshot.yaw = data.yaw;
        snapshot.pitch = data.pitch;
        snapshot.worldId = data.worldId;
        snapshot.heldItemIndex = data.heldItemIndex;

        snapshot.items = new ArrayList<>();
        if (data.itemsBase64 != null) {
            for (String b64 : data.itemsBase64) {
                if (b64 == null || b64.isEmpty()) {
                    snapshot.items.add(ItemStack.EMPTY.copy());
                    continue;
                }
                try {
                    byte[] binary = Base64Utils.decode(b64);
                    NbtCompound nbt = binaryToNbt(binary);
                    snapshot.items.add(ItemStack.fromNbt(nbt));
                } catch (Exception e) {
                    IqclAuth.LOGGER.warn("[IQCL Auth] 反序列化物品失败，使用空物品替代: {}", e.getMessage());
                    snapshot.items.add(ItemStack.EMPTY.copy());
                }
            }
        }
        return snapshot;
    }

    /**
     * 清除玩家的磁盘快照（在成功恢复后调用）。
     */
    public static void remove(UUID uuid) {
        deleteDisk(uuid);
    }

    // ========== NBT 二进制序列化 ==========

    private static byte[] nbtToBinary(NbtCompound nbt) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (DataOutputStream dos = new DataOutputStream(baos)) {
            NbtIo.write(nbt, dos);
        }
        return baos.toByteArray();
    }

    private static NbtCompound binaryToNbt(byte[] binary) throws IOException {
        try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(binary))) {
            return NbtIo.read(dis);
        }
    }

    // ========== 磁盘 I/O ==========

    private static Path getFilePath(UUID uuid) {
        return SNAPSHOTS_DIR.resolve(uuid + ".json");
    }

    private static void writeDisk(UUID uuid, SnapshotData data) {
        try {
            if (!Files.exists(SNAPSHOTS_DIR)) {
                Files.createDirectories(SNAPSHOTS_DIR);
            }
            Files.writeString(getFilePath(uuid), GSON.toJson(data));
        } catch (IOException e) {
            IqclAuth.LOGGER.error("[IQCL Auth] 写入快照失败: UUID={}", uuid, e);
        }
    }

    private static SnapshotData readDisk(UUID uuid) {
        Path path = getFilePath(uuid);
        if (!Files.exists(path)) return null;
        try {
            String json = Files.readString(path);
            SnapshotData data = GSON.fromJson(json, SnapshotData.class);
            if (data != null && data.worldId != null && data.itemsBase64 != null) {
                return data;
            }
        } catch (Exception e) {
            IqclAuth.LOGGER.error("[IQCL Auth] 读取快照失败: UUID={}", uuid, e);
        }
        return null;
    }

    private static void deleteDisk(UUID uuid) {
        Path path = getFilePath(uuid);
        try {
            Files.deleteIfExists(path);
        } catch (IOException e) {
            IqclAuth.LOGGER.error("[IQCL Auth] 删除快照失败: UUID={}", uuid, e);
        }
    }
}
