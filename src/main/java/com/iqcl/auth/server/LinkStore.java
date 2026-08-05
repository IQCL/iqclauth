package com.iqcl.auth.server;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.iqcl.auth.IqclAuth;
import net.fabricmc.loader.api.FabricLoader;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 账号关联持久化存储。
 * <p>
 * 将玩家的 IQCL 账号关联信息（displayId、username）持久化到磁盘，
 * 防止服务端重启后丢失关联状态。
 * <p>
 * 存储路径：{@code config/iqclauth/links/} 目录下按 UUID 命名的 JSON 文件。
 * 每个文件格式：{@code {"displayId":123,"username":"xxx"}}
 */
public final class LinkStore {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private static final Path LINKS_DIR =
            FabricLoader.getInstance().getConfigDir().resolve("iqclauth").resolve("links");

    /** 内存缓存：UUID → LinkData（避免频繁读磁盘）。 */
    private static final Map<UUID, LinkData> CACHE = new ConcurrentHashMap<>();

    private LinkStore() {
    }

    /** 关联数据。 */
    public static class LinkData {
        public Integer displayId;
        public String username;

        public LinkData() {
        }

        public LinkData(Integer displayId, String username) {
            this.displayId = displayId;
            this.username = username;
        }
    }

    /**
     * 保存玩家的关联信息到内存缓存 + 磁盘。
     */
    public static void save(UUID uuid, Integer displayId, String username) {
        if (displayId == null) return;
        LinkData data = new LinkData(displayId, username);
        CACHE.put(uuid, data);
        writeDisk(uuid, data);
        IqclAuth.LOGGER.debug("[IQCL Auth] 保存关联信息: UUID={}, displayId={}", uuid, displayId);
    }

    /**
     * 从缓存或磁盘加载玩家的关联信息。
     * @return 关联数据，或 null（未关联）
     */
    public static LinkData load(UUID uuid) {
        // 先查缓存
        LinkData cached = CACHE.get(uuid);
        if (cached != null) {
            return cached;
        }
        // 再查磁盘
        LinkData disk = readDisk(uuid);
        if (disk != null) {
            CACHE.put(uuid, disk);
            return disk;
        }
        return null;
    }

    /**
     * 清除玩家的关联信息（登出时调用）。
     */
    public static void remove(UUID uuid) {
        CACHE.remove(uuid);
        deleteDisk(uuid);
    }

    // ========== 磁盘 I/O ==========

    private static Path getFilePath(UUID uuid) {
        return LINKS_DIR.resolve(uuid + ".json");
    }

    private static void writeDisk(UUID uuid, LinkData data) {
        try {
            if (!Files.exists(LINKS_DIR)) {
                Files.createDirectories(LINKS_DIR);
            }
            Files.writeString(getFilePath(uuid), GSON.toJson(data));
        } catch (IOException e) {
            IqclAuth.LOGGER.error("[IQCL Auth] 写入关联信息失败: UUID={}", uuid, e);
        }
    }

    private static LinkData readDisk(UUID uuid) {
        Path path = getFilePath(uuid);
        if (!Files.exists(path)) return null;
        try {
            String json = Files.readString(path);
            LinkData data = GSON.fromJson(json, LinkData.class);
            if (data != null && data.displayId != null) {
                return data;
            }
        } catch (Exception e) {
            IqclAuth.LOGGER.error("[IQCL Auth] 读取关联信息失败: UUID={}", uuid, e);
        }
        return null;
    }

    private static void deleteDisk(UUID uuid) {
        Path path = getFilePath(uuid);
        try {
            Files.deleteIfExists(path);
        } catch (IOException e) {
            IqclAuth.LOGGER.error("[IQCL Auth] 删除关联信息失败: UUID={}", uuid, e);
        }
    }
}
