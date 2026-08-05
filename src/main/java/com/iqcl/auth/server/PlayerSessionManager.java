package com.iqcl.auth.server;

import com.iqcl.auth.IqclAuth;
import com.iqcl.auth.config.ModConfig;
import net.minecraft.block.Blocks;
import net.minecraft.entity.player.PlayerInventory;
import net.minecraft.item.ItemStack;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.network.ServerPlayerEntity;
import net.minecraft.server.world.ServerWorld;
import net.minecraft.text.Text;
import net.minecraft.util.math.BlockPos;
import net.minecraft.util.math.Vec3d;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 玩家会话管理器（服务端单例）。
 * <p>
 * 职责：
 * <ul>
 *   <li>Limbo 隔离区：未登录玩家传送至隔离区，清空背包和位置；</li>
 *   <li>登录恢复：登录成功后恢复物品和位置；</li>
 *   <li>持久会话：同 IP 重连自动恢复登录状态；</li>
 *   <li>防多开：同一 IQCL 账号禁止多人同时登录；</li>
 *   <li>物品快照：玩家进服时快照物品和位置。</li>
 * </ul>
 */
public final class PlayerSessionManager {

    /** 玩家进服时的物品/位置快照。 */
    private static final Map<UUID, PlayerSnapshot> JOIN_SNAPSHOTS = new ConcurrentHashMap<>();

    /** 持久会话数据：UUID → SessionData（含 IP 和过期时间）。 */
    private static final Map<UUID, SessionData> PERSISTENT_SESSIONS = new ConcurrentHashMap<>();

    /** IQCL displayId → 当前在线玩家 UUID 映射（防多开）。 */
    private static final Map<Integer, UUID> DISPLAYID_TO_PLAYER = new ConcurrentHashMap<>();

    /** 已送入 Limbo 的玩家 UUID 集合（用于每 tick 持续保护）。 */
    private static final Set<UUID> LIMBO_PLAYERS = ConcurrentHashMap.newKeySet();

    /** 传送后坠落保护：UUID → 保护到期时间（毫秒）。 */
    private static final Map<UUID, Long> FALL_PROTECTION = new ConcurrentHashMap<>();

    /** 持续坠落保护默认时长（毫秒）——传送后 3 秒内免疫坠落伤害。 */
    private static final long FALL_PROTECTION_MS = 3000L;

    /** 持久会话数据（IP + 过期时间）。 */
    private static class SessionData {
        final String ip;
        final long expireAtMs;
        SessionData(String ip, long expireAtMs) {
            this.ip = ip;
            this.expireAtMs = expireAtMs;
        }
    }

    private PlayerSessionManager() {
    }

    /**
     * 记录玩家进服时的物品和位置快照。
     * 如果玩家上次在 Limbo 断线（playerdata 保存了 Limbo 位置），用出生点替代。
     */
    public static void captureJoinSnapshot(ServerPlayerEntity player) {
        PlayerSnapshot snapshot = new PlayerSnapshot();
        snapshot.pos = player.getPos();
        snapshot.yaw = player.getYaw();
        snapshot.pitch = player.getPitch();
        snapshot.worldId = player.getWorld().getRegistryKey().getValue().toString();
        snapshot.items = new ArrayList<>();
        PlayerInventory inv = player.getInventory();
        for (int i = 0; i < inv.size(); i++) {
            snapshot.items.add(inv.getStack(i).copy());
        }
        snapshot.heldItemIndex = inv.selectedSlot;

        // —— 检测当前位置是否是 Limbo 位置（上次在 Limbo 断线）——
        ModConfig config = ModConfig.get();
        if (config.limboEnabled) {
            Vec3d limboCenter = new Vec3d(
                    config.limboX + 0.5, config.limboY, config.limboZ + 0.5);
            double distSq = snapshot.pos.squaredDistanceTo(limboCenter);
            boolean inLimboDim = snapshot.worldId.equals(config.limboDimension);

            // 距离 Limbo 中心 < 25 格（约 5 格半径）且在 Limbo 维度 → 视为 Limbo 位置
            if (distSq < 25.0 && inLimboDim) {
                IqclAuth.LOGGER.info("[IQCL Auth] 检测到玩家 {} 的 playerdata 位置在 Limbo，使用出生点替代",
                        player.getEntityName());
                // 用世界出生点替代
                ServerWorld world = player.getServerWorld();
                BlockPos spawnPos = world.getSpawnPos();
                snapshot.pos = new Vec3d(
                        spawnPos.getX() + 0.5,
                        spawnPos.getY(),
                        spawnPos.getZ() + 0.5);
                snapshot.yaw = world.getSpawnAngle();
                snapshot.pitch = 0f;
            }
        }

        JOIN_SNAPSHOTS.put(player.getUuid(), snapshot);
    }

    /**
     * 将玩家送入 Limbo 隔离区。
     */
    public static void sendToLimbo(ServerPlayerEntity player) {
        ModConfig config = ModConfig.get();
        if (!config.limboEnabled) return;

        ServerWorld world = player.getServerWorld();
        int bx = config.limboX;
        int by = config.limboY;
        int bz = config.limboZ;

        // —— 在 Limbo 生成安全平台（3x3 石头+玻璃地板）——
        // 防止玩家跌落虚空，让玩家有地方站立
        BlockPos centerPos = new BlockPos(bx, by, bz);
        for (int dx = -2; dx <= 2; dx++) {
            for (int dz = -2; dz <= 2; dz++) {
                BlockPos floorPos = centerPos.add(dx, -1, dz);
                if (world.getBlockState(floorPos).isAir()) {
                    world.setBlockState(floorPos, Blocks.STONE.getDefaultState());
                }
            }
        }
        // 中心位置用玻璃标记
        BlockPos glassPos = centerPos.add(0, -1, 0);
        world.setBlockState(glassPos, Blocks.GLASS.getDefaultState());

        // —— 强制传送至 Limbo 中心 ——
        player.networkHandler.requestTeleport(
                bx + 0.5, by, bz + 0.5,
                0f, 0f);

        // —— 立即清除所有速度和坠落 ——
        player.setVelocity(Vec3d.ZERO);
        player.fallDistance = 0f;
        player.setNoGravity(true);

        // —— 清空背包 ——
        if (config.clearInventoryOnJoin) {
            PlayerInventory inv = player.getInventory();
            for (int i = 0; i < inv.size(); i++) {
                inv.setStack(i, ItemStack.EMPTY);
            }
        }

        // —— 标记为 Limbo 玩家（用于每 tick 持续保护）——
        LIMBO_PLAYERS.add(player.getUuid());

        // 发送提示
        player.sendMessage(
                Text.literal("[IQCL] 你已被送入隔离区，请先完成 PIN 登录！")
                        .formatted(net.minecraft.util.Formatting.RED,
                                net.minecraft.util.Formatting.BOLD),
                false);
    }

    /**
     * 每 tick 对 Limbo 中的玩家执行坠落保护（防止任何情况下的坠落死亡）。
     * 由 PlayerRestrictionManager.onServerTick 调用。
     */
    public static void tickLimboProtection(ServerPlayerEntity player, ModConfig config) {
        if (!LIMBO_PLAYERS.contains(player.getUuid())) return;
        if (!config.limboEnabled) return;
        if (AuthState.isAuthenticated(player.getUuid())) {
            // 已认证，移除 Limbo 标记
            LIMBO_PLAYERS.remove(player.getUuid());
            player.setNoGravity(false);
            return;
        }

        // —— 持续坠落保护 ——
        player.fallDistance = 0f;
        player.setVelocity(Vec3d.ZERO);

        // 如果玩家偏离 Limbo 中心超过 4 格，强制拉回
        Vec3d pos = player.getPos();
        Vec3d limboCenter = new Vec3d(config.limboX + 0.5, config.limboY, config.limboZ + 0.5);
        double distSq = pos.squaredDistanceTo(limboCenter);
        if (distSq > 16.0) {
            player.networkHandler.requestTeleport(
                    config.limboX + 0.5, config.limboY, config.limboZ + 0.5,
                    player.getYaw(), player.getPitch());
        }
    }

    /**
     * 登录成功后恢复玩家物品和位置。
     */
    public static void restoreFromLimbo(ServerPlayerEntity player) {
        ModConfig config = ModConfig.get();
        if (!config.restoreOnLogin) {
            LIMBO_PLAYERS.remove(player.getUuid());
            player.setNoGravity(false);
            return;
        }

        PlayerSnapshot snapshot = JOIN_SNAPSHOTS.get(player.getUuid());
        if (snapshot == null) {
            // 没有快照：传送到世界出生点
            LIMBO_PLAYERS.remove(player.getUuid());
            player.setNoGravity(false);
            player.fallDistance = 0f;
            player.setVelocity(Vec3d.ZERO);
            ServerWorld world = player.getServerWorld();
            BlockPos spawnPos = world.getSpawnPos();
            player.networkHandler.requestTeleport(
                    spawnPos.getX() + 0.5, spawnPos.getY(), spawnPos.getZ() + 0.5,
                    world.getSpawnAngle(), 0f);
            FALL_PROTECTION.put(player.getUuid(), System.currentTimeMillis() + FALL_PROTECTION_MS);
            IqclAuth.LOGGER.info("[IQCL Auth] 玩家 {} 无快照，传送到世界出生点",
                    player.getEntityName());
            return;
        }

        // —— 先清除 Limbo 保护 ——
        player.setNoGravity(false);
        player.fallDistance = 0f;
        player.setVelocity(Vec3d.ZERO);

        // —— 检查目标位置下方是否有方块，确保安全 ——
        ServerWorld world = player.getServerWorld();
        int blockX = (int) Math.floor(snapshot.pos.x);
        int blockY = (int) Math.floor(snapshot.pos.y);
        int blockZ = (int) Math.floor(snapshot.pos.z);
        BlockPos targetPos = new BlockPos(blockX, blockY - 1, blockZ);
        boolean hasGround = world.getBlockState(targetPos).isSolidBlock(world, targetPos);

        double teleportX = snapshot.pos.x;
        double teleportY = snapshot.pos.y;
        double teleportZ = snapshot.pos.z;

        if (!hasGround) {
            // 下方没有方块，找最近的安全位置
            // 往上找 10 格内的第一个有地面的位置
            for (int dy = 1; dy <= 10; dy++) {
                BlockPos groundPos = new BlockPos(blockX, blockY + dy - 1, blockZ);
                if (world.getBlockState(groundPos).isSolidBlock(world, groundPos)) {
                    teleportY = snapshot.pos.y + dy;
                    break;
                }
            }
        }

        // —— 传送回原位置（或安全位置）——
        player.networkHandler.requestTeleport(
                teleportX, teleportY, teleportZ,
                snapshot.yaw, snapshot.pitch);

        // 二次清除（防止传送过程中产生的坠落）
        player.setVelocity(Vec3d.ZERO);
        player.fallDistance = 0f;

        // —— 标记 3 秒坠落保护 ——
        FALL_PROTECTION.put(player.getUuid(), System.currentTimeMillis() + FALL_PROTECTION_MS);

        // 恢复物品
        PlayerInventory inv = player.getInventory();
        for (int i = 0; i < inv.size(); i++) {
            inv.setStack(i, i < snapshot.items.size() ? snapshot.items.get(i) : ItemStack.EMPTY);
        }
        inv.selectedSlot = snapshot.heldItemIndex;

        LIMBO_PLAYERS.remove(player.getUuid());
        JOIN_SNAPSHOTS.remove(player.getUuid());
    }

    /**
     * 每 tick 检查坠落保护：如果玩家在保护期内，重置 fallDistance。
     * 由 PlayerRestrictionManager.onServerTick 调用。
     */
    public static void tickFallProtection(ServerPlayerEntity player) {
        Long expireAt = FALL_PROTECTION.get(player.getUuid());
        if (expireAt == null) return;

        long now = System.currentTimeMillis();
        if (now >= expireAt) {
            FALL_PROTECTION.remove(player.getUuid());
            return;
        }

        // 保护期内：强制清零坠落距离和速度
        player.fallDistance = 0f;
        player.setVelocity(Vec3d.ZERO);
    }

    /**
     * 检查持久会话是否有效（同 IP 且未过期）。
     * 纯检查方法，不修改任何状态。
     * @return true = 可以自动恢复，false = 需要重新登录
     */
    public static boolean tryPersistentSession(ServerPlayerEntity player) {
        ModConfig config = ModConfig.get();
        if (!config.persistentSession) return false;

        UUID uuid = player.getUuid();
        SessionData session = PERSISTENT_SESSIONS.get(uuid);
        if (session == null) {
            IqclAuth.LOGGER.info("[IQCL Auth] 玩家 {} 无持久会话记录", player.getEntityName());
            return false;
        }

        // 检查是否过期
        long now = System.currentTimeMillis();
        if (now > session.expireAtMs) {
            IqclAuth.LOGGER.info("[IQCL Auth] 玩家 {} 持久会话已过期", player.getEntityName());
            PERSISTENT_SESSIONS.remove(uuid);
            return false;
        }

        // 检查 IP 是否匹配
        if (config.trustIp) {
            String playerIp = getPlayerIp(player);
            if (playerIp == null) {
                IqclAuth.LOGGER.warn("[IQCL Auth] 玩家 {} IP 获取失败，无法匹配持久会话",
                        player.getEntityName());
                return false;
            }
            if (!playerIp.equals(session.ip)) {
                IqclAuth.LOGGER.info("[IQCL Auth] 玩家 {} IP 不匹配 ({} != {})，需重新登录",
                        player.getEntityName(), playerIp, session.ip);
                return false;
            }
        }

        IqclAuth.LOGGER.info("[IQCL Auth] 玩家 {} 持久会话命中，自动恢复登录", player.getEntityName());
        return true;
    }

    /**
     * 记录玩家的持久会话（含过期时间）。在登录成功后调用。
     */
    public static void recordAuthenticatedIp(ServerPlayerEntity player) {
        ModConfig config = ModConfig.get();
        String ip = getPlayerIp(player);
        if (ip != null) {
            long expireAt = System.currentTimeMillis() + (long) config.sessionMaxAgeSeconds * 1000L;
            PERSISTENT_SESSIONS.put(player.getUuid(), new SessionData(ip, expireAt));
            IqclAuth.LOGGER.info("[IQCL Auth] 玩家 {} 持久会话已记录 (IP={}, 过期={}秒后)",
                    player.getEntityName(), ip, config.sessionMaxAgeSeconds);
        } else {
            IqclAuth.LOGGER.warn("[IQCL Auth] 玩家 {} IP 获取失败，持久会话未记录",
                    player.getEntityName());
        }
    }

    /**
     * 移除玩家的持久会话（登出时调用）。
     */
    public static void removeSession(UUID uuid) {
        PERSISTENT_SESSIONS.remove(uuid);
    }

    /**
     * 检查并处理单账号多开。
     * @return 被踢的旧玩家（若有），或 null
     */
    public static ServerPlayerEntity enforceSingleAccount(ServerPlayerEntity player,
                                                          Integer displayId) {
        ModConfig config = ModConfig.get();
        if (!config.singleAccountOnline || displayId == null) return null;

        UUID oldUuid = DISPLAYID_TO_PLAYER.put(displayId, player.getUuid());
        if (oldUuid != null && !oldUuid.equals(player.getUuid())) {
            MinecraftServer server = player.getServer();
            for (ServerPlayerEntity sp : server.getPlayerManager().getPlayerList()) {
                if (sp.getUuid().equals(oldUuid)) {
                    sp.networkHandler.disconnect(Text.literal(
                            "[IQCL] 该账号已在其他设备登录"));
                    return sp;
                }
            }
        }
        return null;
    }

    /**
     * 移除玩家的单账号绑定（登出时调用）。
     */
    public static void removeAccountBinding(ServerPlayerEntity player) {
        AuthState.PlayerAuthState state = AuthState.getState(player.getUuid());
        if (state != null && state.linkedDisplayId != null) {
            DISPLAYID_TO_PLAYER.remove(state.linkedDisplayId);
        }
        // 保留持久会话（AUTHENTICATED_IPS），只清除账号绑定
    }

    /**
     * 清理玩家会话数据（离线时调用）。
     * 保留持久会话数据（PERSISTENT_SESSIONS）供重连自动登录使用。
     */
    public static void cleanupSession(UUID uuid) {
        JOIN_SNAPSHOTS.remove(uuid);
        LIMBO_PLAYERS.remove(uuid);
        // 注意：不清除 PERSISTENT_SESSIONS，让持久会话在过期前可用于自动恢复
        AuthState.PlayerAuthState state = AuthState.getState(uuid);
        if (state != null && state.linkedDisplayId != null) {
            DISPLAYID_TO_PLAYER.remove(state.linkedDisplayId);
        }
    }

    /**
     * 获取玩家 IP 地址。
     * 使用 ServerPlayNetworkHandler.getConnectionAddress() 公开方法（Loom 自动重映射），
     * 避免反射使用 Yarn 映射名（生产环境会失败）。
     */
    private static String getPlayerIp(ServerPlayerEntity player) {
        try {
            java.net.SocketAddress addr = player.networkHandler.getConnectionAddress();
            if (addr instanceof java.net.InetSocketAddress inet) {
                return inet.getHostString();
            }
        } catch (Exception e) {
            IqclAuth.LOGGER.warn("[IQCL Auth] 获取玩家 IP 失败: {}", e.getMessage());
        }
        return null;
    }

    /** 玩家物品/位置快照。 */
    public static class PlayerSnapshot {
        public Vec3d pos;
        public float yaw;
        public float pitch;
        public String worldId;
        public List<ItemStack> items;
        public int heldItemIndex;
    }
}
