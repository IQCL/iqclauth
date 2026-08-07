/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.password.crypto;

import com.iqcl.auth.IqclAuth;
import com.iqcl.auth.crypto.Base64Utils;
import net.fabricmc.loader.api.FabricLoader;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.lang.reflect.Type;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.XECPublicKeySpec;

/**
 * 服务端 X25519 静态密钥对的生成与持久化。
 * <p>
 * 用于客户端 → 服务端密码操作密文的 ECDH 密钥交换。
 * 公钥通过 {@code S2C_AUTHINFO_ID} 发送给客户端，客户端再用其生成临时 X25519 密钥对。
 * <p>
 * 密钥文件格式：JSON（base64 编码公/私钥字节，DER 编码）。权限 best-effort 设为 600。
 * 对外暴露的公钥为 32 字节原始 X25519 字节（base64），供客户端直接用于 ECDH 密钥构造。
 */
public final class ServerKeyStore {

    private static final String KEY_FILE_NAME = "server_x25519.json";
    private static final String KEY_VERSION = "2";

    private static final NamedParameterSpec X25519_SPEC = new NamedParameterSpec("X25519");

    private static volatile KeyPair keyPair;
    /** 32 字节原始 X25519 公钥（base64），用于发送给客户端。 */
    private static volatile String publicKeyBase64;

    private ServerKeyStore() {
    }

    /** 加载或生成服务端 X25519 密钥对。应在 {@link IqclAuth#onInitialize} 中调用一次。 */
    public static synchronized void init() {
        Path keyDir = FabricLoader.getInstance().getConfigDir()
                .resolve(IqclAuth.MOD_ID).resolve("keys");
        Path keyFile = keyDir.resolve(KEY_FILE_NAME);

        try {
            if (Files.exists(keyFile)) {
                boolean loaded = tryLoad(keyFile);
                if (!loaded) {
                    // 旧格式或字段缺失，删除旧文件重新生成
                    IqclAuth.LOGGER.warn("[IQCL Auth] 旧格式密钥文件不兼容，删除并重新生成: {}", keyFile);
                    Files.delete(keyFile);
                    generateAndSave(keyDir, keyFile);
                }
            } else {
                generateAndSave(keyDir, keyFile);
            }
        } catch (Exception e) {
            IqclAuth.LOGGER.error("[IQCL Auth] 服务端 X25519 密钥初始化失败，密码登录加密通道不可用", e);
            keyPair = null;
            publicKeyBase64 = null;
        }
    }

    /**
     * 尝试从文件加载密钥对。
     * 返回 true 表示加载成功；false 表示文件格式不兼容，需重新生成。
     */
    private static boolean tryLoad(Path keyFile) {
        try {
            KeyData data = load(keyFile);
            if (data.publicKey == null || data.publicKey.isEmpty()
                    || data.privateKey == null || data.privateKey.isEmpty()) {
                IqclAuth.LOGGER.warn("[IQCL Auth] 密钥文件缺少必要字段 (publicKey/privateKey)");
                return false;
            }
            keyPair = deserialize(data);
            // 兼容旧版本：若存储的是 44 字节 DER 编码公钥，仍可通过 X509EncodedKeySpec 恢复
            publicKeyBase64 = rawPublicKeyBase64(keyPair.getPublic());
            IqclAuth.LOGGER.info("[IQCL Auth] 已加载服务端 X25519 密钥对");
            return true;
        } catch (Exception e) {
            IqclAuth.LOGGER.warn("[IQCL Auth] 密钥文件加载失败: {}", e.getMessage());
            return false;
        }
    }

    /** 生成新密钥对并保存到文件。 */
    private static void generateAndSave(Path keyDir, Path keyFile) throws Exception {
        Files.createDirectories(keyDir);
        keyPair = generate();
        String pubDerB64 = Base64Utils.encode(keyPair.getPublic().getEncoded());
        String privB64 = Base64Utils.encode(keyPair.getPrivate().getEncoded());
        publicKeyBase64 = rawPublicKeyBase64(keyPair.getPublic());
        KeyData data = new KeyData(
                KEY_VERSION, pubDerB64, privB64, publicKeyBase64,
                System.currentTimeMillis());
        save(keyFile, data);
        IqclAuth.LOGGER.info("[IQCL Auth] 已生成并保存服务端 X25519 密钥对: {}", keyFile);
    }

    /** 是否已初始化密钥对。 */
    public static boolean isAvailable() {
        return keyPair != null && publicKeyBase64 != null;
    }

    /**
     * 获取服务端公钥（32 字节原始 X25519 字节的 base64，发送给客户端用于 ECDH）。
     * 若密钥未就绪返回 null。
     */
    public static String getPublicKeyBase64() {
        return publicKeyBase64;
    }

    /** 获取 KeyPair（仅供 EcdhEncryptor 内部使用）。 */
    static KeyPair getKeyPair() {
        return keyPair;
    }

    /** 重新生成密钥对（破坏现有客户端缓存的公钥，需客户端重连）。 */
    public static synchronized void rotate() throws GeneralSecurityException, IOException {
        Path keyDir = FabricLoader.getInstance().getConfigDir()
                .resolve(IqclAuth.MOD_ID).resolve("keys");
        Path keyFile = keyDir.resolve(KEY_FILE_NAME);
        try {
            generateAndSave(keyDir, keyFile);
        } catch (Exception e) {
            if (e instanceof GeneralSecurityException) throw (GeneralSecurityException) e;
            if (e instanceof IOException) throw (IOException) e;
            throw new IOException("rotate failed", e);
        }
        IqclAuth.LOGGER.info("[IQCL Auth] 服务端 X25519 密钥对已轮换");
    }

    private static KeyPair generate() throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH");
        kpg.initialize(X25519_SPEC);
        return kpg.generateKeyPair();
    }

    /** 把 X25519 公钥转为 32 字节原始表示（X 坐标的 big-endian，对齐到 32 字节）。 */
    private static String rawPublicKeyBase64(PublicKey pub) throws GeneralSecurityException {
        KeyFactory kf = KeyFactory.getInstance("XDH");
        XECPublicKeySpec spec = (XECPublicKeySpec) kf.getKeySpec(pub, XECPublicKeySpec.class);
        byte[] raw = spec.getU().toByteArray();
        byte[] out = new byte[32];
        int srcLen = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - srcLen, out, 32 - srcLen, srcLen);
        return Base64Utils.encode(out);
    }

    private static KeyPair deserialize(KeyData data) throws GeneralSecurityException {
        byte[] pubBytes = Base64Utils.decode(data.publicKey);
        byte[] privBytes = Base64Utils.decode(data.privateKey);
        KeyFactory kf = KeyFactory.getInstance("XDH");
        PublicKey pub;
        if (pubBytes.length == 32) {
            // 新版 32 字节原始公钥
            BigInteger u = new BigInteger(1, pubBytes);
            XECPublicKeySpec spec = new XECPublicKeySpec(X25519_SPEC, u);
            pub = kf.generatePublic(spec);
        } else {
            // 兼容旧版 DER 编码公钥
            pub = kf.generatePublic(new X509EncodedKeySpec(pubBytes));
        }
        PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(privBytes));
        return new KeyPair(pub, priv);
    }

    private static KeyData load(Path file) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (Reader r = Files.newBufferedReader(file)) {
            char[] buf = new char[1024];
            int n;
            while ((n = r.read(buf)) != -1) {
                sb.append(buf, 0, n);
            }
        }
        return parseJson(sb.toString());
    }

    private static void save(Path file, KeyData data) throws IOException {
        String json = toJson(data);
        try (Writer w = Files.newBufferedWriter(file)) {
            w.write(json);
        }
        // best-effort 设文件权限 600
        try {
            java.nio.file.attribute.PosixFilePermissions.fromString("rw-------");
            Files.setPosixFilePermissions(file,
                    java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException ignored) {
            // Windows 上 POSIX 不支持，忽略
        }
    }

    /** 极简 JSON 序列化（不引入 Gson 依赖）。 */
    private static String toJson(KeyData d) {
        StringBuilder sb = new StringBuilder(256);
        sb.append('{');
        sb.append("\"version\":\"").append(escape(d.version)).append("\",");
        sb.append("\"publicKey\":\"").append(escape(d.publicKey)).append("\",");
        sb.append("\"privateKey\":\"").append(escape(d.privateKey)).append("\",");
        sb.append("\"rawPublicKey\":\"").append(escape(d.rawPublicKey)).append("\",");
        sb.append("\"createdAt\":").append(d.createdAt);
        sb.append('}');
        return sb.toString();
    }

    private static KeyData parseJson(String json) {
        String version = extractField(json, "version");
        String publicKey = extractField(json, "publicKey");
        String privateKey = extractField(json, "privateKey");
        String rawPublicKey = extractField(json, "rawPublicKey");
        if (rawPublicKey == null) rawPublicKey = "";
        String createdStr = extractNumericField(json, "createdAt");
        long createdAt = 0L;
        try { createdAt = Long.parseLong(createdStr); } catch (NumberFormatException ignored) {}
        return new KeyData(version, publicKey, privateKey, rawPublicKey, createdAt);
    }

    private static String extractField(String json, String key) {
        String pattern = "\"" + key + "\":\\s*\"";
        int start = json.indexOf(pattern);
        if (start < 0) return null;
        start += pattern.length();
        int end = json.indexOf('"', start);
        if (end < 0) return null;
        return unescape(json.substring(start, end));
    }

    private static String extractNumericField(String json, String key) {
        String pattern = "\"" + key + "\":\\s*";
        int start = json.indexOf(pattern);
        if (start < 0) return "0";
        start += pattern.length();
        int end = start;
        while (end < json.length() && Character.isDigit(json.charAt(end))) end++;
        return json.substring(start, end);
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String unescape(String s) {
        return s.replace("\\\"", "\"").replace("\\\\", "\\");
    }

    private static final class KeyData {
        final String version;
        final String publicKey;       // DER 编码 base64
        final String privateKey;      // PKCS8 编码 base64
        final String rawPublicKey;    // 32 字节原始 base64（发给客户端用）
        final long createdAt;

        KeyData(String version, String publicKey, String privateKey,
                String rawPublicKey, long createdAt) {
            this.version = version;
            this.publicKey = publicKey;
            this.privateKey = privateKey;
            this.rawPublicKey = rawPublicKey;
            this.createdAt = createdAt;
        }
    }
}
