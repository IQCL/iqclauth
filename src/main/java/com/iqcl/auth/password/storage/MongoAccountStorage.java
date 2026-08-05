/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.password.storage;

import com.iqcl.auth.IqclAuth;
import com.iqcl.auth.config.ModConfig;
import com.iqcl.auth.password.AccountRecord;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.IndexOptions;
import com.mongodb.client.model.Indexes;
import org.bson.Document;
import org.bson.types.Binary;

import java.util.UUID;

/**
 * MongoDB 存储后端实现。
 * <p>
 * 依赖：{@code org.mongodb:mongodb-driver-sync} 嵌套 JAR。
 * <p>
 * 文档结构：
 * <pre>
 * {
 *   "_id":          "uuid-string",
 *   "username":     "string",
 *   "salt":         Binary(subtype, byte[]),
 *   "hash":         Binary(subtype, byte[]),
 *   "iterations":   int,
 *   "createdAtMs":  long,
 *   "updatedAtMs":  long
 * }
 * </pre>
 */
public final class MongoAccountStorage implements AccountStorage {

    private final MongoClient client;
    private final MongoCollection<Document> collection;

    public MongoAccountStorage(ModConfig.PasswordStorageConfig cfg) {
        // 优先使用完整 URI，否则从 host/port 拼接
        String uri;
        if (cfg.mongoUri != null && !cfg.mongoUri.isEmpty()) {
            uri = cfg.mongoUri;
        } else {
            String host = cfg.mongoHost != null ? cfg.mongoHost : "localhost";
            int port = cfg.mongoPort > 0 ? cfg.mongoPort : 27017;
            uri = "mongodb://" + host + ":" + port;
        }

        this.client = MongoClients.create(uri);
        MongoDatabase database = client.getDatabase(cfg.mongoDatabase != null ? cfg.mongoDatabase : "iqclauth");
        String collName = cfg.mongoCollection != null ? cfg.mongoCollection : "accounts";
        this.collection = database.getCollection(collName);
        IqclAuth.LOGGER.info("[IQCL Auth] MongoDB 存储后端已初始化: {} → {}", uri, collName);
    }

    @Override
    public void init() {
        // 创建唯一索引（若不存在）
        try {
            collection.createIndex(Indexes.ascending("uuid"),
                    new IndexOptions().unique(true).name("uuid_1"));
            collection.createIndex(Indexes.ascending("username"),
                    new IndexOptions().unique(true).name("username_1"));
        } catch (Exception e) {
            // 索引已存在则忽略
            IqclAuth.LOGGER.debug("[IQCL Auth] MongoDB 索引创建完成或已存在", e);
        }
    }

    @Override
    public void close() {
        if (client != null) {
            client.close();
            IqclAuth.LOGGER.info("[IQCL Auth] MongoDB 存储后端已关闭");
        }
    }

    @Override
    public AccountRecord findByUuid(UUID uuid) {
        Document filter = new Document("uuid", uuid.toString());
        Document doc = collection.find(filter).first();
        return doc != null ? documentToRecord(doc) : null;
    }

    @Override
    public AccountRecord findByUsername(String username) {
        Document filter = new Document("username", username);
        Document doc = collection.find(filter).first();
        return doc != null ? documentToRecord(doc) : null;
    }

    @Override
    public void insert(AccountRecord record) throws StorageException {
        Document doc = recordToDocument(record);
        try {
            collection.insertOne(doc);
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : "";
            if (msg.contains("E11000") || msg.contains("duplicate key")) {
                throw new StorageException("账号已存在", e);
            }
            throw new StorageException("MongoDB 插入失败", e);
        }
    }

    @Override
    public void updatePassword(UUID uuid, byte[] salt, byte[] hash, int iterations, long updatedAtMs)
            throws StorageException {
        Document filter = new Document("uuid", uuid.toString());
        Document update = new Document("$set", new Document()
                .append("salt", new Binary((byte) 0x00, salt))
                .append("hash", new Binary((byte) 0x00, hash))
                .append("iterations", iterations)
                .append("updatedAtMs", updatedAtMs));
        com.mongodb.client.result.UpdateResult result = collection.updateOne(filter, update);
        if (result.getMatchedCount() == 0) {
            throw new StorageException("更新失败：账号不存在");
        }
    }

    @Override
    public void updateTotp(UUID uuid, boolean enabled, String secret, String lastCode, long updatedAtMs)
            throws StorageException {
        Document filter = new Document("uuid", uuid.toString());
        Document update = new Document("$set", new Document()
                .append("totpEnabled", enabled)
                .append("totpSecret", secret)
                .append("totpLastCode", lastCode)
                .append("updatedAtMs", updatedAtMs));
        com.mongodb.client.result.UpdateResult result = collection.updateOne(filter, update);
        if (result.getMatchedCount() == 0) {
            throw new StorageException("更新 TOTP 失败：账号不存在");
        }
    }

    @Override
    public void updateTotpLastCode(UUID uuid, String lastCode) throws StorageException {
        Document filter = new Document("uuid", uuid.toString());
        Document update = new Document("$set", new Document("totpLastCode", lastCode));
        collection.updateOne(filter, update);
    }

    @Override
    public void delete(UUID uuid) {
        collection.deleteOne(new Document("uuid", uuid.toString()));
    }

    @Override
    public boolean exists(UUID uuid) {
        return collection.find(new Document("uuid", uuid.toString())).first() != null;
    }

    private Document recordToDocument(AccountRecord r) {
        Document doc = new Document();
        doc.append("uuid", r.uuid.toString());
        doc.append("username", r.username);
        doc.append("salt", new Binary((byte) 0x00, r.salt));
        doc.append("hash", new Binary((byte) 0x00, r.hash));
        doc.append("iterations", r.iterations);
        doc.append("createdAtMs", r.createdAtMs);
        doc.append("updatedAtMs", r.updatedAtMs);
        doc.append("totpEnabled", r.totpEnabled);
        doc.append("totpSecret", r.totpSecret);
        doc.append("totpLastCode", r.totpLastCode);
        return doc;
    }

    private AccountRecord documentToRecord(Document doc) {
        String uuidStr = doc.getString("uuid");
        String username = doc.getString("username");
        Binary saltBin = doc.get("salt", Binary.class);
        Binary hashBin = doc.get("hash", Binary.class);
        Integer iterations = doc.getInteger("iterations");
        Long createdAtMs = doc.getLong("createdAtMs");
        Long updatedAtMs = doc.getLong("updatedAtMs");
        Boolean totpEnabled = doc.getBoolean("totpEnabled", false);
        String totpSecret = doc.getString("totpSecret");
        String totpLastCode = doc.getString("totpLastCode");
        return new AccountRecord(
                UUID.fromString(uuidStr),
                username,
                saltBin.getData(),
                hashBin.getData(),
                iterations != null ? iterations : 100_000,
                createdAtMs != null ? createdAtMs : 0L,
                updatedAtMs != null ? updatedAtMs : 0L,
                totpEnabled != null && totpEnabled,
                totpSecret,
                totpLastCode
        );
    }
}
