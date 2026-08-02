/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.crypto;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.util.Map;
import java.util.TreeMap;

/**
 * 规范化 JSON 序列化工具（Canonical JSON）。
 * <p>
 * 规则（严格遵守，验签前必须使用）：
 * <ol>
 *   <li>所有对象键按字典序（lexicographic）升序排列；</li>
 *   <li>无多余空格——键值分隔符 ':' 与元素分隔符 ',' 后均无空格；</li>
 *   <li>无换行；</li>
 *   <li>递归处理嵌套对象与数组；</li>
 *   <li>字符串转义遵循 JSON 标准（双引号、反斜杠、控制字符及 Unicode 转义序列）。</li>
 * </ol>
 * 该实现与 JavaScript 端 canonicalJsonStringify 行为对齐，
 * 保证服务端验签时计算出的待签名字节与验证服务器签名时一致。
 */
public final class CanonicalJson {

    private CanonicalJson() {
    }

    /** 将任意 JsonElement 序列化为规范化 JSON 字符串。 */
    public static String stringify(JsonElement element) {
        StringBuilder sb = new StringBuilder();
        write(element, sb);
        return sb.toString();
    }

    private static void write(JsonElement element, StringBuilder sb) {
        if (element == null || element.isJsonNull()) {
            sb.append("null");
        } else if (element.isJsonObject()) {
            writeObject(element.getAsJsonObject(), sb);
        } else if (element.isJsonArray()) {
            writeArray(element.getAsJsonArray(), sb);
        } else if (element.isJsonPrimitive()) {
            writePrimitive(element.getAsJsonPrimitive(), sb);
        }
    }

    private static void writeObject(JsonObject obj, StringBuilder sb) {
        sb.append('{');
        // TreeMap 按 key 自然序（字典序）排列，保证输出稳定
        TreeMap<String, JsonElement> sorted = new TreeMap<>();
        for (Map.Entry<String, JsonElement> e : obj.entrySet()) {
            sorted.put(e.getKey(), e.getValue());
        }
        boolean first = true;
        for (Map.Entry<String, JsonElement> e : sorted.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append(quote(e.getKey()));
            sb.append(':');
            write(e.getValue(), sb);
        }
        sb.append('}');
    }

    private static void writeArray(JsonArray arr, StringBuilder sb) {
        sb.append('[');
        boolean first = true;
        for (JsonElement e : arr) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            write(e, sb);
        }
        sb.append(']');
    }

    private static void writePrimitive(JsonPrimitive p, StringBuilder sb) {
        if (p.isNumber()) {
            // 直接输出数字字面量，不加引号
            sb.append(p.getAsNumber().toString());
        } else if (p.isBoolean()) {
            sb.append(p.getAsBoolean() ? "true" : "false");
        } else {
            sb.append(quote(p.getAsString()));
        }
    }

    /**
     * JSON 字符串转义：用双引号包裹，转义控制字符与特殊字符。
     */
    private static String quote(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 2);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b");  break;
                case '\f': sb.append("\\f");  break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
        return sb.toString();
    }
}
