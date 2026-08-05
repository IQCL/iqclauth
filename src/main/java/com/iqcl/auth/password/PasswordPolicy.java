/*
 * Copyright (c) 2026 IQCL
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package com.iqcl.auth.password;

import com.iqcl.auth.config.ModConfig;

/**
 * 密码强度校验（集中规则）。
 * <p>
 * 规则由 {@link ModConfig.PasswordPolicyConfig} 驱动。
 * 校验结果通过 {@link ValidationResult} 返回，包含结果枚举与本地化消息 key。
 */
public final class PasswordPolicy {

    /** 弱密码黑名单（小写匹配）。 */
    private static final String[] WEAK_BLACKLIST = {
            "123456", "12345678", "123456789", "1234567890",
            "password", "passwd", "qwerty", "abc123", "111111", "000000",
            "iloveyou", "admin", "letmein", "welcome", "monkey"
    };

    private PasswordPolicy() {
    }

    /**
     * 校验密码是否符合策略。
     *
     * @param password 待校验密码（不为 null）
     * @return 校验结果
     */
    public static ValidationResult validate(String password) {
        if (password == null) {
            return new ValidationResult(Result.NULL, "iqclauth.password.error.null");
        }
        ModConfig.PasswordPolicyConfig cfg = ModConfig.get().passwordPolicy;

        int len = password.length();
        if (len < cfg.minPasswordLength) {
            return new ValidationResult(Result.TOO_SHORT, "iqclauth.password.error.too_short");
        }
        if (len > cfg.maxPasswordLength) {
            return new ValidationResult(Result.TOO_LONG, "iqclauth.password.error.too_long");
        }

        boolean hasLetter = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;
        boolean hasIllegal = false;

        for (int i = 0; i < len; i++) {
            char c = password.charAt(i);
            if (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
                hasLetter = true;
            } else if (c >= '0' && c <= '9') {
                hasDigit = true;
            } else if (c == ' ') {
                // 空格单独处理
            } else if (c >= 0x20 && c < 0x7F) {
                // 可见 ASCII 非字母数字非空格 → 视为特殊字符
                hasSpecial = true;
            } else if (c < 0x20 || c == 0x7F) {
                // 控制字符 → 拒绝
                hasIllegal = true;
            } else {
                // 非 ASCII（如中文）→ 视为特殊字符
                hasSpecial = true;
            }
        }

        if (hasIllegal) {
            return new ValidationResult(Result.ILLEGAL_CHAR, "iqclauth.password.error.illegal_char");
        }
        if (!cfg.allowSpace && password.indexOf(' ') >= 0) {
            return new ValidationResult(Result.ILLEGAL_CHAR, "iqclauth.password.error.no_space");
        }
        if (cfg.requireLetter && !hasLetter) {
            return new ValidationResult(Result.NO_LETTER, "iqclauth.password.error.no_letter");
        }
        if (cfg.requireDigit && !hasDigit) {
            return new ValidationResult(Result.NO_DIGIT, "iqclauth.password.error.no_digit");
        }
        if (cfg.requireSpecialChar && !hasSpecial) {
            return new ValidationResult(Result.NO_SPECIAL, "iqclauth.password.error.no_special");
        }

        // 弱密码黑名单（级别 ≥ 1）
        if (cfg.weakPasswordCheckLevel >= 1) {
            String lower = password.toLowerCase();
            for (String weak : WEAK_BLACKLIST) {
                if (lower.contains(weak)) {
                    return new ValidationResult(Result.WEAK, "iqclauth.password.error.weak");
                }
            }
        }

        return new ValidationResult(Result.OK, null);
    }

    /** 校验结果枚举。 */
    public enum Result {
        OK,
        NULL,
        TOO_SHORT,
        TOO_LONG,
        NO_LETTER,
        NO_DIGIT,
        NO_SPECIAL,
        ILLEGAL_CHAR,
        WEAK
    }

    /** 校验结果载体。 */
    public static final class ValidationResult {
        public final Result result;
        public final String messageKey;

        public ValidationResult(Result result, String messageKey) {
            this.result = result;
            this.messageKey = messageKey;
        }

        public boolean isValid() {
            return result == Result.OK;
        }
    }
}
