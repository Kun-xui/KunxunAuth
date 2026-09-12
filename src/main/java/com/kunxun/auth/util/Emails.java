package com.kunxun.auth.util;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * 邮箱校验与小工具。
 */
public final class Emails {

    /**
     * 常规邮箱格式校验：本地部分 + @ + 域名 + 顶级域。
     * 刻意不允许中文域名 / 空格，避免把非法值写进数据库。
     */
    private static final Pattern PATTERN = Pattern.compile(
            "^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}@[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                    + "(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$");

    private static final int MAX_LENGTH = 254;

    private Emails() {
    }

    public static boolean isValid(String email) {
        if (email == null) {
            return false;
        }
        String trimmed = email.trim();
        if (trimmed.isEmpty() || trimmed.length() > MAX_LENGTH) {
            return false;
        }
        if (trimmed.startsWith(".") || trimmed.contains("..")) {
            return false;
        }
        return PATTERN.matcher(trimmed).matches();
    }

    public static String normalize(String email) {
        return email == null ? "" : email.trim().toLowerCase(Locale.ROOT);
    }

    /** 取 @ 后面的域名，小写 */
    public static String domain(String email) {
        String normalized = normalize(email);
        int at = normalized.lastIndexOf('@');
        return at < 0 ? "" : normalized.substring(at + 1);
    }

    /** 域名是否命中（相等或子域），用于黑白名单 */
    public static boolean domainMatches(String domain, String rule) {
        if (domain.isEmpty() || rule == null || rule.isEmpty()) {
            return false;
        }
        String normalizedRule = rule.trim().toLowerCase(Locale.ROOT);
        return domain.equals(normalizedRule) || domain.endsWith("." + normalizedRule);
    }

    /** 打码显示：abcdef@qq.com → ab***@qq.com */
    public static String mask(String email) {
        if (email == null || email.isBlank()) {
            return "";
        }
        String trimmed = email.trim();
        int at = trimmed.lastIndexOf('@');
        if (at <= 0) {
            return trimmed;
        }
        String local = trimmed.substring(0, at);
        String domain = trimmed.substring(at);
        if (local.length() <= 2) {
            return local.charAt(0) + "***" + domain;
        }
        return local.substring(0, 2) + "***" + domain;
    }
}
