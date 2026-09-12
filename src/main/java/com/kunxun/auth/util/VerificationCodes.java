package com.kunxun.auth.util;

import java.security.SecureRandom;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 邮箱验证码的签发与校验（内存实现）。
 *
 * <p>键是「用途 + 规范化邮箱」，所以同一个邮箱的「注册码」和「找回密码码」
 * 互不干扰。验证码只保存在内存里、只以哈希无关的明文形式短暂存在，
 * 重启服务器即全部失效——这是有意的，避免把验证码落盘。
 */
public final class VerificationCodes {

    public enum Purpose { REGISTER, RESET }

    public enum Status {
        /** 校验通过，验证码已作废 */
        OK,
        /** 没有发过验证码 */
        MISSING,
        /** 验证码不对 */
        WRONG,
        /** 已过期 */
        EXPIRED,
        /** 错误次数用尽 */
        TOO_MANY
    }

    public record Result(Status status, int remainingAttempts) {
        public boolean ok() {
            return status == Status.OK;
        }
    }

    private static final class Entry {
        private final String code;
        private final long expiresAt;
        private final long sentAt;
        private int attempts;

        Entry(String code, long expiresAt, long sentAt) {
            this.code = code;
            this.expiresAt = expiresAt;
            this.sentAt = sentAt;
        }
    }

    private static final int CODE_BOUND = 1_000_000;

    private final Map<String, Entry> entries = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

    private static String key(Purpose purpose, String email) {
        return purpose.name() + "|" + Emails.normalize(email);
    }

    /**
     * 签发一个新验证码，覆盖该邮箱此前的同用途验证码。
     *
     * @return 6 位数字验证码
     */
    public String issue(Purpose purpose, String email, int expireMinutes) {
        String code = String.format(Locale.ROOT, "%06d", random.nextInt(CODE_BOUND));
        long now = System.currentTimeMillis();
        entries.put(key(purpose, email), new Entry(code, now + expireMinutes * 60_000L, now));
        return code;
    }

    /**
     * 距离可以再次发送还差多少秒。
     *
     * @return 0 表示现在就能发
     */
    public long resendCooldownRemaining(Purpose purpose, String email, int cooldownSeconds) {
        if (cooldownSeconds <= 0) {
            return 0L;
        }
        Entry entry = entries.get(key(purpose, email));
        if (entry == null) {
            return 0L;
        }
        long elapsed = System.currentTimeMillis() - entry.sentAt;
        long waitMillis = cooldownSeconds * 1000L - elapsed;
        return waitMillis <= 0 ? 0L : (waitMillis + 999L) / 1000L;
    }

    /** 该邮箱是否已经发过（且尚未过期）验证码 */
    public boolean has(Purpose purpose, String email) {
        Entry entry = entries.get(key(purpose, email));
        return entry != null && entry.expiresAt > System.currentTimeMillis();
    }

    /**
     * 校验验证码。校验成功会立刻作废该验证码，防止重放。
     */
    public Result verify(Purpose purpose, String email, String input, int maxAttempts) {
        String mapKey = key(purpose, email);
        Entry entry = entries.get(mapKey);
        if (entry == null) {
            return new Result(Status.MISSING, 0);
        }
        if (System.currentTimeMillis() > entry.expiresAt) {
            entries.remove(mapKey);
            return new Result(Status.EXPIRED, 0);
        }
        if (entry.attempts >= Math.max(1, maxAttempts)) {
            entries.remove(mapKey);
            return new Result(Status.TOO_MANY, 0);
        }
        String normalized = input == null ? "" : input.trim();
        if (!entry.code.equals(normalized)) {
            entry.attempts++;
            int remaining = Math.max(0, maxAttempts - entry.attempts);
            if (remaining == 0) {
                entries.remove(mapKey);
                return new Result(Status.TOO_MANY, 0);
            }
            return new Result(Status.WRONG, remaining);
        }
        entries.remove(mapKey);
        return new Result(Status.OK, 0);
    }

    /** 主动作废，例如玩家取消注册 */
    public void invalidate(Purpose purpose, String email) {
        entries.remove(key(purpose, email));
    }

    /** 清理过期条目 */
    public void sweep() {
        long now = System.currentTimeMillis();
        entries.entrySet().removeIf(entry -> entry.getValue().expiresAt + 3_600_000L < now);
    }

    public int size() {
        return entries.size();
    }
}
