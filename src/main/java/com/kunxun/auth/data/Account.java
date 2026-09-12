package com.kunxun.auth.data;

/**
 * 一条账号记录。
 *
 * @param id             自增主键
 * @param username       玩家名（保留原始大小写）
 * @param email          绑定邮箱（原始大小写）
 * @param passwordHash   PBKDF2 哈希串
 * @param registeredAt   注册时间戳（毫秒）
 * @param lastLoginAt    上次登录时间戳（毫秒，0 = 从未）
 * @param lastIp         上次登录 IP
 * @param failedAttempts 连续登录失败次数
 * @param lockedUntil    锁定到期时间戳（毫秒，0 = 未锁定）
 */
public record Account(
        long id,
        String username,
        String email,
        String passwordHash,
        long registeredAt,
        long lastLoginAt,
        String lastIp,
        int failedAttempts,
        long lockedUntil
) {

    public boolean isLocked(long now) {
        return lockedUntil > now;
    }

    public long lockedMinutesLeft(long now) {
        long remaining = lockedUntil - now;
        return remaining <= 0 ? 0 : (remaining + 59_999L) / 60_000L;
    }
}
