package com.kunxun.auth.device;

/**
 * 一条已绑定的设备记录。
 *
 * <p>{@code publicKey} 才是设备的身份，{@code deviceName} 只是玩家自报的显示名，
 * 可以随便改、也会重名，绝不能拿它做任何判定。
 */
public record DeviceRecord(long id, String publicKey, String username, String deviceName,
                           long createdAt, long lastSeenAt, String lastIp) {

    /**
     * 公钥前缀，用于在聊天里指认「是哪一台」。
     *
     * <p>公钥本身是 59 个字符的 Base64url，整串贴给玩家没法看；
     * 但完整公钥必须能对上，所以列表里显示前缀、删除时要求玩家给前缀即可，
     * 前缀撞车时再退回用列表序号。
     */
    public String keyPrefix() {
        return publicKey.length() <= 12 ? publicKey : publicKey.substring(0, 12);
    }

    /** 设备名缺失时的兜底显示 */
    public String displayName() {
        return deviceName == null || deviceName.isBlank() ? "未命名设备" : deviceName;
    }
}
