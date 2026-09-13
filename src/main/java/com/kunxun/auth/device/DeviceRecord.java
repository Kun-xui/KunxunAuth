package com.kunxun.auth.device;

/**
 * 一条已绑定的设备记录。
 *
 * <p>{@code publicKey} 才是设备的身份，{@code deviceName} 只是玩家自报的显示名，
 * 可以随便改、也会重名，绝不能拿它做任何判定。
 *
 * <p>{@code fingerprint} 是客户端上报的硬件指纹摘要（CPU + 主板 + 系统盘 + 机器 ID
 * 的 SHA-256 截断值），它是「这台机器」的稳定标识。它<b>不能</b>替代公钥：
 * 指纹是任何进程都能读到的公开信息，可以被伪造；公钥对应的私钥才是真正的凭据。
 * 指纹的作用是把「私钥文件被整份复制到另一台机器」这件事变成一次可发现的异常，
 * 并提供一条「换机器就该重新绑定」的判定依据。
 */
public record DeviceRecord(long id, String publicKey, String username, String deviceName,
                           long createdAt, long lastSeenAt, String lastIp, String fingerprint) {

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

    /** 指纹摘要是否可用（老模组回复的 v1 应答没有这一项） */
    public boolean hasFingerprint() {
        return fingerprint != null && !fingerprint.isEmpty();
    }

    /** 指纹前缀，只用于管理命令里给人看，不做任何判定 */
    public String fingerprintPrefix() {
        if (!hasFingerprint()) {
            return "无";
        }
        return fingerprint.length() <= 8 ? fingerprint : fingerprint.substring(0, 8);
    }

    /** 这份记录是否来自同一台机器（任一侧缺失都算「无法判定」，返回 false） */
    public boolean sameMachine(String otherFingerprint) {
        return hasFingerprint() && otherFingerprint != null
                && !otherFingerprint.isEmpty() && fingerprint.equals(otherFingerprint);
    }
}
