package top.kunxun.device;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * 客户端模组与服务器插件之间的设备绑定协议。
 *
 * <p>这个类刻意不引用任何 Minecraft 类：三个加载器（Fabric / NeoForge / Forge）
 * 的封包类只是把这个字符串塞进自定义负载里，协议本身只有一份实现，
 * 不会出现「Fabric 版签名算法和 Forge 版不一样」这种事。
 *
 * <p>线格式（全部为 UTF-8 纯文本，字段用 {@code |} 分隔）：
 *
 * <pre>
 * 服务器 -&gt; 客户端  challenge：  1|nonce|serverId|playerName
 * 客户端 -&gt; 服务器  response ：  2|publicKey|signature|deviceName|fingerprint
 * </pre>
 *
 * <p>其中 {@code nonce} 是服务器生成的随机数（防重放），{@code signature} 是
 * 客户端用设备私钥对 {@code nonce|serverId|playerName} 整串做的 Ed25519 签名。
 * 服务器拿 {@code publicKey} 验签通过，就说明「这台设备确实持有该账号绑定的私钥」，
 * 于是可以免密放行。
 *
 * <p>{@code fingerprint} 是本机硬件指纹的摘要（见 {@link DeviceFingerprint}），
 * 服务端把它存进设备表，用来回答「这台机器还是不是当初绑定那台」。
 * 它<b>不是</b>凭据：公钥验签才是。
 *
 * <p>协议里不出现密码，也不出现任何长期凭据：每次登录都是一次新的随机挑战。
 *
 * <p><b>关于版本号。</b> 挑战那一侧始终是 {@code 1} —— 它的字段从第一天起就没变过，
 * 把它提到 2 只会让所有老模组静默不回包，等于用一次服务端升级把玩家的免密整体关掉。
 * 新增的设备指纹放在应答里，应答版本因此是 {@code 2}；服务端同时接受
 * {@code 1}（4 字段，无指纹）和 {@code 2}（5 字段），所以老模组连到新插件照样能用。
 */
public final class DeviceProtocol {

    /** 插件命名空间，和 KunxunAuth 的一致性靠这个字符串对齐 */
    public static final String NAMESPACE = "kunxunauth";

    /** 通道名：kunxunauth:device */
    public static final String PATH = "device";

    /** 负载标识，用于同一通道下区分两个方向的包 */
    public static final String ID_CHALLENGE = "challenge";
    public static final String ID_RESPONSE = "response";

    /** 应答的协议版本：2 = 末尾多一个设备指纹字段 */
    public static final int PROTOCOL_VERSION = 2;

    /**
     * 通道注册用的网络版本，<b>刻意与 {@link #PROTOCOL_VERSION} 分开</b>。
     *
     * <p>Forge / NeoForge 会在握手时比对「双方注册表的版本串」。线格式加了一个字段
     * 并不需要客户端之间重新协商，把它跟着一起 +1 只会让老服务端、老客户端之间
     * 平白多出一种「版本不匹配」的报错可能。所以这个值保持不变，
     * 只有真正改动包结构（增删包类型）时才动它。
     */
    public static final int CHANNEL_NETWORK_VERSION = 1;

    /** 挑战格式的版本，服务端一直用这个值 */
    public static final int CHALLENGE_VERSION = 1;

    /** 设备指纹摘要长度上限，与插件端 MAX_FINGERPRINT 对齐 */
    public static final int MAX_FINGERPRINT = 64;

    private static final String SEPARATOR = "|";
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private DeviceProtocol() {
    }

    // ------------------------------------------------------------------ 数据

    /** 服务器发来的挑战 */
    public record Challenge(String nonce, String serverId, String playerName) {

        /** 客户端要签名的原文 */
        public String signingInput() {
            return nonce + SEPARATOR + serverId + SEPARATOR + playerName;
        }

        public byte[] signingBytes() {
            return signingInput().getBytes(StandardCharsets.UTF_8);
        }
    }

    /** 客户端回给服务器的应答 */
    public record Response(String publicKey, String signature, String deviceName, String fingerprint) {
    }

    /** 挑战解析失败时抛出；调用方应当忽略这个包而不是断开连接 */
    public static final class MalformedPayloadException extends RuntimeException {
        public MalformedPayloadException(String message) {
            super(message);
        }
    }

    // ------------------------------------------------------------ 编解码

    /** 服务器侧：把挑战编码成负载内容 */
    public static String encodeChallenge(String nonceBase64, String serverId, String playerName) {
        return CHALLENGE_VERSION + SEPARATOR
                + sanitize(nonceBase64) + SEPARATOR
                + sanitize(serverId) + SEPARATOR
                + sanitize(playerName);
    }

    /**
     * 解析挑战。
     *
     * <p>版本号必须是我们认识的那一个；不认识就<b>安静地不回包</b>（抛异常由上层吞掉），
     * 而不是把玩家踢下线 —— 协议升级不该让任何人卡在门外。
     */
    public static Challenge parseChallenge(String payload) {
        String[] parts = split(payload, 4, "challenge");
        int version = parseInt(parts[0]);
        if (version != CHALLENGE_VERSION && version != PROTOCOL_VERSION) {
            throw new MalformedPayloadException("协议版本不匹配: " + version);
        }
        return new Challenge(parts[1], parts[2], parts[3]);
    }

    /**
     * 客户端侧：把应答编码成负载内容。
     *
     * <p>{@code fingerprint} 为空时退回 4 字段的 v1 形态 —— 这只会发生在指纹采集
     * 彻底失败的时候，此时报文仍然合法，服务端按「老模组」处理。
     */
    public static String encodeResponse(String publicKeyBase64, String signatureBase64, String deviceName,
                                        String fingerprint) {
        String cleanFingerprint = sanitize(fingerprint);
        if (cleanFingerprint.isEmpty()) {
            return CHALLENGE_VERSION + SEPARATOR
                    + sanitize(publicKeyBase64) + SEPARATOR
                    + sanitize(signatureBase64) + SEPARATOR
                    + sanitize(deviceName);
        }
        if (cleanFingerprint.length() > MAX_FINGERPRINT) {
            cleanFingerprint = cleanFingerprint.substring(0, MAX_FINGERPRINT);
        }
        return PROTOCOL_VERSION + SEPARATOR
                + sanitize(publicKeyBase64) + SEPARATOR
                + sanitize(signatureBase64) + SEPARATOR
                + sanitize(deviceName) + SEPARATOR
                + cleanFingerprint;
    }

    /** 解析服务端应答（目前只有服务端会解析它，这里留着做自检与单测用） */
    public static Response parseResponse(String payload) {
        String[] parts = splitRaw(payload, "response");
        int version = parseInt(parts[0]);
        if (version == CHALLENGE_VERSION && parts.length == 4) {
            return new Response(parts[1], parts[2], parts[3], "");
        }
        if (version == PROTOCOL_VERSION && parts.length == 5) {
            return new Response(parts[1], parts[2], parts[3], parts[4]);
        }
        throw new MalformedPayloadException("response 负载不合法: 版本 " + version
                + " 字段数 " + parts.length);
    }

    // ------------------------------------------------------------------ 工具

    public static String base64(byte[] raw) {
        return ENCODER.encodeToString(raw);
    }

    public static byte[] unbase64(String encoded) {
        return DECODER.decode(encoded);
    }

    /**
     * 清掉字段里的分隔符。
     *
     * <p>玩家名和服务器 ID 都是外部输入，理论上不该出现 {@code |}，
     * 但真出现了也不能让整条协议错位——那会变成「换个游戏名就能伪造签名」。
     */
    private static String sanitize(String value) {
        if (value == null) {
            return "";
        }
        return value.replace(SEPARATOR, "");
    }

    private static String[] split(String payload, int expected, String kind) {
        String[] parts = splitRaw(payload, kind);
        if (parts.length != expected) {
            throw new MalformedPayloadException(
                    kind + " 负载字段数不对: 期望 " + expected + " 实际 " + parts.length);
        }
        return parts;
    }

    /** 按 {@code |} 切分，保留空段（{@code -1}），否则末尾的空字段会被吃掉导致段数对不上 */
    private static String[] splitRaw(String payload, String kind) {
        if (payload == null || payload.isEmpty()) {
            throw new MalformedPayloadException(kind + " 负载为空");
        }
        return payload.split("\\" + SEPARATOR, -1);
    }

    private static int parseInt(String value) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new MalformedPayloadException("协议版本不是数字: " + value);
        }
    }
}
