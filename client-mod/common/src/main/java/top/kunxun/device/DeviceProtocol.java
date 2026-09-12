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
 * 服务器 -&gt; 客户端  challenge：  nonce|serverId|playerName
 * 客户端 -&gt; 服务器  response ：  publicKey|signature|deviceName
 * </pre>
 *
 * <p>其中 {@code nonce} 是服务器生成的随机数（防重放），{@code signature} 是
 * 客户端用设备私钥对 {@code nonce|serverId|playerName} 整串做的 Ed25519 签名。
 * 服务器拿 {@code publicKey} 验签通过，就说明「这台设备确实持有该账号绑定的私钥」，
 * 于是可以免密放行。
 *
 * <p>协议里不出现密码，也不出现任何长期凭据：每次登录都是一次新的随机挑战。
 */
public final class DeviceProtocol {

    /** 插件命名空间，和 KunxunAuth 的一致性靠这个字符串对齐 */
    public static final String NAMESPACE = "kunxunauth";

    /** 通道名：kunxunauth:device */
    public static final String PATH = "device";

    /** 负载标识，用于同一通道下区分两个方向的包 */
    public static final String ID_CHALLENGE = "challenge";
    public static final String ID_RESPONSE = "response";

    /** 协议版本：以后改线格式时靠它让老客户端优雅退出，而不是验签失败 */
    public static final int PROTOCOL_VERSION = 1;

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
    public record Response(String publicKey, String signature, String deviceName) {
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
        return PROTOCOL_VERSION + SEPARATOR
                + sanitize(nonceBase64) + SEPARATOR
                + sanitize(serverId) + SEPARATOR
                + sanitize(playerName);
    }

    public static Challenge parseChallenge(String payload) {
        String[] parts = split(payload, 4, "challenge");
        int version = parseInt(parts[0]);
        if (version != PROTOCOL_VERSION) {
            throw new MalformedPayloadException("协议版本不匹配: " + version);
        }
        return new Challenge(parts[1], parts[2], parts[3]);
    }

    /** 客户端侧：把应答编码成负载内容 */
    public static String encodeResponse(String publicKeyBase64, String signatureBase64, String deviceName) {
        return PROTOCOL_VERSION + SEPARATOR
                + sanitize(publicKeyBase64) + SEPARATOR
                + sanitize(signatureBase64) + SEPARATOR
                + sanitize(deviceName);
    }

    public static Response parseResponse(String payload) {
        String[] parts = split(payload, 4, "response");
        int version = parseInt(parts[0]);
        if (version != PROTOCOL_VERSION) {
            throw new MalformedPayloadException("协议版本不匹配: " + version);
        }
        return new Response(parts[1], parts[2], parts[3]);
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
        if (payload == null || payload.isEmpty()) {
            throw new MalformedPayloadException(kind + " 负载为空");
        }
        String[] parts = payload.split("\\" + SEPARATOR, -1);
        if (parts.length != expected) {
            throw new MalformedPayloadException(
                    kind + " 负载字段数不对: 期望 " + expected + " 实际 " + parts.length);
        }
        return parts;
    }

    private static int parseInt(String value) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new MalformedPayloadException("协议版本不是数字: " + value);
        }
    }
}
