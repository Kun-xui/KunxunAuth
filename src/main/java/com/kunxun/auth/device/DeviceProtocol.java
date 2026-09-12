package com.kunxun.auth.device;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * 设备免密登录的线格式（KunxunAuth Device 协议 v1）。
 *
 * <p>负载就是一个用 {@code |} 分隔的纯文本字符串，塞进 {@code kunxunauth:device}
 * 通道的自定义负载里原样传输。选纯文本而不是 NBT/JSON，是因为它在任何平台、
 * 任何 MC 版本上都不需要额外编解码器，三行代码就能解析完。
 *
 * <pre>
 *   服务端 → 客户端：1|nonce|serverId|playerName
 *   客户端 → 服务端：1|publicKey|signature|deviceName
 * </pre>
 *
 * <p>签名覆盖的内容是 {@code nonce + "|" + serverId + "|" + playerName}
 * 的 UTF-8 字节（<b>没有</b>版本号前缀）。服务端验签时必须用「自己记录的」
 * nonce / serverId / playerName 重建这段字节 —— 应答里根本没有 playerName 字段，
 * 就是为了让服务端没得选，攻击者无从注入。
 *
 * <p>所有 Base64 一律是 <b>Base64url 去填充</b>；解码前要先把 {@code =} 补回去，
 * 因为不同实现有的补有的不补，直接比较字符串会莫名失败。
 */
public final class DeviceProtocol {

    /** 通道完整标识 */
    public static final String CHANNEL = "kunxunauth:device";

    /**
     * Fabric / NeoForge 客户端的挑战通道。
     *
     * <p>这两个加载器把「挑战」和「应答」注册成两个独立的
     * {@code CustomPacketPayload.Type}，也就是两条不同的通道名；
     * Forge 则把所有消息塞进同一条 {@link #CHANNEL}，靠包体内的序号区分。
     * 三条通道名都发，谁认得就用谁的，谁也不认得就当玩家没装模组（回落密码登录）。
     */
    public static final String CHANNEL_CHALLENGE = "kunxunauth:challenge";

    /** Fabric / NeoForge 客户端的应答通道 */
    public static final String CHANNEL_RESPONSE = "kunxunauth:response";

    /** Forge 客户端上「挑战」消息的注册序号（先注册，分到 0） */
    public static final int FORGE_INDEX_CHALLENGE = 0;

    /** Forge 客户端上「应答」消息的注册序号（后注册，分到 1） */
    public static final int FORGE_INDEX_RESPONSE = 1;

    /** 协议版本，恒为 "1" */
    public static final String VERSION = "1";

    private static final char SEPARATOR = '|';
    private static final String SEPARATOR_TEXT = "|";

    /** Ed25519 公钥 X.509 DER 的固定前 12 字节 */
    private static final byte[] ED25519_DER_HEADER = {
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
    };

    /** X.509 DER 编码的 Ed25519 公钥固定 44 字节（12 字节头 + 32 字节裸公钥） */
    public static final int ED25519_DER_LENGTH = 44;

    /** Ed25519 签名固定 64 字节 */
    public static final int ED25519_SIGNATURE_LENGTH = 64;

    /** deviceName 只给人看，长度截断到数据库列宽 */
    public static final int MAX_DEVICE_NAME = 64;

    private DeviceProtocol() {
    }

    // ==================================================================== 编码

    /** Base64url、无填充 */
    public static String encodeBase64(byte[] raw) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    }

    /**
     * 解码 Base64url，自动补回 {@code =} 填充。
     *
     * @return 解码结果；输入不是合法 Base64 时返回 null
     */
    public static byte[] decodeBase64(String text) {
        if (text == null || text.isEmpty()) {
            return null;
        }
        int remainder = text.length() % 4;
        if (remainder == 1) {
            // 长度为 4n+1 不可能是任何 Base64 编码结果
            return null;
        }
        String padded = remainder == 0 ? text : text + "=".repeat(4 - remainder);
        try {
            return Base64.getUrlDecoder().decode(padded);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * 剔除字段内的分隔符，防止有人把玩家名写成 {@code a|b} 让字段错位。
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "";
        }
        return value.indexOf(SEPARATOR) < 0 ? value : value.replace(SEPARATOR_TEXT, "");
    }

    // ==================================================================== 组包

    /** 组装服务端 → 客户端的挑战字符串 */
    public static String challenge(String nonce, String serverId, String playerName) {
        return String.join(SEPARATOR_TEXT, VERSION,
                sanitize(nonce), sanitize(serverId), sanitize(playerName));
    }

    /** 客户端 → 服务端应答的解析结果 */
    public record Response(String publicKey, String signature, String deviceName) {
    }

    /**
     * 解析客户端应答。
     *
     * @return 格式不合法（段数不对 / 版本不认识 / 关键字段为空）时返回 null，
     *         调用方只需记一条日志然后忽略这个包
     */
    public static Response parseResponse(String payload) {
        if (payload == null) {
            return null;
        }
        String[] fields = payload.split("\\|", -1);
        if (fields.length != 4) {
            return null;
        }
        if (!VERSION.equals(fields[0])) {
            return null;
        }
        if (fields[1].isEmpty() || fields[2].isEmpty()) {
            return null;
        }
        String deviceName = fields[3];
        if (deviceName.length() > MAX_DEVICE_NAME) {
            deviceName = deviceName.substring(0, MAX_DEVICE_NAME);
        }
        return new Response(fields[1], fields[2], sanitize(deviceName));
    }

    // ==================================================================== 验签

    /** 签名原文：nonce + "|" + serverId + "|" + playerName（没有版本号前缀） */
    public static byte[] signingInput(String nonce, String serverId, String playerName) {
        return (nonce + SEPARATOR_TEXT + serverId + SEPARATOR_TEXT + playerName)
                .getBytes(StandardCharsets.UTF_8);
    }

    /**
     * 公钥必须是标准形状的 Ed25519 X.509 DER。
     *
     * <p>先做一次便宜的字节形状检查，避免把任意垃圾直接喂给 {@code KeyFactory}；
     * 后面还有真正的验签，这一步只是提前挡掉明显不对的输入。
     */
    public static boolean looksLikeEd25519Der(byte[] der) {
        if (der == null || der.length != ED25519_DER_LENGTH) {
            return false;
        }
        return Arrays.equals(Arrays.copyOf(der, ED25519_DER_HEADER.length), ED25519_DER_HEADER);
    }

    /**
     * 用 Base64url 形式的公钥验证签名。
     *
     * <p>算法名必须是 {@code "Ed25519"}。不要写 {@code "EdEC"} —— 那是 SunEC 的
     * 内部名字，JDK 上会直接抛 {@code NoSuchAlgorithmException}。
     *
     * @return true = 签名有效
     */
    public static boolean verify(String publicKeyBase64, String signatureBase64, byte[] signed) {
        byte[] der = decodeBase64(publicKeyBase64);
        if (!looksLikeEd25519Der(der)) {
            return false;
        }
        byte[] signature = decodeBase64(signatureBase64);
        if (signature == null || signature.length != ED25519_SIGNATURE_LENGTH) {
            return false;
        }
        try {
            PublicKey key = KeyFactory.getInstance("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(der));
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(key);
            verifier.update(signed);
            return verifier.verify(signature);
        } catch (GeneralSecurityException e) {
            // 密钥形状不对 / JDK 不支持算法：一律当作验签失败
            return false;
        }
    }

    // ==================================================================== 出站组包

    /**
     * 把挑战文本封成「Fabric / NeoForge 版」的包体。
     *
     * <p>这两个加载器用 {@code StreamCodec} 里的 {@code buf.readUtf()} 读文本，
     * 而 {@code writeUtf} 的线格式就是 <b>VarInt 长度 + UTF-8 字节</b>，
     * 所以这里原样照抄，别多加任何前缀。
     */
    public static byte[] challengeBody(String payload) {
        return utfBody(payload);
    }

    /**
     * 把挑战文本封成「Forge 版」的包体。
     *
     * <p>Forge 的 {@code SimpleChannel} 在同一条通道上复用了多个消息类型，
     * 因此发出去的每一个包体前面都被它<b>无条件</b>写了一个 VarInt 序号
     * （{@code SimpleChannel.encode} 里那句 {@code out.writeVarInt(msg.index())}）。
     * 挑战是静态块里第一个注册的，序号恒为 {@link #FORGE_INDEX_CHALLENGE}。
     */
    public static byte[] forgeChallengeBody(String payload) {
        return forgeFrame(payload, FORGE_INDEX_CHALLENGE);
    }

    /** VarInt 序号 + UTF 文本，即 Forge 客户端眼里的一条消息 */
    public static byte[] forgeFrame(String payload, int index) {
        byte[] indexBytes = varint(index);
        byte[] body = utfBody(payload);
        byte[] out = new byte[indexBytes.length + body.length];
        System.arraycopy(indexBytes, 0, out, 0, indexBytes.length);
        System.arraycopy(body, 0, out, indexBytes.length, body.length);
        return out;
    }

    /** 原生 {@code writeUtf} 线格式：VarInt 长度前缀 + UTF-8 字节 */
    public static byte[] utfBody(String payload) {
        byte[] raw = payload == null ? new byte[0] : payload.getBytes(StandardCharsets.UTF_8);
        byte[] length = varint(raw.length);
        byte[] out = new byte[length.length + raw.length];
        System.arraycopy(length, 0, out, 0, length.length);
        System.arraycopy(raw, 0, out, length.length, raw.length);
        return out;
    }

    private static byte[] varint(int value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(5);
        int remaining = value;
        do {
            int current = remaining & 0x7F;
            remaining >>>= 7;
            if (remaining != 0) {
                current |= 0x80;
            }
            out.write(current);
        } while (remaining != 0);
        return out.toByteArray();
    }

    // ==================================================================== 入站解包

    /**
     * 从客户端发来的原始字节里把文本负载抠出来。
     *
     * <p>同一个插件要同时伺候两类客户端，包体形状不一样，所以这里不做「猜格式」，
     * 而是两种都试一遍，谁能解出一个合法的应答就用谁：
     *
     * <ol>
     *   <li>裸 UTF（长度前缀 + 文本）—— Fabric / NeoForge；</li>
     *   <li>VarInt 序号 + 裸 UTF —— Forge。</li>
     * </ol>
     *
     * <p>判据是 {@link #parseResponse} 能否解析成功，而不是「第 1 种解出来非空」：
     * 一个 Forge 包（首字节 0x01）用第 1 种读会得到长度为 1 的垃圾串，非空但没意义，
     * 必须靠解析结果来分辨。
     *
     * @return 解析得出的文本；两种都不像时返回 null（调用方记日志后忽略）
     */
    public static String decodeResponse(byte[] data) {
        if (data == null || data.length == 0) {
            return null;
        }
        String plain = readUtf(data, 0);
        if (plain != null && parseResponse(plain) != null) {
            return plain;
        }
        int[] cursor = {0};
        Integer index = readVarInt(data, cursor);
        if (index != null && index >= 0 && index <= 8) {
            String framed = readUtf(data, cursor[0]);
            if (framed != null && parseResponse(framed) != null) {
                return framed;
            }
        }
        return null;
    }

    /** 读一个 VarInt；越界或超过 5 字节返回 null，并把 {@code cursor[0]} 推到下一个字节 */
    public static Integer readVarInt(byte[] data, int[] cursor) {
        int value = 0;
        int position = 0;
        int start = cursor[0];
        while (true) {
            if (start + position >= data.length || position >= 5) {
                return null;
            }
            byte current = data[start + position];
            value |= (current & 0x7F) << (position * 7);
            position++;
            if ((current & 0x80) == 0) {
                cursor[0] = start + position;
                return value;
            }
        }
    }

    /** 从 {@code offset} 起按「VarInt 长度 + UTF-8」读一个字符串；长度不自洽时返回 null */
    public static String readUtf(byte[] data, int offset) {
        if (offset < 0 || offset >= data.length) {
            return null;
        }
        int[] cursor = {offset};
        Integer length = readVarInt(data, cursor);
        if (length == null || length < 0) {
            return null;
        }
        int start = cursor[0];
        if (start + length > data.length) {
            return null;
        }
        return new String(data, start, length, StandardCharsets.UTF_8);
    }
}
