package top.kunxun.device;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 设备私钥的落地存储。
 *
 * <p>用一个 {@code .properties} 文件而不是 JSON：{@link Properties} 是 JDK 自带的，
 * 自带转义，模组因此不需要拖进 Gson 之类的依赖——这是「Java 只做一件事」的代价最小的写法。
 *
 * <p>⚠️ 这个文件就是凭据本身。谁拿到它，谁就能冒充这台设备免密登录，
 * 所以它是 bearer token，而不是「缓存」。写入时尽量收紧权限，
 * 并在日志里明确提示玩家不要外传。
 */
public final class DeviceKeyStore {

    /** 私钥（PKCS#8 DER 的 Base64url） */
    private static final String KEY_PRIVATE = "privateKey";
    /** 公钥（X.509 DER 的 Base64url） */
    private static final String KEY_PUBLIC = "publicKey";
    /** 设备名，给玩家在「已绑定设备」列表里认自己用的是哪台机器 */
    private static final String KEY_DEVICE_NAME = "deviceName";
    private static final String KEY_VERSION = "version";

    private static final String FILE_VERSION = "1";
    private static final String HEADER = "KunxunAuth 设备密钥 —— 这是账号凭据，请勿分享或上传";

    private static final Logger LOGGER = Logger.getLogger("KunxunAuth-Device");

    private DeviceKeyStore() {
    }

    /** 从磁盘读出的原始材料 */
    public record StoredKeys(String privateKeyBase64, String publicKeyBase64, String deviceName) {
    }

    public static boolean exists(Path file) {
        return file != null && Files.isRegularFile(file);
    }

    public static StoredKeys read(Path file) throws IOException {
        Properties properties = new Properties();
        try (InputStream in = Files.newInputStream(file, StandardOpenOption.READ)) {
            properties.load(in);
        }
        String priv = trim(properties.getProperty(KEY_PRIVATE));
        String pub = trim(properties.getProperty(KEY_PUBLIC));
        String name = trim(properties.getProperty(KEY_DEVICE_NAME));
        if (priv.isEmpty() || pub.isEmpty()) {
            throw new IOException("设备密钥文件缺少 privateKey / publicKey");
        }
        return new StoredKeys(priv, pub, name.isEmpty() ? "未命名设备" : name);
    }

    public static void write(Path file, String privateKeyBase64, String publicKeyBase64, String deviceName)
            throws IOException {
        Path parent = file.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Properties properties = new Properties();
        properties.setProperty(KEY_VERSION, FILE_VERSION);
        properties.setProperty(KEY_PRIVATE, privateKeyBase64);
        properties.setProperty(KEY_PUBLIC, publicKeyBase64);
        properties.setProperty(KEY_DEVICE_NAME, deviceName);

        try (OutputStream out = Files.newOutputStream(file, StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
            properties.store(out, HEADER);
        }
        restrictPermissions(file);
    }

    /**
     * 尽量把文件权限收到「只有本人可读写」。
     *
     * <p>Linux / macOS 上直接生效；Windows 上 POSIX 视图不可用会抛
     * {@link UnsupportedOperationException}，此时只能靠用户目录本身的权限，
     * 所以降级为记一条警告，不阻断启动。
     */
    private static void restrictPermissions(Path file) {
        Set<PosixFilePermission> ownerOnly =
                EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
        try {
            Files.setPosixFilePermissions(file, ownerOnly);
        } catch (UnsupportedOperationException | IOException e) {
            LOGGER.log(Level.FINE, "当前文件系统不支持 POSIX 权限，设备密钥依赖用户目录权限保护", e);
        }
    }

    /** Base64 的等号填充在不同实现里可能带也可能不带，统一去掉再比较 */
    public static String normalizeBase64(String value) {
        String trimmed = trim(value);
        int end = trimmed.length();
        while (end > 0 && trimmed.charAt(end - 1) == '=') {
            end--;
        }
        return trimmed.substring(0, end);
    }

    /** 断言两串 Base64 表示同一段字节（用于校验文件里的公私钥是否配套、自检用） */
    public static boolean sameKeyMaterial(String a, String b) {
        return java.util.Arrays.equals(decode(a), decode(b));
    }

    /** Base64url 解码；补齐被去掉的等号填充 */
    public static byte[] decode(String base64Url) {
        return Base64.getUrlDecoder().decode(pad(normalizeBase64(base64Url)));
    }

    /** Base64url 解码器要求长度是 4 的倍数，补回被去掉的等号 */
    public static String pad(String base64Url) {
        int remainder = base64Url.length() % 4;
        if (remainder == 0) {
            return base64Url;
        }
        return base64Url + "=".repeat(4 - remainder);
    }

    private static String trim(String value) {
        return value == null ? "" : value.trim();
    }
}
