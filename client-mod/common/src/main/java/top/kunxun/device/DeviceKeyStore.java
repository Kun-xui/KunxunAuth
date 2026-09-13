package top.kunxun.device;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 设备私钥的落地存储。
 *
 * <p>用 {@code .properties} 而不是 JSON：{@link Properties} 是 JDK 自带的，
 * 自带转义，模组因此不需要拖进 Gson 之类的依赖。
 *
 * <p><b>两个关键设计。</b>
 *
 * <ol>
 *   <li><b>一台机器、一个账号、一把密钥。</b> 密钥文件按账号分开
 *       （{@code kunxun-device/<账号>-<摘要>.properties}）。1.0.0 是「一台机器共用一把」，
 *       直接后果是同一台电脑上的第二个账号永远绑不上设备：服务端的公钥是全局唯一的，
 *       第二个账号拿同一把公钥去绑定只会撞冲突，于是每次登录都得输密码 ——
 *       这正是 1.1.0 要修的那个现象。</li>
 *   <li><b>私钥落盘时加密，密钥由本机硬件指纹派生。</b> 见
 *       {@link DeviceFingerprint}。把文件复制到别的机器上，AES-GCM 解不开、
 *       私钥拿不到，于是「密钥跟设备绑定」这件事第一次真正成立 ——
 *       1.0.0 里这个文件是一份明文 bearer token，复制走就能用。</li>
 * </ol>
 *
 * <p>仍然要提醒玩家：这个文件是他的凭据。加密挡住的是「换一台机器用」，
 * 挡不住「在同一台机器上以他的身份运行任何程序」。
 */
public final class DeviceKeyStore {

    /** 1.0.0 的密钥文件名：全网一份，放在游戏目录下。升级后归档，不再读写 */
    public static final String LEGACY_FILE_NAME = "kunxun-device.properties";

    /** 归档后的名字，保留内容以便回退排查 */
    private static final String LEGACY_ARCHIVE_NAME = LEGACY_FILE_NAME + ".legacy-bak";

    /** 密钥文件目录（游戏目录下） */
    private static final String DIRECTORY_NAME = "kunxun-device";

    private static final String SUFFIX = ".properties";

    /** 私钥（旧格式：PKCS#8 DER 的 Base64url，明文） */
    private static final String KEY_PRIVATE = "privateKey";
    /** 私钥（新格式：AES-256-GCM 密文，Base64url） */
    private static final String KEY_PRIVATE_ENCRYPTED = "privateKeyEncrypted";
    /** 公钥（X.509 DER 的 Base64url） */
    private static final String KEY_PUBLIC = "publicKey";
    /** 设备名，给玩家在「已绑定设备」列表里认自己用的是哪台机器 */
    private static final String KEY_DEVICE_NAME = "deviceName";
    /** 账号名，便于人工核对这是谁的文件 */
    private static final String KEY_ACCOUNT = "account";
    /** 加密这份文件时所在机器的指纹摘要 */
    private static final String KEY_FINGERPRINT = "fingerprint";
    private static final String KEY_KDF_SALT = "kdfSalt";
    private static final String KEY_KDF_ITERATIONS = "kdfIterations";
    private static final String KEY_VERSION = "version";

    private static final String FILE_VERSION = "2";

    /** 1.0.0 的文件版本号；读到它要按明文私钥处理 */
    private static final String LEGACY_FILE_VERSION = "1";

    /** PBKDF2 迭代次数。硬件指纹本身熵不高，靠迭代次数把暴力枚举的成本抬起来 */
    private static final int KDF_ITERATIONS = 120_000;
    private static final int KDF_KEY_BITS = 256;
    private static final int SALT_BYTES = 16;
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;

    private static final String KDF_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String CIPHER = "AES/GCM/NoPadding";

    private static final String HEADER =
            "KunxunAuth 设备密钥（本机硬件加密）—— 这是账号凭据，请勿分享或上传";

    private static final Logger LOGGER = Logger.getLogger("KunxunAuth-Device");

    private static final SecureRandom RANDOM = new SecureRandom();

    /** 归档按「游戏目录」只做一次；存档换目录 / 多实例共用一个 JVM 时也不会重复搬 */
    private static final Set<Path> LEGACY_CHECKED = ConcurrentHashMap.newKeySet();

    private DeviceKeyStore() {
    }

    /** 从磁盘读出的原始材料 */
    public record StoredKeys(String privateKeyBase64, String publicKeyBase64, String deviceName,
                             boolean encrypted) {
    }

    // ------------------------------------------------------------------ 路径

    /**
     * 某个账号在这台机器上的密钥文件路径。
     *
     * <p>文件名里带账号（清洗过的）+ 账号名的短摘要：前者是给人看的，后者是为了
     * 让 {@code a.b} 和 {@code a_b} 这种会被清洗成同一个名字的账号不会互相覆盖。
     * 这层隔离是「同一台机器上多个账号各自免密」的基础。
     */
    public static Path fileFor(Path gameDirectory, String account) {
        String safe = safeName(account);
        return gameDirectory.resolve(DIRECTORY_NAME).resolve(safe + SUFFIX);
    }

    /** 账号名清洗：只留下文件系统安全的字符，再加 8 位摘要保证唯一 */
    static String safeName(String account) {
        String value = account == null ? "" : account.trim().toLowerCase(Locale.ROOT);
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < value.length() && builder.length() < 24; i++) {
            char c = value.charAt(i);
            builder.append(Character.isLetterOrDigit(c) || c == '_' || c == '-' ? c : '_');
        }
        if (builder.length() == 0) {
            builder.append("player");
        }
        return builder + "-" + shortHash(value);
    }

    public static boolean exists(Path file) {
        return file != null && Files.isRegularFile(file);
    }

    /**
     * 把 1.0.0 的全机共用密钥文件归档掉。
     *
     * <p>为什么不直接沿用旧文件：旧文件里那把私钥已经绑在「先登录的那个账号」名下，
     * 谁也说不准现在启动的是不是那个账号。沿用的话，另一个账号会拿同一把公钥去绑定、
     * 撞上服务端的唯一约束，就又回到「每次都要输密码」。归档掉之后每个账号都用自己的
     * 新密钥，代价是升级后需要各自用密码登录一次重新绑定 —— 这一步无法避免，
     * 而且只做一次。
     *
     * <p>幂等：目标文件已存在就不再动，目录不对（单人存档？）也不报错。
     */
    public static void archiveLegacyIfPresent(Path gameDirectory) {
        if (gameDirectory == null || !LEGACY_CHECKED.add(gameDirectory)) {
            return;
        }
        Path legacy = gameDirectory.resolve(LEGACY_FILE_NAME);
        if (!Files.isRegularFile(legacy)) {
            return;
        }
        Path archived = gameDirectory.resolve(LEGACY_ARCHIVE_NAME);
        if (Files.exists(archived)) {
            return;
        }
        try {
            Files.move(legacy, archived, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException atomicFailed) {
            try {
                Files.move(legacy, archived);
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "[KunxunAuth] 无法归档旧设备密钥 " + legacy, e);
                return;
            }
        }
        LOGGER.info("[KunxunAuth] 已归档 1.0.0 的全机共用密钥为 " + LEGACY_ARCHIVE_NAME
                + "：从 1.1.0 起每个账号各有一把设备密钥。"
                + "首次进服请用密码登录一次，登录后点击「绑定这台设备」即可恢复免密。");
    }

    // ------------------------------------------------------------------ 读

    /**
     * 读取并解密设备密钥。
     *
     * @param account           当前账号名（参与 AES-GCM 的附加认证数据）
     * @param machineFingerprint 本机指纹摘要
     * @throws IOException 文件里两套格式都没有、指纹不属于本机、或者解密失败
     *                     —— 调用方应当据此重新生成一把新密钥并让玩家重新绑定
     */
    public static StoredKeys read(Path file, String account, String machineFingerprint) throws IOException {
        Properties properties = new Properties();
        try (InputStream in = Files.newInputStream(file, StandardOpenOption.READ)) {
            properties.load(in);
        }
        String publicKey = trim(properties.getProperty(KEY_PUBLIC));
        String deviceName = trim(properties.getProperty(KEY_DEVICE_NAME));
        String encrypted = trim(properties.getProperty(KEY_PRIVATE_ENCRYPTED));
        String plain = trim(properties.getProperty(KEY_PRIVATE));

        if (!encrypted.isEmpty()) {
            String storedFingerprint = trim(properties.getProperty(KEY_FINGERPRINT));
            if (!storedFingerprint.isEmpty() && !storedFingerprint.equals(machineFingerprint)) {
                throw new IOException("设备密钥是用另一台机器的硬件指纹加密的（文件 "
                        + storedFingerprint + " / 本机 " + machineFingerprint + "）");
            }
            String salt = trim(properties.getProperty(KEY_KDF_SALT));
            int iterations = parseIterations(properties.getProperty(KEY_KDF_ITERATIONS));
            byte[] key = deriveKey(machineFingerprint, salt, iterations);
            String decrypted = decrypt(key, encrypted, account);
            if (publicKey.isEmpty() || deviceName.isEmpty()) {
                throw new IOException("设备密钥文件字段不完整");
            }
            return new StoredKeys(decrypted, publicKey, deviceName, true);
        }

        if (!plain.isEmpty()) {
            // 1.0.0 的明文格式：读得出来，但调用方会立刻用新格式重写一遍
            if (publicKey.isEmpty()) {
                throw new IOException("设备密钥文件缺少 publicKey");
            }
            return new StoredKeys(plain, publicKey,
                    deviceName.isEmpty() ? "未命名设备" : deviceName, false);
        }
        throw new IOException("设备密钥文件既没有 " + KEY_PRIVATE_ENCRYPTED + " 也没有 " + KEY_PRIVATE);
    }

    // ------------------------------------------------------------------ 写

    /**
     * 用本机指纹派生出的密钥加密私钥后落盘。
     *
     * <p>公钥与设备名是明文 —— 它们本来就要上报给服务器，没有保护的必要，
     * 也方便玩家自己打开文件核对「这台机器是哪一把」。
     */
    public static void write(Path file, String account, String privateKeyBase64, String publicKeyBase64,
                             String deviceName, String machineFingerprint) throws IOException {
        Path parent = file.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        byte[] key = deriveKey(machineFingerprint, Base64.getUrlEncoder().withoutPadding()
                .encodeToString(salt), KDF_ITERATIONS);

        Properties properties = new Properties();
        properties.setProperty(KEY_VERSION, FILE_VERSION);
        properties.setProperty(KEY_ACCOUNT, account == null ? "" : account);
        properties.setProperty(KEY_PUBLIC, publicKeyBase64);
        properties.setProperty(KEY_DEVICE_NAME, deviceName);
        properties.setProperty(KEY_FINGERPRINT, machineFingerprint);
        properties.setProperty(KEY_KDF_SALT, Base64.getUrlEncoder().withoutPadding()
                .encodeToString(salt));
        properties.setProperty(KEY_KDF_ITERATIONS, String.valueOf(KDF_ITERATIONS));
        properties.setProperty(KEY_PRIVATE_ENCRYPTED, encrypt(key, privateKeyBase64, account));

        try (OutputStream out = Files.newOutputStream(file, StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
            properties.store(out, HEADER);
        }
        restrictPermissions(file);
    }

    // ------------------------------------------------------------------ 加密

    /** PBKDF2：指纹 + 盐 → 256 位密钥。指纹取了短摘要，所以盐必须每份文件都不一样 */
    private static byte[] deriveKey(String fingerprint, String saltBase64, int iterations) throws IOException {
        if (saltBase64 == null || saltBase64.isEmpty()) {
            throw new IOException("设备密钥文件缺少 kdfSalt");
        }
        byte[] salt = decode(saltBase64);
        try {
            PBEKeySpec spec = new PBEKeySpec(
                    (fingerprint == null ? "" : fingerprint).toCharArray(), salt, iterations, KDF_KEY_BITS);
            byte[] key = SecretKeyFactory.getInstance(KDF_ALGORITHM).generateSecret(spec).getEncoded();
            spec.clearPassword();
            return key;
        } catch (GeneralSecurityException e) {
            throw new IOException("派生设备密钥失败：" + e.getMessage(), e);
        }
    }

    /** AES-256-GCM 加密；账号名进 AAD，所以把文件挪到别的账号名下会直接解不开 */
    private static String encrypt(byte[] key, String plaintextBase64, String account) throws IOException {
        byte[] nonce = new byte[NONCE_BYTES];
        RANDOM.nextBytes(nonce);
        try {
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(aad(account));
            byte[] sealed = cipher.doFinal(plaintextBase64.getBytes(StandardCharsets.UTF_8));

            byte[] out = new byte[nonce.length + sealed.length];
            System.arraycopy(nonce, 0, out, 0, nonce.length);
            System.arraycopy(sealed, 0, out, nonce.length, sealed.length);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(out);
        } catch (GeneralSecurityException e) {
            throw new IOException("加密设备密钥失败：" + e.getMessage(), e);
        }
    }

    /** 解密；认证标签不对（换机器 / 改文件 / 换了账号名）都会在这里抛 IOException */
    private static String decrypt(byte[] key, String payloadBase64, String account) throws IOException {
        byte[] payload = decode(payloadBase64);
        if (payload.length <= NONCE_BYTES) {
            throw new IOException("设备密钥密文长度不合法");
        }
        byte[] nonce = new byte[NONCE_BYTES];
        System.arraycopy(payload, 0, nonce, 0, NONCE_BYTES);
        byte[] sealed = new byte[payload.length - NONCE_BYTES];
        System.arraycopy(payload, NONCE_BYTES, sealed, 0, sealed.length);
        try {
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(aad(account));
            return new String(cipher.doFinal(sealed), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IOException("解密设备密钥失败（本机硬件指纹已变化，或文件被改动）", e);
        }
    }

    private static byte[] aad(String account) {
        return (account == null ? "" : account.trim().toLowerCase(Locale.ROOT))
                .getBytes(StandardCharsets.UTF_8);
    }

    // ------------------------------------------------------------------ 工具

    private static int parseIterations(String raw) {
        try {
            int value = Integer.parseInt(trim(raw));
            // 文件里写着一个极小的迭代数只可能是被改过；退回默认值比听它的更安全
            return value >= 1000 ? value : KDF_ITERATIONS;
        } catch (NumberFormatException e) {
            return KDF_ITERATIONS;
        }
    }

    /**
     * 尽量把文件权限收到「只有本人可读写」。
     *
     * <p>Linux / macOS 上直接生效；Windows 上 POSIX 视图不可用会抛
     * {@link UnsupportedOperationException}，此时只能靠用户目录本身的权限，
     * 所以降级为记一条日志，不阻断启动。
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

    /** 账号名短摘要：让「清洗后同名」的不同账号不会互相覆盖密钥文件 */
    private static String shortHash(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder(8);
            for (int i = 0; i < 4; i++) {
                builder.append(String.format("%02x", digest[i]));
            }
            return builder.toString();
        } catch (NoSuchAlgorithmException e) {
            // JDK 必然带 SHA-256；真没有就用账号名的长度顶着，至少不是随机值
            return String.format("%08x", value.hashCode());
        }
    }

    private static String trim(String value) {
        return value == null ? "" : value.trim();
    }
}
