package top.kunxun.device;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 这台设备上、这个账号的设备身份：一对 Ed25519 密钥 + 一个给人看的名字 + 本机指纹。
 *
 * <p>整个模组只做一件事——拿本地私钥对服务器给的随机挑战签名。
 * 服务端用对应的公钥验签，验过就认为「这就是上次绑定过的那台机器」，可以直接放行。
 *
 * <p>用 Ed25519 而不是 RSA/ECDSA 的原因：签名固定 64 字节、没有随机数陷阱
 * （ECDSA 重用 k 会直接泄露私钥）、并且从 Java 15 起由 JDK 内置，
 * 模组不需要引入任何加密库。
 *
 * <p><b>密钥是按账号分开存的</b>（见 {@link DeviceKeyStore#fileFor}）：同一台电脑上
 * 一个正版号加一个离线小号，各自有一把密钥、各自绑一次，互不打架。
 * 1.0.0 是「一台机器一把、所有账号共用」，第二个账号因此永远绑不上设备。
 *
 * <p>私钥永远不出本机，而且落盘时用本机硬件指纹派生出的密钥加密过；
 * 上报给服务器的只有公钥和指纹摘要。
 */
public final class DeviceIdentity {

    private static final Logger LOGGER = Logger.getLogger("KunxunAuth-Device");
    private static final String ALGORITHM = "Ed25519";
    /**
     * KeyFactory / KeyPairGenerator 的服务名。
     *
     * <p>这里必须是 {@code Ed25519} 而不是 {@code EdEC}：{@code EdEC} 是
     * SunEC 内部实现类的名字，并没有注册成 KeyFactory 的公开算法名，
     * 用它会直接抛 {@code NoSuchAlgorithmException}。
     */
    private static final String KEY_ALGORITHM = "Ed25519";

    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final String deviceName;
    private final String fingerprint;

    private DeviceIdentity(PrivateKey privateKey, PublicKey publicKey, String deviceName, String fingerprint) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.deviceName = deviceName;
        this.fingerprint = fingerprint;
    }

    // ------------------------------------------------------------------ 加载

    /** 用当前机器的指纹加载 / 生成这个账号的设备密钥 */
    public static DeviceIdentity load(Path gameDirectory, String account) {
        return load(gameDirectory, account, DeviceFingerprint.current());
    }

    /**
     * 读取这个账号的设备密钥；文件不存在、读不出来或者解不开时自动生成一把新的。
     *
     * <p>「解不开就重建」是有意为之，而且是这套设计的核心：
     *
     * <ul>
     *   <li>把密钥文件复制到另一台机器 → 新机器指纹不同 → 解不开 → 生成新密钥
     *       → 服务端认不出这把公钥 → 玩家用密码登录一次并重新绑定。
     *       这正是「密钥跟设备绑定」要的效果：复制文件拿不到任何东西。</li>
     *   <li>换主板 / 换系统盘 / 重装系统导致指纹变化 → 同上，重新绑定一次即可。</li>
     * </ul>
     *
     * <p>反过来，无论哪种情况都<b>不会</b>把玩家挡在门外：设备免密只是加速通道，
     * 拿不到私钥就退回密码登录。
     */
    public static DeviceIdentity load(Path gameDirectory, String account, DeviceFingerprint.Result fingerprint) {
        // 1.0.0 的全机共用密钥先归档掉，避免和按账号分文件的新布局混在一起
        DeviceKeyStore.archiveLegacyIfPresent(gameDirectory);

        Path keyFile = DeviceKeyStore.fileFor(gameDirectory, account);
        String machine = fingerprint == null ? "" : fingerprint.summary();
        if (DeviceKeyStore.exists(keyFile)) {
            try {
                DeviceKeyStore.StoredKeys stored = DeviceKeyStore.read(keyFile, account, machine);
                PrivateKey priv = decodePrivateKey(stored.privateKeyBase64());
                PublicKey pub = decodePublicKey(stored.publicKeyBase64());
                if (matches(priv, pub)) {
                    if (!stored.encrypted()) {
                        // 明文格式（1.0.0 的写法）：顺手改成加密格式，不留一份可复制的凭据在磁盘上
                        LOGGER.info("[KunxunAuth] 检测到未加密的设备密钥，正在用本机硬件指纹重新加密");
                        DeviceKeyStore.write(keyFile, account, stored.privateKeyBase64(),
                                stored.publicKeyBase64(), stored.deviceName(), machine);
                    }
                    return new DeviceIdentity(priv, pub, stored.deviceName(), machine);
                }
                LOGGER.warning("[KunxunAuth] 设备密钥文件里的公私钥不配套，将重新生成");
            } catch (IOException | GeneralSecurityException e) {
                LOGGER.warning("[KunxunAuth] 无法使用现有设备密钥（" + e.getMessage()
                        + "），将为账号 " + account + " 重新生成一把；免密需要重新绑定一次");
            }
        }
        return create(keyFile, account, machine);
    }

    private static DeviceIdentity create(Path keyFile, String account, String machine) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
            KeyPair pair = generator.generateKeyPair();
            String name = defaultDeviceName();
            DeviceKeyStore.write(keyFile, account,
                    DeviceProtocol.base64(pair.getPrivate().getEncoded()),
                    DeviceProtocol.base64(pair.getPublic().getEncoded()),
                    name, machine);
            LOGGER.info("[KunxunAuth] 已为本机的账号 " + account + " 生成新的设备密钥："
                    + keyFile.toAbsolutePath());
            return new DeviceIdentity(pair.getPrivate(), pair.getPublic(), name, machine);
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException("无法生成设备密钥", e);
        }
    }

    // ------------------------------------------------------------------ 使用

    /** 公钥（X.509 DER 的 Base64url），上报给服务器的那一半 */
    public String publicKeyBase64() {
        return DeviceProtocol.base64(publicKey.getEncoded());
    }

    public String deviceName() {
        return deviceName;
    }

    /** 本机硬件指纹摘要，随应答一起上报（服务端据此判断「还是不是同一台机器」） */
    public String fingerprint() {
        return fingerprint;
    }

    /** 对挑战原文签名，返回 Base64url 编码的 64 字节签名 */
    public String sign(DeviceProtocol.Challenge challenge) {
        return signBytes(challenge.signingBytes());
    }

    public String signBytes(byte[] message) {
        try {
            Signature signer = Signature.getInstance(ALGORITHM);
            signer.initSign(privateKey);
            signer.update(message);
            return DeviceProtocol.base64(signer.sign());
        } catch (GeneralSecurityException e) {
            // 签名失败不该把玩家踢出游戏：上层会把它当成「本次没提供设备凭据」，退回密码登录
            throw new IllegalStateException("设备签名失败", e);
        }
    }

    // ------------------------------------------------------------------ 内部

    private static PrivateKey decodePrivateKey(String base64) throws GeneralSecurityException {
        byte[] der = DeviceKeyStore.decode(base64);
        return KeyFactory.getInstance(KEY_ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    private static PublicKey decodePublicKey(String base64) throws GeneralSecurityException {
        byte[] der = DeviceKeyStore.decode(base64);
        return KeyFactory.getInstance(KEY_ALGORITHM).generatePublic(new X509EncodedKeySpec(der));
    }

    /**
     * 校验私钥和公钥是不是同一对。
     *
     * <p>做法是签一段固定内容再用公钥验——比去解析 DER 里的公钥点位可靠得多，
     * 而且对 Ed25519 这种没有「从私钥导出公钥」公开 API 的算法来说也够用。
     */
    private static boolean matches(PrivateKey priv, PublicKey pub) {
        try {
            byte[] probe = "kunxun-device-selfcheck".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            Signature signer = Signature.getInstance(ALGORITHM);
            signer.initSign(priv);
            signer.update(probe);
            byte[] signature = signer.sign();

            Signature verifier = Signature.getInstance(ALGORITHM);
            verifier.initVerify(pub);
            verifier.update(probe);
            return verifier.verify(signature);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    /** 默认设备名：主机名 + 短随机后缀，避免同一个玩家的两台机器重名认不出来 */
    private static String defaultDeviceName() {
        String host;
        try {
            host = InetAddress.getLocalHost().getHostName();
        } catch (Exception e) {
            host = "PC";
        }
        if (host == null || host.isBlank()) {
            host = "PC";
        }
        if (host.length() > 24) {
            host = host.substring(0, 24);
        }
        int suffix = 1000 + new java.security.SecureRandom().nextInt(9000);
        return host + "-" + suffix;
    }
}
