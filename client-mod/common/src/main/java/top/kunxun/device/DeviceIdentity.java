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
 * 这台设备的身份：一对 Ed25519 密钥 + 一个给人看的名字。
 *
 * <p>整个模组只做一件事——拿本地私钥对服务器给的随机挑战签名。
 * 服务端用对应的公钥验签，验过就认为「这就是上次绑定过的那台机器」，可以直接放行。
 *
 * <p>用 Ed25519 而不是 RSA/ECDSA 的原因：签名固定 64 字节、没有随机数陷阱
 * （ECDSA 重用 k 会直接泄露私钥）、并且从 Java 15 起由 JDK 内置
 * （{@code EdEC}），模组不需要引入任何加密库。
 *
 * <p>私钥永远不出本机；公钥才会上报给服务器。
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

    private DeviceIdentity(PrivateKey privateKey, PublicKey publicKey, String deviceName) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.deviceName = deviceName;
    }

    // ------------------------------------------------------------------ 加载

    /**
     * 读取已有设备密钥；文件不存在或已损坏时自动生成一份新的。
     *
     * <p>「损坏就重建」是有意为之：宁可让玩家重新绑定一次设备，
     * 也不要因为一个读不出来的文件把游戏卡在登录界面。
     */
    public static DeviceIdentity load(Path keyFile) {
        if (DeviceKeyStore.exists(keyFile)) {
            try {
                DeviceKeyStore.StoredKeys stored = DeviceKeyStore.read(keyFile);
                PrivateKey priv = decodePrivateKey(stored.privateKeyBase64());
                PublicKey pub = decodePublicKey(stored.publicKeyBase64());
                if (matches(priv, pub)) {
                    return new DeviceIdentity(priv, pub, stored.deviceName());
                }
                LOGGER.warning("[KunxunAuth] 设备密钥文件里的公私钥不配套，将重新生成");
            } catch (IOException | GeneralSecurityException e) {
                LOGGER.log(Level.WARNING, "[KunxunAuth] 读取设备密钥失败，将重新生成", e);
            }
        }
        return create(keyFile);
    }

    private static DeviceIdentity create(Path keyFile) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
            KeyPair pair = generator.generateKeyPair();
            String name = defaultDeviceName();
            DeviceKeyStore.write(keyFile,
                    DeviceProtocol.base64(pair.getPrivate().getEncoded()),
                    DeviceProtocol.base64(pair.getPublic().getEncoded()),
                    name);
            LOGGER.info("[KunxunAuth] 已在本机生成新的设备密钥：" + keyFile.toAbsolutePath());
            return new DeviceIdentity(pair.getPrivate(), pair.getPublic(), name);
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
