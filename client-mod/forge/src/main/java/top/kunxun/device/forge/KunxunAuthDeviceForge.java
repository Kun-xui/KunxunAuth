package top.kunxun.device.forge;

import net.minecraft.client.Minecraft;
import net.minecraft.resources.Identifier;
import net.minecraftforge.event.network.CustomPayloadEvent;
import net.minecraftforge.fml.common.Mod;
import net.minecraftforge.network.ChannelBuilder;
import net.minecraftforge.network.SimpleChannel;
import top.kunxun.device.DeviceIdentity;
import top.kunxun.device.DeviceProtocol;

import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Forge 客户端入口。
 *
 * <p>通道在类初始化时就建好并注册，这是 Forge 的既定用法：
 * {@code ChannelBuilder} 在 {@code channel(...)} 内部会创建 {@code NetworkInstance}
 * 并向 {@code NetworkRegistry} 登记，登记必须发生在网络握手之前。
 *
 * <p>{@code optional()} 不可省：加了它，连到没装本模组的服务器（包括原版/Paper 服务端）
 * 才不会被 Forge 判定为「通道缺失」而拒绝连接。装了这个模组的唯一目的是少输一次密码，
 * 它不该成为「进不了服务器」的理由。
 */
@Mod(KunxunAuthDeviceForge.MOD_ID)
public final class KunxunAuthDeviceForge {

    public static final String MOD_ID = "kunxunauth_device";

    private static final Logger LOGGER = Logger.getLogger("KunxunAuth-Device");

    /** 私钥文件按账号分开存（游戏目录下的 kunxun-device/），见 DeviceKeyStore#fileFor */
    public static final SimpleChannel CHANNEL = ChannelBuilder
            .named(Identifier.fromNamespaceAndPath(DeviceProtocol.NAMESPACE, DeviceProtocol.PATH))
            .networkProtocolVersion(DeviceProtocol.CHANNEL_NETWORK_VERSION)
            .optional()
            .simpleChannel();

    /**
     * 每个账号一份设备身份，缓存起来避免每次挑战都重算硬件指纹。
     *
     * <p>键是账号名的小写形式。1.0.0 是全机共用一把密钥，导致同一台电脑上的第二个账号
     * 在服务端撞公钥唯一约束、永远绑不上设备；按账号分开之后这个问题不存在。
     */
    private static final Map<String, DeviceIdentity> IDENTITIES = new ConcurrentHashMap<>();

    static {
        CHANNEL.configuration(protocol -> protocol
                // clientbound = 客户端"收"：挑战。用 addMain 让它回到主线程执行，
                // 因为处理里要读游戏目录、要通过 Channel 发回包，这两件事都不适合在网络线程做。
                .clientbound(flow -> flow.addMain(
                        DeviceChallengePayload.class,
                        DeviceChallengePayload.CODEC,
                        KunxunAuthDeviceForge::onChallenge))
                // serverbound = 客户端"发"：应答。纯客户端模组不会收到 serverbound 包，
                // 这里注册只是为了拿到「可以发」的资格，处理器写成空实现即可。
                .serverbound(flow -> flow.add(
                        DeviceResponsePayload.class,
                        DeviceResponsePayload.CODEC,
                        (payload, context) -> {
                        })));
    }

    public KunxunAuthDeviceForge() {
    }

    /**
     * 挑战处理链：解析 → 签名 → 回发。
     *
     * <p>这里是协议异常的唯一出口，任何异常都在此吞掉：设备凭据只是「免密」的加速通道，
     * 畸形包 / 版本不符 / 签名失败都应该退化成「这台设备没提供凭据」，
     * 让玩家走密码登录，而不是变成一次断连。
     */
    private static void onChallenge(DeviceChallengePayload payload, CustomPayloadEvent.Context context) {
        try {
            DeviceProtocol.Challenge challenge = DeviceProtocol.parseChallenge(payload.text());
            // 用挑战里的玩家名定位密钥：服务端认的是这条连接上的玩家名，
            // 客户端也按它取密钥，两边的「账号」才是同一个
            DeviceIdentity device = identity(challenge.playerName());
            String response = DeviceProtocol.encodeResponse(
                    device.publicKeyBase64(),
                    device.sign(challenge),
                    device.deviceName(),
                    device.fingerprint());

            CHANNEL.send(new DeviceResponsePayload(response), context.getConnection());
            LOGGER.fine("[KunxunAuth] 已向服务器发送设备应答");
        } catch (Throwable t) {
            LOGGER.log(Level.WARNING, "[KunxunAuth] 设备挑战处理失败，已忽略该包（不影响正常登录）", t);
        }
    }

    /** 取（必要时生成）某个账号在这台机器上的设备身份；懒加载，只处理挑战时才会碰磁盘 */
    private static DeviceIdentity identity(String account) {
        String key = account == null ? "" : account.toLowerCase(Locale.ROOT);
        return IDENTITIES.computeIfAbsent(key, ignored -> DeviceIdentity.load(
                Minecraft.getInstance().gameDirectory.toPath(), account));
    }
}
