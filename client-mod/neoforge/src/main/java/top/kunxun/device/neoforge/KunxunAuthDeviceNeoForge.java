package top.kunxun.device.neoforge;

import net.minecraft.client.Minecraft;
import net.neoforged.api.distmarker.Dist;
import net.neoforged.bus.api.IEventBus;
import net.neoforged.fml.common.Mod;
import net.neoforged.neoforge.client.network.ClientPacketDistributor;
import net.neoforged.neoforge.client.network.event.RegisterClientPayloadHandlersEvent;
import net.neoforged.neoforge.network.event.RegisterPayloadHandlersEvent;
import net.neoforged.neoforge.network.registration.PayloadRegistrar;
import top.kunxun.device.DeviceIdentity;
import top.kunxun.device.DeviceProtocol;

import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * NeoForge 客户端入口。
 *
 * <p>{@code dist = Dist.CLIENT} 不是可有可无的装饰：没有它，模组里对
 * {@link RegisterClientPayloadHandlersEvent} 这类纯客户端类的引用
 * 会在专用服务端加载时直接抛 {@code NoClassDefFoundError}。
 * 注解法（而不是在方法里写 if 判断）是 NeoForge 提供的官方隔离手段，
 * 因为它作用在类加载之前。
 *
 * <p>网络注册被拆成两个事件：{@link RegisterPayloadHandlersEvent} 是双端都有的
 * 「有哪些包」，{@link RegisterClientPayloadHandlersEvent} 只在客户端触发，
 * 专用于「收到包之后在客户端做什么」。
 */
@Mod(value = KunxunAuthDeviceNeoForge.MOD_ID, dist = Dist.CLIENT)
public final class KunxunAuthDeviceNeoForge {

    public static final String MOD_ID = "kunxunauth_device";

    private static final Logger LOGGER = Logger.getLogger("KunxunAuth-Device");

    /**
     * 网络注册的版本串。它只用于 NeoForge 内部比对双方注册表是否一致，
     * 与线协议里的 {@code PROTOCOL_VERSION} 是<b>两件事</b>：线格式新增一个字段
     * （例如这次的设备指纹）不需要重新协商「有哪些包」，跟着 +1 只会平白多出
     * 一种版本不匹配的报错可能。所以这里固定用 {@code CHANNEL_NETWORK_VERSION}。
     */
    private static final String NETWORK_VERSION = String.valueOf(DeviceProtocol.CHANNEL_NETWORK_VERSION);

    /**
     * 每个账号一份设备身份，缓存起来避免每次挑战都重算硬件指纹。
     *
     * <p>键是账号名的小写形式。1.0.0 是全机共用一把密钥，同一台电脑上的第二个账号
     * 在服务端撞公钥唯一约束、永远绑不上设备；按账号分开之后这个问题不存在。
     */
    private static final Map<String, DeviceIdentity> IDENTITIES = new ConcurrentHashMap<>();

    public KunxunAuthDeviceNeoForge(IEventBus modBus) {
        modBus.addListener(this::onRegisterPayloads);
        modBus.addListener(this::onRegisterClientPayloads);
    }

    /** 双端都要跑的注册：声明两个包的 id 与编解码器 */
    private void onRegisterPayloads(RegisterPayloadHandlersEvent event) {
        PayloadRegistrar registrar = event.registrar(NETWORK_VERSION);

        // 配置阶段：收挑战。第三个参数是「客户端收到后干什么」，
        // 这里不直接写业务逻辑，而是转交给客户端专用事件注册，
        // 保证本方法在两端都能安全执行。
        registrar.configurationToClient(DeviceChallengePayload.TYPE, DeviceChallengePayload.CODEC);

        // 配置阶段：发应答。NeoForge 的 configurationToServer 没有「只要 codec」
        // 的两参重载，所以必须给一个处理器。本模组是纯客户端的，
        // 这个处理器永远不会被调用（没人会向客户端发 serverbound 包），
        // 传空实现即可，不能写成 null。
        registrar.configurationToServer(DeviceResponsePayload.TYPE, DeviceResponsePayload.CODEC,
                (payload, context) -> {
                });
    }

    /** 客户端收到挑战后的处理链：解析 → 签名 → 回发 */
    private void onRegisterClientPayloads(RegisterClientPayloadHandlersEvent event) {
        event.register(DeviceChallengePayload.TYPE, (payload, context) -> {
            // 这里是协议异常的唯一出口，绝不允许往上抛：
            // 设备凭据只是「免密」的加速通道，畸形包、版本不符、签名失败
            // 都应该退化成「这台设备没提供凭据」，让玩家走密码登录，
            // 而不是变成一次断连。
            try {
                handleChallenge(payload);
            } catch (Throwable t) {
                LOGGER.log(Level.WARNING, "[KunxunAuth] 设备挑战处理失败，已忽略该包（不影响正常登录）", t);
            }
        });
    }

    private static void handleChallenge(DeviceChallengePayload payload) {
        DeviceProtocol.Challenge challenge = DeviceProtocol.parseChallenge(payload.text());
        // 用挑战里的玩家名定位密钥：服务端认的是这条连接上的玩家名，
        // 客户端也按它取密钥，两边的「账号」才是同一个
        DeviceIdentity device = identity(challenge.playerName());
        String response = DeviceProtocol.encodeResponse(
                device.publicKeyBase64(),
                device.sign(challenge),
                device.deviceName(),
                device.fingerprint());

        ClientPacketDistributor.sendToServer(new DeviceResponsePayload(response));
        LOGGER.fine("[KunxunAuth] 已向服务器发送设备应答");
    }

    /** 取（必要时生成）某个账号在这台机器上的设备身份；懒加载，只处理挑战时才会碰磁盘 */
    private static DeviceIdentity identity(String account) {
        String key = account == null ? "" : account.toLowerCase(Locale.ROOT);
        return IDENTITIES.computeIfAbsent(key, ignored -> DeviceIdentity.load(
                Minecraft.getInstance().gameDirectory.toPath(), account));
    }
}
