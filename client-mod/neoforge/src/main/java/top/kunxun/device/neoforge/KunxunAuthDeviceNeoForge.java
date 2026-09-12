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

import java.nio.file.Path;
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

    /** 私钥文件名，位于游戏目录；与账号无关，同机多账号共用一把设备密钥 */
    private static final String KEY_FILE_NAME = "kunxun-device.properties";

    /**
     * 网络注册的版本串。它只用于 NeoForge 内部比对双方注册表是否一致，
     * 与线协议里的 {@code PROTOCOL_VERSION} 是两回事，
     * 但由于两者都只在「破坏性变更」时才 +1，这里直接复用同一个数字以免出现两套版本号。
     */
    private static final String NETWORK_VERSION = String.valueOf(DeviceProtocol.PROTOCOL_VERSION);

    /** 懒加载 + volatile：配置阶段的包处理未必发生在渲染主线程上 */
    private static volatile DeviceIdentity identity;

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
        DeviceIdentity device = identity();
        String response = DeviceProtocol.encodeResponse(
                device.publicKeyBase64(),
                device.sign(challenge),
                device.deviceName());

        ClientPacketDistributor.sendToServer(new DeviceResponsePayload(response));
        LOGGER.fine("[KunxunAuth] 已向服务器发送设备应答");
    }

    private static DeviceIdentity identity() {
        DeviceIdentity local = identity;
        if (local != null) {
            return local;
        }
        synchronized (KunxunAuthDeviceNeoForge.class) {
            if (identity == null) {
                Path keyFile = Minecraft.getInstance().gameDirectory.toPath().resolve(KEY_FILE_NAME);
                identity = DeviceIdentity.load(keyFile);
            }
            return identity;
        }
    }
}
