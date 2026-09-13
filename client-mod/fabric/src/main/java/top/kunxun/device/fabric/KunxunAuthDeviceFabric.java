package top.kunxun.device.fabric;

import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.fabric.api.client.networking.v1.ClientConfigurationNetworking;
import net.fabricmc.fabric.api.networking.v1.PayloadTypeRegistry;
import net.minecraft.client.Minecraft;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import top.kunxun.device.DeviceIdentity;
import top.kunxun.device.DeviceProtocol;

import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Fabric 客户端入口。
 *
 * <p>只干两件事：注册两个包类型、挂上挑战的接收器、然后什么都不做。
 * 模组完全被动——它不会主动向服务器要挑战，也不会因为长期收不到挑战而报错。
 * 这样服务器插件可以按自己的节奏（配置阶段或进世界之后）发挑战，客户端都能配合。
 *
 * <p><b>通道兼容的两条腿。</b> 服务端（Paper）用的是老 {@code Bukkit.getMessenger().sendPluginMessage}，
 * 走的是 1.20.5 之前那条 {@code ClientboundCustomPayloadPacket} 路径；
 * Forge 端有 ChannelBuilder 帮它做兼容，Fabric 没有。这两条腿都装上才能稳：
 * <ol>
 *   <li>{@link PayloadTypeRegistry} 注册新 CustomPayload（配置阶段）</li>
 *   <li>{@link ClientConfigurationNetworking#registerGlobalReceiver} 注册新 CustomPayload 的接收器</li>
 * </ol>
 * 第二条腿对 Fabric 原生连接是够的；对 Paper 这种「服务端 + 老 pluginMessage 通道」，得再加第三条腿：
 * <ol start="3">
 *   <li>{@link ClientboundCustomPayloadPacketMixin}（在 {@code client-mod-common/fabric/mixin} 里）</li>
 * </ol>
 * mixin 的作用是改写 {@code ClientboundCustomPayloadPacket} 的
 * {@code FallbackProvider}，让 Fabric 把未注册的 channel 识别成 CustomPayload 类型并触发上面的接收器。
 * 这是 JoshieGemFinder 在 FabricMC/fabric 仓库里给的 workaround（commit 详情见 mixin 文件头注释）。
 *
 * <p>日志走 SLF4J（Fabric Loader 自带 log4j2 后端）。
 * 和 Forge / NeoForge 不同，Fabric 的 JUL 在默认配置下会被打回 silent，
 * LOGGER.warning / LOGGER.info 全都看不到；这里改用 {@code LoggerFactory}，输出走 log4j2，INFO 一行不漏。
 */
public final class KunxunAuthDeviceFabric implements ClientModInitializer {

    private static final Logger LOGGER = LoggerFactory.getLogger("KunxunAuth-Device");

    /**
     * 每个账号一份设备身份，缓存起来避免每次挑战都重算指纹（读硬件要起子进程）。
     *
     * <p>键是账号名的小写形式。按账号分开存是刻意的：同一台电脑上一个正版号加一个
     * 离线小号，各自持有一把密钥、各自绑一次 —— 1.0.0 那种「一台机器共用一把」的写法
     * 会让第二个账号在服务端撞上公钥唯一约束，永远绑不上设备。
     */
    private static final Map<String, DeviceIdentity> IDENTITIES = new ConcurrentHashMap<>();

    @Override
    public void onInitializeClient() {
        LOGGER.info("[KunxunAuth-Device] 客户端模组初始化 · 协议版本={}", DeviceProtocol.PROTOCOL_VERSION);

        // 注册方向要和实际收发方向对应：
        //   clientbound = 客户端"收"，serverbound = 客户端"发"。
        // 注册错方向不会编译报错，但会在运行时收到 "Unknown payload" 然后把连接断开，
        // 是最容易踩的坑之一。
        PayloadTypeRegistry.clientboundConfiguration().register(DeviceChallengePayload.TYPE, DeviceChallengePayload.CODEC);
        PayloadTypeRegistry.serverboundConfiguration().register(DeviceResponsePayload.TYPE, DeviceResponsePayload.CODEC);

        ClientConfigurationNetworking.registerGlobalReceiver(DeviceChallengePayload.TYPE, (payload, context) -> {
            // 这里是唯一一处「协议异常」的出口，整个方法不允许往外抛：
            // 任何异常都会被 Fabric 的网络层转成断连，而设备绑定只是「免密」的加速通道，
            // 不该因为一个畸形包就把玩家踢下线。
            LOGGER.info("[KunxunAuth-Device] 收到服务端挑战包（kunxunauth:challenge）");
            try {
                handleChallenge(payload);
            } catch (Throwable t) {
                LOGGER.warn("[KunxunAuth-Device] 设备挑战处理失败，已忽略该包（不影响正常登录）", t);
            }
        });
    }

    /** 解析挑战 → 签名 → 回发应答；失败由调用方兜底 */
    static void handleChallenge(DeviceChallengePayload payload) {
        DeviceProtocol.Challenge challenge = DeviceProtocol.parseChallenge(payload.text());
        LOGGER.info("[KunxunAuth-Device] 收到服务端挑战 · nonce前8={} player={}",
                challenge.nonce().substring(0, Math.min(8, challenge.nonce().length())),
                challenge.playerName());
        // 用挑战里的玩家名定位密钥：服务端认的是这条连接上的玩家名，
        // 客户端也按它取密钥，两边的「账号」才是同一个
        DeviceIdentity device = identity(challenge.playerName());
        String response = DeviceProtocol.encodeResponse(
                device.publicKeyBase64(),
                device.sign(challenge),
                device.deviceName(),
                device.fingerprint());
        LOGGER.info("[KunxunAuth-Device] 应答已构造 · 公钥前缀={} 设备名={} 指纹={}",
                device.publicKeyBase64().substring(0, Math.min(8, device.publicKeyBase64().length())),
                device.deviceName(), device.fingerprint());

        // 刻意不查 ClientConfigurationNetworking.canSend()：
        // 它检查的是「服务端声明过它能收这条通道」，而那本名单来自 Fabric 自家
        // 的 RegistrationPayload（Fabric↔Fabric 服务器握手用的帧格式）；
        // Paper 走的是原版 minecraft:register（UTF-16LE 文本），Fabric 不把它
        // 计入 sendableChannels，canSend 于是永远 false —— 守卫会把应答整个吞掉。
        // 而发送本身不需要任何声明：ServerboundCustomPayloadPacket 直接写线，
        // 服务端的入站名单（Bukkit Messenger incoming）由插件自己登记。
        try {
            ClientConfigurationNetworking.send(new DeviceResponsePayload(response));
            LOGGER.info("[KunxunAuth-Device] 应答已发出（kunxunauth:response）");
        } catch (Throwable t) {
            LOGGER.warn("[KunxunAuth-Device] 应答发送失败（不影响登录，会回落密码）", t);
        }
    }

    /**
     * 取（必要时生成）某个账号在这台机器上的设备身份。
     *
     * <p>懒加载：只有真的收到挑战才会去读/生成密钥。放在 {@code onInitializeClient}
     * 里预先加载的话，「玩家只是开了个单人游戏」也会在磁盘上凭空多出一个密钥文件。
     */
    private static DeviceIdentity identity(String account) {
        String key = account == null ? "" : account.toLowerCase(Locale.ROOT);
        return IDENTITIES.computeIfAbsent(key, ignored -> DeviceIdentity.load(
                Minecraft.getInstance().gameDirectory.toPath(), account));
    }
}