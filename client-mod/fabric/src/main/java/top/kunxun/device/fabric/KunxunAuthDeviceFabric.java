package top.kunxun.device.fabric;

import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.fabric.api.client.networking.v1.ClientConfigurationNetworking;
import net.fabricmc.fabric.api.networking.v1.PayloadTypeRegistry;
import net.minecraft.client.Minecraft;
import top.kunxun.device.DeviceIdentity;
import top.kunxun.device.DeviceProtocol;

import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Fabric 客户端入口。
 *
 * <p>只干三件事：注册两个包类型、挂上挑战的接收器、然后什么都不做。
 * 模组完全被动——它不会主动向服务器要挑战，也不会因为长期收不到挑战而报错。
 * 这样服务器插件可以按自己的节奏（配置阶段或进世界之后）发挑战，客户端都能配合。
 */
public final class KunxunAuthDeviceFabric implements ClientModInitializer {

    private static final Logger LOGGER = Logger.getLogger("KunxunAuth-Device");

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
            try {
                handleChallenge(payload);
            } catch (Throwable t) {
                LOGGER.log(Level.WARNING, "[KunxunAuth] 设备挑战处理失败，已忽略该包（不影响正常登录）", t);
            }
        });
    }

    /** 解析挑战 → 签名 → 回发应答；失败由调用方兜底 */
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

        if (ClientConfigurationNetworking.canSend(DeviceResponsePayload.TYPE)) {
            ClientConfigurationNetworking.send(new DeviceResponsePayload(response));
            LOGGER.fine("[KunxunAuth] 已向服务器发送设备应答");
        } else {
            // 服务端没声明愿意收这个包（例如老版本插件），那就安静地不发。
            LOGGER.fine("[KunxunAuth] 服务端未注册 kunxunauth:response，跳过设备应答");
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
