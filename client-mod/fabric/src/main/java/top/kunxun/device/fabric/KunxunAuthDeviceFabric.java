package top.kunxun.device.fabric;

import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.fabric.api.client.networking.v1.ClientConfigurationNetworking;
import net.fabricmc.fabric.api.networking.v1.PayloadTypeRegistry;
import net.minecraft.client.Minecraft;
import top.kunxun.device.DeviceIdentity;
import top.kunxun.device.DeviceProtocol;

import java.nio.file.Path;
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

    /** 私钥文件名。放在游戏目录下，和账号无关，所以同一台机器上的所有账号共用一把设备密钥。 */
    private static final String KEY_FILE_NAME = "kunxun-device.properties";

    /**
     * 设备身份是懒加载的：只有真的收到挑战才会去读/生成密钥。
     *
     * <p>如果放在 {@code onInitializeClient} 里预先加载，那么「玩家只是开了个单人游戏」
     * 也会在磁盘上凭空多出一个密钥文件——没有连接到需要它的服务器时，这个文件没有存在意义。
     * volatile + 双重检查是因为配置阶段的包处理未必在主线程上。
     */
    private static volatile DeviceIdentity identity;

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
        DeviceIdentity device = identity();
        String response = DeviceProtocol.encodeResponse(
                device.publicKeyBase64(),
                device.sign(challenge),
                device.deviceName());

        if (ClientConfigurationNetworking.canSend(DeviceResponsePayload.TYPE)) {
            ClientConfigurationNetworking.send(new DeviceResponsePayload(response));
            LOGGER.fine("[KunxunAuth] 已向服务器发送设备应答");
        } else {
            // 服务端没声明愿意收这个包（例如老版本插件），那就安静地不发。
            LOGGER.fine("[KunxunAuth] 服务端未注册 kunxunauth:response，跳过设备应答");
        }
    }

    private static DeviceIdentity identity() {
        DeviceIdentity local = identity;
        if (local != null) {
            return local;
        }
        synchronized (KunxunAuthDeviceFabric.class) {
            if (identity == null) {
                Path keyFile = Minecraft.getInstance().gameDirectory.toPath().resolve(KEY_FILE_NAME);
                identity = DeviceIdentity.load(keyFile);
            }
            return identity;
        }
    }
}
