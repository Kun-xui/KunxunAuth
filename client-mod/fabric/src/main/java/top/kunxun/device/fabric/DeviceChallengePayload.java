package top.kunxun.device.fabric;

import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.Identifier;
import top.kunxun.device.DeviceProtocol;

/**
 * 服务端 → 客户端的挑战包。
 *
 * <p>负载内容就是 {@link DeviceProtocol} 定义的那一行字符串，这里一个字节都不解析——
 * 编解码只负责「把字符串塞进 buf / 从 buf 取出来」。
 * 解析是 {@link DeviceProtocol#parseChallenge(String)} 的事，
 * 这样协议格式要改的时候，动的是 common 里的类，而不是三个加载器各自的封包类。
 *
 * <p>包体用 {@code writeUtf} / {@code readUtf}：Minecraft 的这两个方法自带
 * 长度前缀和 32767 字节上限校验，比手写 {@code writeInt + writeBytes} 安全
 * （对方声称的字符串长度不会变成一次越界读取）。
 *
 * @param text 线格式负载，形如 {@code 1|nonce|serverId|playerName}
 */
public record DeviceChallengePayload(String text) implements CustomPacketPayload {

    /**
     * 包标识 {@code kunxunauth:challenge}。
     *
     * <p>26.2 里 {@code ResourceLocation} 已经改名为 {@link Identifier}，
     * 官方映射下就是这个类名，网上老教程里的 ResourceLocation 在 26.2 编译不过。
     */
    public static final CustomPacketPayload.Type<DeviceChallengePayload> TYPE =
            new CustomPacketPayload.Type<>(
                    Identifier.fromNamespaceAndPath(DeviceProtocol.NAMESPACE, DeviceProtocol.ID_CHALLENGE));

    /**
     * 配置阶段的编解码器参数类型是 {@code FriendlyByteBuf}，
     * <b>不是</b> {@code RegistryFriendlyByteBuf}——后者只在 play 阶段存在，
     * 配置阶段还没有注册表可以携带。
     */
    public static final StreamCodec<FriendlyByteBuf, DeviceChallengePayload> CODEC =
            CustomPacketPayload.codec(
                    (payload, buf) -> buf.writeUtf(payload.text()),
                    buf -> new DeviceChallengePayload(buf.readUtf()));

    @Override
    public CustomPacketPayload.Type<? extends CustomPacketPayload> type() {
        return TYPE;
    }
}
