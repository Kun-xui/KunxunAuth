package top.kunxun.device.neoforge;

import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.Identifier;
import top.kunxun.device.DeviceProtocol;

/**
 * 服务端 → 客户端：设备挑战（{@code kunxunauth:challenge}）。
 *
 * <p>NeoForge 与 Fabric 在这一层是一致的：负载的「身份」是
 * {@link Type}（内部就是一个 {@link Identifier}），所以两个方向各用一个 Type 即可，
 * 不需要像老版本那样在包体里塞一个自制的操作码前缀。
 *
 * <p>包体只用 {@code writeUtf}/{@code readUtf} 做一次字符串透传——
 * 协议本身是纯文本（见 PROTOCOL.md §3），客户端不解析、不校验，
 * 这样协议演进（加字段）时不牵动任何网络层的编解码逻辑。
 */
public record DeviceChallengePayload(String text) implements CustomPacketPayload {

    /**
     * 类型 id 必须用 {@link Identifier#fromNamespaceAndPath} 构造：
     * MC 26.2 里 {@code ResourceLocation} 已改名为 {@link Identifier}，
     * 而它的构造函数是私有的，只能通过工厂方法创建。
     */
    public static final CustomPacketPayload.Type<DeviceChallengePayload> TYPE =
            new CustomPacketPayload.Type<>(
                    Identifier.fromNamespaceAndPath(DeviceProtocol.NAMESPACE, DeviceProtocol.ID_CHALLENGE));

    /**
     * 配置阶段（configuration phase）用的是 {@link FriendlyByteBuf}。
     *
     * <p>这一点很容易踩坑：play 阶段的包用的是 {@code RegistryFriendlyByteBuf}，
     * 两者不是同一个类。把 play 阶段的 codec 类型抄到配置阶段会编译不过，
     * 或者更糟——编译过了但运行时编解码错位。
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
