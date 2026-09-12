package top.kunxun.device.forge;

import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;

/**
 * 服务端 → 客户端：设备挑战。
 *
 * <p>和 Fabric/NeoForge 侧不同，这里没有实现 {@code CustomPacketPayload}：
 * Forge 的 {@code SimpleChannel} 用**注册顺序索引**区分同一个通道下的多个包
 * （见 {@code SimpleChannel.encode}），而不是用 {@code Identifier}。
 * 给这个 record 硬塞一个 Type 只会造成误导——它根本不会被写上线。
 *
 * <p>包体仍然是同一个 UTF-8 字符串，编码方式与另两个加载器逐字节一致；
 * 唯一的差别是 Forge 会在字符串前面多加一个它自己的索引字节，
 * 这也是 Forge 端必须配 Forge 服务端、不能直连 Paper 插件的原因（见 PROTOCOL.md §2.1）。
 */
public record DeviceChallengePayload(String text) {

    /**
     * {@code SimpleChannel} 的配置阶段用的是 {@link FriendlyByteBuf}。
     * play 阶段才是 {@code RegistryFriendlyByteBuf}，两者不能混用。
     */
    public static final StreamCodec<FriendlyByteBuf, DeviceChallengePayload> CODEC =
            StreamCodec.ofMember(
                    (payload, buf) -> buf.writeUtf(payload.text()),
                    buf -> new DeviceChallengePayload(buf.readUtf()));
}
