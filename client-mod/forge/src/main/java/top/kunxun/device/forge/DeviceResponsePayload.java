package top.kunxun.device.forge;

import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;

/**
 * 客户端 → 服务端：设备应答。
 *
 * <p>即使是纯客户端模组也要把 serverbound 方向注册上：
 * Forge 的 {@code SimpleChannel} 在发送前会校验「这个包有没有注册、方向对不对」，
 * 没注册就会直接抛异常，而不是把包发出去。
 */
public record DeviceResponsePayload(String text) {

    public static final StreamCodec<FriendlyByteBuf, DeviceResponsePayload> CODEC =
            StreamCodec.ofMember(
                    (payload, buf) -> buf.writeUtf(payload.text()),
                    buf -> new DeviceResponsePayload(buf.readUtf()));
}
