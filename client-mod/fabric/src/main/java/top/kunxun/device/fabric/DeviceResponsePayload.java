package top.kunxun.device.fabric;

import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.Identifier;
import top.kunxun.device.DeviceProtocol;

/**
 * 客户端 → 服务端的应答包。
 *
 * <p>内容形如 {@code 1|publicKey|signature|deviceName}。
 * 这一侧永远只由客户端发出去，所以注册在 {@code serverboundConfiguration()} 上。
 *
 * @param text 线格式负载
 */
public record DeviceResponsePayload(String text) implements CustomPacketPayload {

    /** 包标识 {@code kunxunauth:response} */
    public static final CustomPacketPayload.Type<DeviceResponsePayload> TYPE =
            new CustomPacketPayload.Type<>(
                    Identifier.fromNamespaceAndPath(DeviceProtocol.NAMESPACE, DeviceProtocol.ID_RESPONSE));

    public static final StreamCodec<FriendlyByteBuf, DeviceResponsePayload> CODEC =
            CustomPacketPayload.codec(
                    (payload, buf) -> buf.writeUtf(payload.text()),
                    buf -> new DeviceResponsePayload(buf.readUtf()));

    @Override
    public CustomPacketPayload.Type<? extends CustomPacketPayload> type() {
        return TYPE;
    }
}
