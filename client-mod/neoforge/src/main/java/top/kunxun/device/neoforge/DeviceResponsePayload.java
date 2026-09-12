package top.kunxun.device.neoforge;

import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.Identifier;
import top.kunxun.device.DeviceProtocol;

/**
 * 客户端 → 服务端：设备应答（{@code kunxunauth:response}）。
 *
 * <p>即使本模组是「纯客户端」的，也必须把它注册成 serverbound 的已知类型：
 * 注册不等于「服务端装了这个模组」，只是让本地连接知道
 * 「这个包该怎么编码」——否则 {@code ClientPacketDistributor.sendToServer}
 * 会因为找不到 codec 而失败。
 */
public record DeviceResponsePayload(String text) implements CustomPacketPayload {

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
