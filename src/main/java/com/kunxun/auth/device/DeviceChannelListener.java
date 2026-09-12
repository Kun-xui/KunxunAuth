package com.kunxun.auth.device;

import io.papermc.paper.connection.PlayerConnection;
import org.bukkit.entity.Player;
import org.bukkit.plugin.messaging.PluginMessageListener;

import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 收客户端回的设备应答。
 *
 * <p>用 {@link PluginMessageListener} 而不是去拦包：Paper 的
 * {@code ServerCommonPacketListenerImpl.handleCustomPayload} 会把原始字节直接丢给
 * {@code Messenger.dispatchIncomingMessage(PlayerConnection, channel, data)}，
 * 而配置阶段那个 {@code PlayerConnection} 与 {@code AsyncPlayerConnectionConfigureEvent}
 * 里拿到的是同一个实例 —— 也就是说，纯 Bukkit API 就够用，不需要 PacketEvents，
 * 也不会因为 NMS 改动而失效。
 *
 * <p><b>这里绝对不能让异常漏出去。</b> 上游那段分发代码是这么写的：
 * 一旦抛异常就 {@code disconnect("Invalid custom payload payload!")}。
 * 也就是说监听器里一个没接住的 {@code RuntimeException} 等价于「把玩家踢掉」，
 * 而触发它的只是一个别人精心构造的畸形包。所以最外层兜 {@code Throwable}。
 */
public final class DeviceChannelListener implements PluginMessageListener {

    /**
     * 需要登记为「入站」的通道。
     *
     * <p>{@code kunxunauth:response} 是 Fabric / NeoForge 用来回答的通道；
     * {@code kunxunauth:device} 是 Forge 用的那条（Forge 把挑战和应答复用在一起）。
     */
    public static final List<String> CHANNELS = List.of(
            DeviceProtocol.CHANNEL,
            DeviceProtocol.CHANNEL_RESPONSE);

    /**
     * 需要登记为「出站」的通道。
     *
     * <p>这一步不是可有可无的美化，漏了它设备免密<b>一次都跑不起来</b>：
     * Paper 的 {@code StandardMessenger.validatePluginMessage} 在真正写包之前，
     * 先查的是「这个插件有没有登记过这条出站通道」这本插件级台账。
     * 没登记就直接抛 {@code ChannelNotRegisteredException}，包连编都不编。
     * 它查的不是连接级那份名单，反射补的 {@code addChannel} 也顶不上 ——
     * 那是两个方向、两张表。
     *
     * <p>顺带还有第二个作用：登记为出站的通道会进服务端握手时下发的
     * {@code minecraft:register} 名单。客户端（Forge 会打一行
     * {@code Accepting channel list from vanilla}）只有先看见名单，才知道该接这条通道。
     */
    public static final List<String> OUTGOING = List.of(
            DeviceProtocol.CHANNEL,
            DeviceProtocol.CHANNEL_CHALLENGE);

    private final DeviceService devices;
    private final Logger logger;

    public DeviceChannelListener(DeviceService devices, Logger logger) {
        this.devices = devices;
        this.logger = logger;
    }

    /** 配置阶段：Paper 会把连接实例一起给过来，而挑战正是按连接登记的 */
    @Override
    public void onPluginMessageReceived(String channel, PlayerConnection connection, byte[] message) {
        receive(channel, connection, message);
    }

    /**
     * 已经进世界之后收到的包。
     *
     * <p>设备应答整个生命周期都在配置阶段，走到这里说明是超时之后才姗姗来迟的
     * 残包（或者玩家装了模组之后又用别的客户端连过）。此时对应的挑战早已销毁，
     * 收下来也没用，直接丢。
     */
    @Override
    public void onPluginMessageReceived(String channel, Player player, byte[] message) {
        // 配置阶段之外的应答一律忽略
    }

    private void receive(String channel, PlayerConnection connection, byte[] message) {
        if (connection == null || message == null) {
            return;
        }
        try {
            devices.onIncoming(connection, channel, message);
        } catch (Throwable t) {
            // 畸形包只值一条日志，不值一次踢人
            logger.log(Level.WARNING, "[KunxunAuth] 处理设备应答时出错（通道 " + channel + "）", t);
        }
    }
}
