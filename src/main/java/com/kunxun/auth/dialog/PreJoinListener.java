package com.kunxun.auth.dialog;

import com.kunxun.auth.config.AuthConfig;
import com.kunxun.auth.config.Messages;
import com.kunxun.auth.device.DeviceService;
import com.kunxun.auth.session.AuthService;
import com.kunxun.auth.session.ClickPayload;
import com.kunxun.auth.session.DialogCapability;
import com.kunxun.auth.session.LoginSession;
import com.kunxun.auth.session.SessionManager;
import io.papermc.paper.connection.PlayerCommonConnection;
import io.papermc.paper.connection.PlayerConfigurationConnection;
import io.papermc.paper.event.connection.configuration.AsyncPlayerConnectionConfigureEvent;
import io.papermc.paper.event.player.PlayerCustomClickEvent;
import net.kyori.adventure.text.Component;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;

import java.net.InetSocketAddress;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 预进服验证入口。
 *
 * <p>两个事件配合完成「进世界前登录」：
 * <ul>
 *   <li>{@link AsyncPlayerConnectionConfigureEvent} —— 玩家已通过正版验证、还没进世界，
 *       在这个异步事件里阻塞等待玩家答完对话框；</li>
 *   <li>{@link PlayerCustomClickEvent} —— 玩家点了对话框按钮，把内容投递给等待中的会话。</li>
 * </ul>
 */
public final class PreJoinListener implements Listener {

    private final AuthConfig config;
    private final Messages messages;
    private final AuthService authService;
    private final SessionManager sessions;
    private final DialogCapability capability;
    private final DeviceService devices;
    private final Logger logger;

    public PreJoinListener(AuthConfig config, Messages messages, AuthService authService,
                           SessionManager sessions, DialogCapability capability, DeviceService devices,
                           Logger logger) {
        this.config = config;
        this.messages = messages;
        this.authService = authService;
        this.sessions = sessions;
        this.capability = capability;
        this.devices = devices;
        this.logger = logger;
    }

    // ------------------------------------------------------------ 配置阶段

    @EventHandler(priority = EventPriority.LOW)
    public void onConfigure(AsyncPlayerConnectionConfigureEvent event) {
        if (!config.preJoin().enable()) {
            return;
        }
        PlayerConfigurationConnection connection = event.getConnection();
        UUID playerId = connection.getProfile().getId();
        String playerName = connection.getProfile().getName();
        String ip = addressOf(connection);

        // 已经认证过（例如 /reload 后重连、免密会话命中）
        if (sessions.isAuthenticated(playerId)) {
            return;
        }

        // 客户端版本太低、看不到对话框
        if (!capability.isDialogCapable(playerId)) {
            if (config.preJoin().legacyMode() == AuthConfig.LegacyMode.KICK) {
                connection.disconnect(messages.get("kick.legacy-dialog-unsupported"));
            }
            // chat 模式：放行进世界，交给聊天命令 + 冻结保护
            return;
        }

        if (sessions.exceedsConnectionLimit(ip, config.misc().maxConnectionsPerIp())) {
            connection.disconnect(messages.get("kick.server-full"));
            return;
        }

        LoginSession session = sessions.open(connection, playerId, playerName, ip);
        try {
            AuthService.Decision decision = authService.runPreJoinDialogFlow(connection, session);
            if (!decision.allowed()) {
                session.markCancelled();
                disconnect(connection, decision.kickMessage());
            } else if (connection.isConnected()) {
                // 验证通过：关掉对话框让客户端继续进世界
                closeDialog(connection);
            }
        } catch (Throwable t) {
            logger.log(Level.SEVERE, "[KunxunAuth] 预进服验证流程异常: " + playerName, t);
            disconnect(connection, messages.get("dialog.error-internal"));
        } finally {
            // 顺序要紧：先撤掉这条连接上的设备挑战，再关掉会话。
            //
            // 挑战登记处是按「连接实例」索引的，不撤的话那个对象会一直被内存里的
            // IdentityHashMap 强引用着，直到 5 分钟一次的兜底清理才被扫掉；
            // 更糟的是如果挑战还没过期，补发任务会继续往这条已经没人要的连接上发包。
            if (devices != null) {
                devices.onDisconnect(connection);
            }
            sessions.close(connection);
        }
    }

    /**
     * 给玩家断开提示并立即断开连接。
     *
     * <p>顺序是刻意排的：<b>先关对话框，再发断连包</b>。
     * 对话框用的是 {@code afterAction = WAIT_FOR_RESPONSE}，也就是玩家点完按钮之后，
     * 客户端界面停在「等服务器回话」的状态；先把对话框关掉，客户端才立刻从那个状态里
     * 出来，接着收到的断连提示就能当场显示。反过来先发断连包的话，玩家会先看到
     * 界面卡一下、再看到提示 —— 也就是「点了退出要等服务器」的那个手感。
     *
     * <p>设备挑战与补发任务已经在 {@code AuthService.deny} 里停过了，这里不重复。
     */
    private void disconnect(PlayerConfigurationConnection connection, Component message) {
        if (!connection.isConnected()) {
            return;
        }
        closeDialog(connection);
        if (message != null) {
            connection.disconnect(message);
        }
    }

    private void closeDialog(PlayerConfigurationConnection connection) {
        try {
            connection.getAudience().closeDialog();
        } catch (RuntimeException e) {
            // 关不掉就算了：调用方紧接着要么断开、要么放行进世界，不会因此卡住玩家
            logger.log(Level.FINE, "[KunxunAuth] 关闭对话框失败: " + e.getMessage(), e);
        }
    }

    // ------------------------------------------------------------ 按钮回调

    @EventHandler(priority = EventPriority.LOW, ignoreCancelled = true)
    public void onCustomClick(PlayerCustomClickEvent event) {
        AuthAction action = AuthAction.from(event.getIdentifier());
        if (action == null) {
            // 不是本插件的对话框
            return;
        }
        PlayerCommonConnection connection = event.getCommonConnection();
        LoginSession session = sessions.session(connection).orElse(null);
        if (session == null) {
            // 会话已结束（超时/已断开），忽略这次点击
            logger.log(Level.FINE, "[KunxunAuth] 收到已失效的对话框点击: " + action.id());
            return;
        }
        ClickPayload payload = AuthService.payloadOf(action.id(), event.getDialogResponseView());
        if (!session.deliver(payload)) {
            logger.log(Level.FINE, "[KunxunAuth] 当前没有等待中的对话框，丢弃点击: " + action.id());
        }
    }

    private static String addressOf(PlayerCommonConnection connection) {
        try {
            InetSocketAddress address = connection.getClientAddress();
            if (address != null && address.getAddress() != null) {
                return address.getAddress().getHostAddress();
            }
        } catch (RuntimeException ignored) {
            // 掉线竞态
        }
        return "unknown";
    }
}
