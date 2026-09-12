package com.kunxun.auth.dialog;

import com.kunxun.auth.config.AuthConfig;
import com.kunxun.auth.config.Messages;
import com.kunxun.auth.session.AuthService;
import com.kunxun.auth.session.ClickPayload;
import com.kunxun.auth.session.DialogCapability;
import com.kunxun.auth.session.LoginSession;
import com.kunxun.auth.session.SessionManager;
import io.papermc.paper.connection.PlayerCommonConnection;
import io.papermc.paper.connection.PlayerConfigurationConnection;
import io.papermc.paper.event.connection.configuration.AsyncPlayerConnectionConfigureEvent;
import io.papermc.paper.event.player.PlayerCustomClickEvent;
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
    private final Logger logger;

    public PreJoinListener(AuthConfig config, Messages messages, AuthService authService,
                           SessionManager sessions, DialogCapability capability, Logger logger) {
        this.config = config;
        this.messages = messages;
        this.authService = authService;
        this.sessions = sessions;
        this.capability = capability;
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
                if (decision.kickMessage() != null && connection.isConnected()) {
                    connection.disconnect(decision.kickMessage());
                }
            } else if (connection.isConnected()) {
                // 验证通过：关掉对话框让客户端继续进世界
                try {
                    connection.getAudience().closeDialog();
                } catch (RuntimeException e) {
                    logger.log(Level.FINE, "[KunxunAuth] 关闭对话框失败: " + e.getMessage(), e);
                }
            }
        } catch (Throwable t) {
            logger.log(Level.SEVERE, "[KunxunAuth] 预进服验证流程异常: " + playerName, t);
            if (connection.isConnected()) {
                connection.disconnect(messages.get("dialog.error-internal"));
            }
        } finally {
            sessions.close(connection);
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
