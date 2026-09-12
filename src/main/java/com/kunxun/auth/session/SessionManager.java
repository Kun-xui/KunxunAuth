package com.kunxun.auth.session;

import com.kunxun.auth.util.VerificationCodes;
import io.papermc.paper.connection.PlayerCommonConnection;

import java.util.Collection;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 全局会话登记处。
 *
 * <p>三类状态：
 * <ol>
 *   <li><b>配置阶段会话</b>：按连接实例索引，用于对话框点击回调定位玩家；</li>
 *   <li><b>已认证集合</b>：玩家通过验证后进世界，保护监听器据此放行；</li>
 *   <li><b>聊天降级状态</b>：旧客户端注册时暂存待验证邮箱。</li>
 * </ol>
 */
public final class SessionManager {

    private final Map<PlayerCommonConnection, LoginSession> configSessions = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> connectionsPerIp = new ConcurrentHashMap<>();
    private final Set<UUID> authenticated = ConcurrentHashMap.newKeySet();
    private final Map<String, Long> rememberedUntil = new ConcurrentHashMap<>();

    // -------------------------------------------------------------- 配置阶段

    public LoginSession open(PlayerCommonConnection connection, UUID playerId, String playerName, String ip) {
        LoginSession session = new LoginSession(connection, playerId, playerName, ip);
        configSessions.put(connection, session);
        countUp(ip);
        return session;
    }

    public void close(PlayerCommonConnection connection) {
        LoginSession removed = configSessions.remove(connection);
        if (removed != null) {
            removed.abortWait();
            countDown(removed.ip());
        }
    }

    public Optional<LoginSession> session(PlayerCommonConnection connection) {
        return Optional.ofNullable(configSessions.get(connection));
    }

    public int configSessionCount() {
        return configSessions.size();
    }

    // -------------------------------------------------------------- IP 计数

    private void countUp(String ip) {
        connectionsPerIp.computeIfAbsent(ip, ignored -> new AtomicInteger()).incrementAndGet();
    }

    private void countDown(String ip) {
        AtomicInteger counter = connectionsPerIp.get(ip);
        if (counter != null && counter.decrementAndGet() <= 0) {
            connectionsPerIp.remove(ip, counter);
        }
    }

    public int connectionsFrom(String ip) {
        AtomicInteger counter = connectionsPerIp.get(ip);
        return counter == null ? 0 : counter.get();
    }

    /** 是否已经超过该 IP 的并发连接上限（limit <= 0 表示不限） */
    public boolean exceedsConnectionLimit(String ip, int limit) {
        return limit > 0 && connectionsFrom(ip) >= limit;
    }

    // -------------------------------------------------------------- 认证状态

    public boolean isAuthenticated(UUID playerId) {
        return authenticated.contains(playerId);
    }

    public void authenticate(UUID playerId) {
        authenticated.add(playerId);
    }

    public void deauthenticate(UUID playerId) {
        authenticated.remove(playerId);
        pendingEmails.remove(playerId);
    }

    public int authenticatedCount() {
        return authenticated.size();
    }

    /** 热重载前取一份已认证快照，重载后原样搬回去，避免在线玩家被打回未登录 */
    public Set<UUID> authenticatedSnapshot() {
        return new HashSet<>(authenticated);
    }

    /** 热重载后恢复已认证集合 */
    public void restoreAuthenticated(Collection<UUID> playerIds) {
        if (playerIds != null) {
            authenticated.addAll(playerIds);
        }
    }

    // ------------------------------------------------------------ 免密会话

    private static String rememberKey(UUID playerId, String ip) {
        return playerId + "|" + ip;
    }

    public void remember(UUID playerId, String ip, int minutes) {
        if (minutes <= 0) {
            return;
        }
        rememberedUntil.put(rememberKey(playerId, ip),
                System.currentTimeMillis() + minutes * 60_000L);
    }

    /** 命中免密会话则标记为已认证并返回 true */
    public boolean tryAutoLogin(UUID playerId, String ip) {
        Long until = rememberedUntil.get(rememberKey(playerId, ip));
        if (until == null) {
            return false;
        }
        if (until < System.currentTimeMillis()) {
            rememberedUntil.remove(rememberKey(playerId, ip));
            return false;
        }
        authenticated.add(playerId);
        return true;
    }

    public void forget(UUID playerId, String ip) {
        rememberedUntil.remove(rememberKey(playerId, ip));
    }

    // -------------------------------------------------------- 聊天降级暂存

    /** 旧客户端在聊天里注册/找回时，暂存「已发码的邮箱 + 用途」 */
    public record PendingEmail(String email, VerificationCodes.Purpose purpose) {
    }

    private final Map<UUID, PendingEmail> pendingEmails = new ConcurrentHashMap<>();

    public void pendingEmail(UUID playerId, String email, VerificationCodes.Purpose purpose) {
        if (email == null || email.isBlank()) {
            pendingEmails.remove(playerId);
        } else {
            pendingEmails.put(playerId, new PendingEmail(email, purpose));
        }
    }

    public PendingEmail pendingEmail(UUID playerId) {
        return pendingEmails.get(playerId);
    }

    public void clearPendingEmail(UUID playerId) {
        pendingEmails.remove(playerId);
    }

    // ---------------------------------------------------- 管理员重置授权

    /** 管理员签发的一次性重置码 */
    public record ResetGrant(String code, long expiresAt) {
        public boolean expired() {
            return System.currentTimeMillis() > expiresAt;
        }
    }

    private final Map<String, ResetGrant> resetGrants = new ConcurrentHashMap<>();

    private static String nameKey(String playerName) {
        return playerName == null ? "" : playerName.toLowerCase(Locale.ROOT);
    }

    /**
     * 管理员为某个玩家名签发一次性重置码。
     *
     * <p>用这个而不是「直接设一个新密码」，是因为新密码一旦作为命令参数
     * 就会进服务器日志 / RCON 日志 / 面板命令历史；重置码是一次性的，
     * 而且只对这一个玩家名生效。
     */
    public void grantPasswordReset(String playerName, String code, int validMinutes) {
        String key = nameKey(playerName);
        if (key.isEmpty() || code == null || code.isBlank()) {
            return;
        }
        resetGrants.put(key, new ResetGrant(code,
                System.currentTimeMillis() + Math.max(1, validMinutes) * 60_000L));
    }

    /** 取该玩家名待用的重置授权；已过期则顺手清掉并返回 null */
    public ResetGrant passwordResetGrant(String playerName) {
        String key = nameKey(playerName);
        if (key.isEmpty()) {
            return null;
        }
        ResetGrant grant = resetGrants.get(key);
        if (grant == null) {
            return null;
        }
        if (grant.expired()) {
            resetGrants.remove(key, grant);
            return null;
        }
        return grant;
    }

    /** 重置码校验通过、密码改完之后清掉，保证一次性 */
    public void clearPasswordReset(String playerName) {
        resetGrants.remove(nameKey(playerName));
    }

    // -------------------------------------------------------------- 清理

    /** 玩家退出时清掉所有与该玩家相关的临时状态 */
    public void purge(UUID playerId) {
        authenticated.remove(playerId);
        pendingEmails.remove(playerId);
        rememberedUntil.keySet().removeIf(key -> key.startsWith(playerId + "|"));
    }
}
