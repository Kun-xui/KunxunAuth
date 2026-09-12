package com.kunxun.auth.session;

import io.papermc.paper.connection.PlayerCommonConnection;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * 单次连接的验证会话。
 *
 * <p>关键点：会话是<b>按连接实例</b>存的，不是按 UUID 或玩家名。
 * 离线模式（online-mode=false）下 UUID 由玩家名推导，同名玩家可以并发连接，
 * 若按 UUID 存会话就会出现「A 的验证结果被 B 拿走」的越权登录。
 *
 * <p>字段用 volatile + 一次性 future，保证配置线程与事件线程之间的可见性。
 */
public final class LoginSession {

    private final PlayerCommonConnection connection;
    private final UUID playerId;
    private final String playerName;
    private final String ip;
    private final long createdAt = System.currentTimeMillis();

    private final Object lock = new Object();
    private CompletableFuture<ClickPayload> awaiting;
    private volatile String email = "";
    private volatile boolean cancelled;

    public LoginSession(PlayerCommonConnection connection, UUID playerId, String playerName, String ip) {
        this.connection = connection;
        this.playerId = playerId;
        this.playerName = playerName;
        this.ip = ip;
    }

    public PlayerCommonConnection connection() {
        return connection;
    }

    public UUID playerId() {
        return playerId;
    }

    public String playerName() {
        return playerName;
    }

    public String ip() {
        return ip;
    }

    public long elapsedMillis() {
        return System.currentTimeMillis() - createdAt;
    }

    public String email() {
        return email;
    }

    public void email(String value) {
        this.email = value == null ? "" : value;
    }

    public boolean cancelled() {
        return cancelled;
    }

    public void markCancelled() {
        this.cancelled = true;
    }

    // ------------------------------------------------------------ 等待与回调

    /** 开始等待玩家点击，返回一个只会在本次等待中被完成的 future */
    public CompletableFuture<ClickPayload> beginAwait() {
        CompletableFuture<ClickPayload> future = new CompletableFuture<>();
        synchronized (lock) {
            awaiting = future;
        }
        return future;
    }

    /** 结束等待，之后到达的点击会被丢弃 */
    public void endAwait() {
        synchronized (lock) {
            awaiting = null;
        }
    }

    /**
     * 把一次点击投递给正在等待的 future。
     *
     * @return true = 被消费；false = 当前没有等待者（玩家点了已失效的旧对话框）
     */
    public boolean deliver(ClickPayload payload) {
        CompletableFuture<ClickPayload> future;
        synchronized (lock) {
            future = awaiting;
        }
        if (future == null) {
            return false;
        }
        return future.complete(payload);
    }

    /** 外部原因（被踢、超时）导致等待中断 */
    public void abortWait() {
        CompletableFuture<ClickPayload> future;
        synchronized (lock) {
            future = awaiting;
            awaiting = null;
        }
        if (future != null) {
            future.cancel(false);
        }
    }
}
