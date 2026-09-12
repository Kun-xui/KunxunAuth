package com.kunxun.auth.device;

import io.papermc.paper.connection.PlayerConnection;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * 待应答的挑战登记处。
 *
 * <p><b>按连接实例索引，不按玩家名或 UUID。</b> 这一条是整个设备免密的安全地基：
 * 挑战必须由「收到挑战的那条连接」来应答。如果按玩家名索引，攻击者可以在自己
 * 的连接里拿到挑战、转给另一条连接的客户端代签、再拿回来 —— 那条连接就成了他。
 * 按连接实例索引之后，一条连接上收到的应答只可能对上它自己收到的那个挑战。
 *
 * <p>这里刻意用 {@link IdentityHashMap}：{@code PlayerConnection} 的实现没有重写
 * equals/hashCode，我们要的语义恰好就是「同一个对象实例」。Paper 侧也确实是同一个
 * 实例 —— {@code ServerCommonPacketListenerImpl.handleCustomPayload} 用的
 * {@code paperConnection()} 与 {@code AsyncPlayerConnectionConfigureEvent} 里
 * 拿到的 {@code packetListener.paperConnection} 是同一个字段。
 *
 * <p>nonce 是<b>一次性</b>的：{@link #consume} 取出即销毁，无论后面验签成功还是失败
 * 都不会再有第二次机会。Ed25519 是确定性签名算法，同一组 (nonce, serverId, playerName)
 * 算出来的签名恒定，所以 nonce 一旦可复用，抓一次包就等于永久拿走这台设备。
 */
public final class ChallengeRegistry {

    /** 挑战的用途 */
    public enum Purpose {
        /** 用已绑定的设备免密登录 */
        LOGIN,
        /** 把当前设备登记到账号下 */
        BIND
    }

    /** 一次待应答的挑战 */
    public record Challenge(String nonce, String serverId, String playerName, Purpose purpose,
                            long issuedAt, long expiresAt) {
        public boolean expired() {
            return System.currentTimeMillis() > expiresAt;
        }
    }

    /** 客户端应答 + 它对应的挑战（挑战连同 nonce 一起已经销毁） */
    public record Delivery(Challenge challenge, String payload) {
    }

    /** 一个连接上正在等待的挑战 */
    private record Pending(Challenge challenge, CompletableFuture<Delivery> future) {
    }

    /**
     * 刚登记好的挑战 + 等应答用的 future。
     *
     * <p>{@link #payload()} 是直接可以塞进包体发出去的那串文本；挑战明文只在登记处和
     * 这里各存一份，nonce 不会经客户端之外的地方流转。
     */
    public record Handshake(Challenge challenge, CompletableFuture<Delivery> future) {
        /** 服务端 → 客户端的负载文本 */
        public String payload() {
            return DeviceProtocol.challenge(challenge.nonce(), challenge.serverId(), challenge.playerName());
        }
    }

    /** nonce 熵：16 字节 = 128 bit */
    private static final int NONCE_BYTES = 16;

    private static final SecureRandom RANDOM = new SecureRandom();

    private final Map<PlayerConnection, Pending> waiting =
            Collections.synchronizedMap(new IdentityHashMap<>());

    /**
     * 登记一个新挑战，返回「挑战 + 等应答的 future」。
     *
     * <p>同一条连接上已有的等待会被顶掉（旧 future 取消），
     * 避免一个连接上堆积多个挑战。
     *
     * @return 调用方把 payload 发出去，然后拿 future 去阻塞等待；
     *         超时后请调用 {@link #discard}
     */
    public Handshake open(PlayerConnection connection, Purpose purpose,
                          String serverId, String playerName, int ttlSeconds) {
        long now = System.currentTimeMillis();
        Challenge challenge = new Challenge(newNonce(), serverId, playerName, purpose,
                now, now + Math.max(1, ttlSeconds) * 1000L);
        CompletableFuture<Delivery> future = new CompletableFuture<>();
        Pending previous = waiting.put(connection, new Pending(challenge, future));
        if (previous != null) {
            previous.future().cancel(false);
        }
        return new Handshake(challenge, future);
    }

    /**
     * 取出并销毁该连接上的挑战，同时把应答交给等待方。
     *
     * @return true = 找到了等待中的挑战并已投递；
     *         false = 没有等待者（过期 / 重复包 / 伪造包），调用方记日志后忽略即可
     */
    public boolean consume(PlayerConnection connection, String payload) {
        Pending pending = waiting.remove(connection);
        if (pending == null) {
            return false;
        }
        if (pending.challenge().expired()) {
            // 过期挑战一律作废，不交给等待方去验签
            pending.future().cancel(false);
            return false;
        }
        return pending.future().complete(new Delivery(pending.challenge(), payload));
    }

    /** 主动丢弃某个连接上的挑战（等待超时、玩家被踢等），并销毁对应 nonce */
    public void discard(PlayerConnection connection) {
        Pending pending = waiting.remove(connection);
        if (pending != null) {
            pending.future().cancel(false);
        }
    }

    public int pendingCount() {
        return waiting.size();
    }

    /** 这条连接上是否正等着一个还没过期的挑战（用来避免重复登记 / 无谓的重复发包） */
    public boolean hasPending(PlayerConnection connection) {
        Pending pending = waiting.get(connection);
        return pending != null && !pending.challenge().expired();
    }

    /**
     * 清理已经没人再等的条目。
     *
     * <p>正常情况下等待方超时后会自己 {@link #discard}，这里只是兜底：
     * 万一哪条路径漏了，过期条目也不会在内存里无限堆积。
     */
    public void sweep() {
        List<PlayerConnection> stale = new ArrayList<>();
        synchronized (waiting) {
            waiting.forEach((connection, pending) -> {
                if (pending.future().isDone() || pending.challenge().expired()) {
                    stale.add(connection);
                }
            });
        }
        for (PlayerConnection connection : stale) {
            Pending pending = waiting.remove(connection);
            if (pending != null) {
                pending.future().cancel(false);
            }
        }
    }

    /** ≥16 字节 SecureRandom → Base64url 无填充 */
    private static String newNonce() {
        byte[] raw = new byte[NONCE_BYTES];
        RANDOM.nextBytes(raw);
        return DeviceProtocol.encodeBase64(raw);
    }
}
