package com.kunxun.auth.device;

import com.kunxun.auth.config.AuthConfig;
import io.papermc.paper.connection.PlayerConfigurationConnection;
import io.papermc.paper.connection.PlayerConnection;
import org.bukkit.Bukkit;
import org.bukkit.plugin.Plugin;

import java.lang.reflect.Method;
import java.sql.SQLException;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 设备免密登录的对外门面：发挑战、收应答、验签、绑定、吊销。
 *
 * <p>这个类只干「协议 + 密码学 + 落库」，不碰对话框。谁在什么时候问玩家
 * 「要不要绑定这台设备」是 {@code AuthService} 的事。
 *
 * <p><b>为什么要在两条通道上发两次。</b> 三类客户端对同一条协议的理解不一样：
 *
 * <ul>
 *   <li>Fabric / NeoForge：把「挑战」和「应答」注册成两个独立的
 *       {@code CustomPacketPayload.Type}，于是走两条通道
 *       {@code kunxunauth:challenge} / {@code kunxunauth:response}，
 *       包体就是原生的 {@code writeUtf}；</li>
 *   <li>Forge：{@code SimpleChannel} 把它们复用在同一条
 *       {@code kunxunauth:device} 上，靠包体前面那个 VarInt 序号区分，
 *       所以挑战的包体是 {@code VarInt(0) + writeUtf}。</li>
 * </ul>
 *
 * <p>两种形状必须<b>分别发在各自的通道上</b>，不能在同一条通道上两种都发：
 * Forge 的解码器会把「长度前缀」当成消息序号，找不到对应的消息类型就直接抛异常，
 * 那是会把玩家踢掉的失败方式。反过来，把包发给我们完全不认识的通道（原版客户端）
 * 是安全的 —— 原版对未知的自定义负载一律回落成 {@code DiscardedPayload} 静默丢弃。
 *
 * <p><b>为什么要反复补发。</b> 光在插件里登记出站通道还不够，Paper 在配置阶段
 * 只有在「客户端登记过的」通道上才真的把包发出去
 * （{@code PaperPlayerConfigurationConnection.sendPluginMessage} 里那句
 * {@code channels().contains(channel)} 不满足就静默 return，不抛异常、不发包）。
 * 而挑战是在配置阶段刚开场的那一刻签发的，客户端的通道登记（Forge 走
 * {@code forge:channel_registration}、Fabric / NeoForge 走 {@code minecraft:register}）
 * 至少要一个来回才到服务端 —— 也就是说首次那份包必然撞在这段空窗上。
 * 所以这里在挑战有效期内反复补发，等客户端的登记真正到达之后再把同一份包发一遍。
 *
 * <p>前两秒<b>只认客户端自己的登记</b>，不硬塞：硬塞等于在客户端还没准备好接收时
 * 就丢一条它不认识的负载过去，运气差就是一次踢人。超过两秒还没等到登记，才退而
 * 反射 {@code PluginMessageBridgeImpl.addChannel} 把通道补进连接级名单
 * （这个方法不在 paper-api 里，只能反射），保住可用性。
 * 反射不到也只是退化成「等客户端自己报」：玩家照旧用密码登录。
 */
public final class DeviceService {

    /** 验签通过、但还没落库的一次设备应答 */
    public record Proof(String publicKey, String deviceName, String fingerprint) {

        /** 这份应答有没有带硬件指纹（v2 模组才有；v1 老模组是空串） */
        public boolean hasFingerprint() {
            return fingerprint != null && !fingerprint.isEmpty();
        }
    }

    /** 免密登录的判定结果 */
    public enum Authorization {
        /** 免密放行 */
        ALLOWED,
        /** 这把公钥没绑在这个账号名下（含「绑在别人账号下」） */
        NOT_BOUND,
        /** 绑在这个账号名下，但硬件指纹对不上：换了机器，或者私钥文件被复制走了 */
        FINGERPRINT_MISMATCH
    }

    /** 绑定结果 */
    public enum BindResult {
        /** 绑定成功 */
        OK,
        /** 这台设备本来就绑在当前账号下 */
        ALREADY_BOUND,
        /** 超过单账号设备上限 */
        LIMIT_REACHED,
        /** 这把公钥已经绑在别的账号名下了 */
        CONFLICT,
        /** 数据库出错 */
        FAILED
    }

    /** 反射拿到的 {@code PluginMessageBridgeImpl.addChannel}，拿不到就是 null */
    private static final Method ADD_CHANNEL = resolveMethod("addChannel", String.class);

    /** 反射拿到的 {@code PluginMessageBridgeImpl.channels}，只用来判断「客户端登记了没有」 */
    private static final Method CHANNELS = resolveMethod("channels");

    /**
     * 补发间隔。首次发送在配置阶段刚开场，正是客户端通道登记还没到的空窗；
     * 挑战总有效期只有几秒，所以起步要快、间隔要短。
     */
    private static final long REDELIVER_INITIAL_DELAY_MILLIS = 250L;
    private static final long REDELIVER_PERIOD_MILLIS = 500L;

    /**
     * 等应答的窗口下限（毫秒）：必须罩得住「客户端通道登记 + 一个来回」。
     *
     * <p>以前这里没有下限，等多久直接取 {@code challenge-timeout-seconds}（线上配的 3 秒），
     * 结果是<b>绑定过的账号永远免不了密</b>：挑战 3 秒就放弃并销毁 nonce，
     * 而客户端从建连到真正认这条通道实测要 2~3.5 秒，留给「发出去 + 签回来」的时间
     * 根本不够。绑定前之所以能成，是因为那时候还没设备、压根没走这条等待分支。
     *
     * <p>所以配置值现在只是下限，真正的下限由这里兜底。
     */
    private static final long MIN_CHALLENGE_WAIT_MILLIS = 7000L;

    /**
     * 挑战 nonce 的最短有效期（秒）。
     *
     * <p>{@code challenge-timeout-seconds} 原本同时充当两件事：nonce 的生命周期，
     * 以及「有绑定设备时值得为免密等多久」。补发机制让这两件事必须分开 ——
     * 等应答的窗口由 {@link #MIN_CHALLENGE_WAIT_MILLIS} 决定，nonce 必须活得更久，
     * 否则补发还没命中、挑战就先过期了，白等。
     */
    private static final int MIN_CHALLENGE_TTL_SECONDS = 10;

    private final AuthConfig config;
    private final DeviceRepository devices;
    private final ChallengeRegistry challenges;
    private final Plugin plugin;
    private final Logger logger;

    public DeviceService(AuthConfig config, DeviceRepository devices, ChallengeRegistry challenges,
                         Plugin plugin, Logger logger) {
        this.config = config;
        this.devices = devices;
        this.challenges = challenges;
        this.plugin = plugin;
        this.logger = logger;
        if (ADD_CHANNEL == null) {
            logger.info("[KunxunAuth] 反射不到 PluginMessageBridgeImpl.addChannel"
                    + " —— 设备挑战改为纯靠客户端主动登记通道（补发会自动生效）");
        }
    }

    public boolean enabled() {
        return config.device().enable();
    }

    public AuthConfig.DeviceSettings settings() {
        return config.device();
    }

    public DeviceRepository repository() {
        return devices;
    }

    // ==================================================================== 挑战

    /**
     * 登记一个挑战并立刻在全部候选通道上发出去。
     *
     * <p>登记和发包写在一起，是为了杜绝「登记了却没发」和「发了却没登记」这两种
     * 只会在超时里体现出来的错位。
     */
    public ChallengeRegistry.Handshake issue(PlayerConnection connection, ChallengeRegistry.Purpose purpose,
                                             String username) {
        AuthConfig.DeviceSettings settings = config.device();
        ChallengeRegistry.Handshake handshake = challenges.open(connection, purpose,
                settings.serverId(), username, challengeTtlSeconds());
        Say say = new Say();
        deliver(connection, handshake, 0L, say);
        scheduleRedelivery(connection, handshake, say);
        return handshake;
    }

    /** nonce 的实际有效期：不会比配置值短，但至少要活到补发能命中 */
    private int challengeTtlSeconds() {
        return Math.max(1, Math.max(config.device().challengeTimeoutSeconds(), MIN_CHALLENGE_TTL_SECONDS));
    }

    /** 等应答的实际上限：配置值只是下限，真正的下限由补发窗口决定 */
    private long challengeWaitMillis() {
        return Math.max(MIN_CHALLENGE_WAIT_MILLIS,
                Math.max(1000L, config.device().challengeTimeoutSeconds() * 1000L));
    }

    /**
     * 阻塞等待应答并验签。
     *
     * <p>超时、负载畸形、nonce 对不上、验签不过 —— 一律返回 null，调用方回落密码登录。
     * 这里刻意不抛异常也不区分原因：对玩家来说结果都是「这台设备没认出来」。
     *
     * @return 验签通过的设备证明；没有则 null
     */
    public Proof await(PlayerConnection connection, ChallengeRegistry.Handshake handshake) {
        if (handshake == null) {
            return null;
        }
        ChallengeRegistry.Delivery delivery;
        long waitMillis = challengeWaitMillis();
        try {
            delivery = handshake.future().get(waitMillis, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            challenges.discard(connection);
            return null;
        } catch (ExecutionException | TimeoutException | CancellationException e) {
            // 超时是常态（客户端没装模组），把 nonce 一并销毁，别留着等下一轮。
            // 注意 discard 会 cancel 掉 future，补发任务据此自停 —— 所以窗口必须
            // 留够，早停一秒，补发就少一秒机会。
            logger.info("[KunxunAuth] 设备挑战在 " + (waitMillis / 1000) + " 秒内没有收到应答，回落密码登录");
            challenges.discard(connection);
            return null;
        }

        ChallengeRegistry.Challenge challenge = delivery.challenge();
        DeviceProtocol.Response response = DeviceProtocol.parseResponse(delivery.payload());
        if (response == null) {
            logger.fine("[KunxunAuth] 设备应答格式不合法，已忽略");
            return null;
        }
        byte[] signed = DeviceProtocol.signingInput(
                challenge.nonce(), challenge.serverId(), challenge.playerName());
        if (!DeviceProtocol.verify(response.publicKey(), response.signature(), signed)) {
            // 只有这一条值得进日志：格式对、nonce 对，但签名不对，通常意味着有人在伪造
            logger.warning("[KunxunAuth] 设备应答验签失败：玩家 " + challenge.playerName());
            return null;
        }
        return new Proof(response.publicKey(), response.deviceName(), response.fingerprint());
    }

    /** 入站应答。channel 只用来记日志，解析方式是两种包体都试 */
    public void onIncoming(PlayerConnection connection, String channel, byte[] data) {
        String payload = DeviceProtocol.decodeResponse(data);
        if (payload == null) {
            logger.fine("[KunxunAuth] 收到无法解析的设备应答（通道 " + channel + "），已忽略");
            return;
        }
        if (challenges.consume(connection, payload)) {
            logger.info("[KunxunAuth] 已收到设备应答 · 通道=" + channel);
            return;
        }
        // 没有等待者：重复包、过期包，或者有人拿别的连接的挑战来重放
        logger.fine("[KunxunAuth] 收到没有对应挑战的设备应答（通道 " + channel + "），已忽略");
    }

    /** 连接断开：销毁它名下的 nonce */
    public void onDisconnect(PlayerConnection connection) {
        challenges.discard(connection);
    }

    /**
     * 主动放弃这条连接上的设备挑战。
     *
     * <p>和 {@link #onDisconnect} 是同一件事，只是调用语义不同：在
     * 「玩家点了取消 / 验证失败要被断开」这类马上就要关连接的路径上，
     * 必须<b>先</b>调用它再断开 —— 否则补发任务会在连接关闭的同时
     * 从另一个线程往这条连接上写包，发包和断连撞在一起，
     * 玩家看到的就是「点了退出还得等服务器」。
     */
    public void discard(PlayerConnection connection) {
        onDisconnect(connection);
    }

    /** 兜底清理过期挑战 */
    public void sweep() {
        challenges.sweep();
    }

    // ==================================================================== 绑定

    /** 这把公钥归属哪个账号；没绑过就是空 */
    public Optional<DeviceRecord> find(String publicKey) {
        try {
            return devices.findByPublicKey(publicKey);
        } catch (SQLException e) {
            logger.log(Level.WARNING, "[KunxunAuth] 查询设备失败", e);
            return Optional.empty();
        }
    }

    /** 应答里的公钥是否确实绑在这个账号名下 —— 免密登录的唯一判据 */
    public boolean isBoundTo(String username, String publicKey) {
        Optional<DeviceRecord> record = find(publicKey);
        return record.isPresent() && sameUser(record.get().username(), username);
    }

    /**
     * 免密登录的完整判定：公钥归属 + 硬件指纹。
     *
     * <p>指纹的三档处理见 {@link AuthConfig.FingerprintMode}。这里只有一件事值得强调：
     * <b>指纹永远不是放行的依据</b>，公钥验签才是。指纹只用来回答
     * 「这台机器还是不是当初绑定那台」，回答「不是」时把这条绑定作废，
     * 让玩家用密码登录一次、重新绑一次 —— 而不是把人挡在门外。
     */
    public Authorization authorize(String username, Proof proof) {
        if (proof == null || username == null) {
            return Authorization.NOT_BOUND;
        }
        Optional<DeviceRecord> found = find(proof.publicKey());
        if (found.isEmpty() || !sameUser(found.get().username(), username)) {
            return Authorization.NOT_BOUND;
        }
        return checkFingerprint(found.get(), proof);
    }

    private Authorization checkFingerprint(DeviceRecord record, Proof proof) {
        AuthConfig.FingerprintMode mode = config.device().fingerprintMode();
        if (mode == AuthConfig.FingerprintMode.OFF || !proof.hasFingerprint()) {
            // 关了校验，或者对面是没带指纹的老模组：按公钥放行
            return Authorization.ALLOWED;
        }
        if (!record.hasFingerprint()) {
            // 这条绑定是老模组建的，指纹栏还空着：这一次补记上去，之后就能校验
            fillFingerprint(record, proof.fingerprint());
            return Authorization.ALLOWED;
        }
        if (record.sameMachine(proof.fingerprint())) {
            return Authorization.ALLOWED;
        }
        if (mode == AuthConfig.FingerprintMode.RECORD) {
            logger.warning("[KunxunAuth] 设备指纹与绑定记录不一致（" + record.username()
                    + " / " + record.displayName() + "），fingerprint-mode=record，本次仍然放行");
            return Authorization.ALLOWED;
        }
        // STRICT：这台机器已经不是当初绑定那台了
        logger.warning("[KunxunAuth] 设备指纹不匹配，免密已作废：" + record.username()
                + " / " + record.displayName() + " · 绑定=" + record.fingerprintPrefix()
                + " · 本次=" + DeviceProtocol.normalizeFingerprint(proof.fingerprint()));
        revokeStale(record);
        return Authorization.FINGERPRINT_MISMATCH;
    }

    private void fillFingerprint(DeviceRecord record, String fingerprint) {
        try {
            if (devices.fillFingerprintIfMissing(record.publicKey(), fingerprint)) {
                logger.info("[KunxunAuth] 已为设备「" + record.displayName()
                        + "」补记硬件指纹（账号 " + record.username() + "）");
            }
        } catch (SQLException e) {
            logger.log(Level.WARNING, "[KunxunAuth] 补记设备指纹失败", e);
        }
    }

    /**
     * 把「机器已经不是原来那台」的绑定删掉。
     *
     * <p>必须删而不是留着：留着的话公钥仍然被这条记录占着，玩家用密码登录之后
     * 想重新绑定这台设备，会在 {@code bind} 里撞上 {@link BindResult#ALREADY_BOUND}，
     * 于是永远卡在「每次都要输密码」上 —— 这正是要修的那个现象。
     */
    private void revokeStale(DeviceRecord record) {
        try {
            if (devices.deleteByPublicKey(record.publicKey())) {
                logger.info("[KunxunAuth] 已作废账号 " + record.username()
                        + " 上一台机器的设备绑定，玩家下次密码登录后可重新绑定");
            }
        } catch (SQLException e) {
            logger.log(Level.WARNING, "[KunxunAuth] 作废陈旧设备绑定时出错", e);
        }
    }

    /** 这个账号名下有没有绑过设备（用来决定值不值得为免密多等那几秒） */
    public boolean hasAnyDevice(String username) {
        return count(username) > 0;
    }

    public List<DeviceRecord> list(String username) {
        try {
            return devices.listByUsername(username);
        } catch (SQLException e) {
            logger.log(Level.WARNING, "[KunxunAuth] 列出设备失败", e);
            return List.of();
        }
    }

    public int count(String username) {
        try {
            return devices.countByUsername(username);
        } catch (SQLException e) {
            logger.log(Level.WARNING, "[KunxunAuth] 统计设备失败", e);
            return 0;
        }
    }

    /**
     * 把一台设备绑到账号下。
     *
     * <p>「同一把公钥被两个账号抢绑」这件事由数据库的唯一约束兜底，这里的预查询
     * 只负责把结果翻译成玩家能看懂的一句话。公钥本身就是设备身份，所以不存在
     * 「改个名字蒙过去」的空间。
     *
     * <p>从 1.1.0 起客户端是按账号分开存密钥的，所以「同一台机器上的两个账号」
     * 会各自持有一把公钥，互不冲突；真走到 {@link BindResult#CONFLICT}，
     * 只剩两种情况：客户端还是旧版（一机一把共用密钥），或者密钥文件被人复制过去了。
     */
    public BindResult bind(String username, String publicKey, String deviceName, String fingerprint, String ip) {
        Optional<DeviceRecord> existing = find(publicKey);
        if (existing.isPresent()) {
            if (sameUser(existing.get().username(), username)) {
                return BindResult.ALREADY_BOUND;
            }
            logger.warning("[KunxunAuth] 设备「" + deviceName + "」的公钥已绑在账号 "
                    + existing.get().username() + " 名下，拒绝绑定到 " + username
                    + "（若是同一台机器的第二个账号，请把客户端模组升级到 1.1.0+，"
                    + "旧版模组全机共用一把密钥）");
            return BindResult.CONFLICT;
        }
        try {
            if (devices.countByUsername(username) >= config.device().maxDevicesPerAccount()) {
                return BindResult.LIMIT_REACHED;
            }
            return devices.bind(username, publicKey, deviceName, fingerprint, ip)
                    ? BindResult.OK : BindResult.CONFLICT;
        } catch (SQLException e) {
            logger.log(Level.WARNING, "[KunxunAuth] 绑定设备失败", e);
            return BindResult.FAILED;
        }
    }

    /** 刷新设备最后使用时间；失败不影响本次登录 */
    public void touch(String publicKey, String ip) {
        devices.touch(publicKey, ip);
    }

    /** 玩家自己删自己的一台设备 */
    public boolean revokeOwned(String username, String publicKey) {
        try {
            return devices.revokeOwned(username, publicKey);
        } catch (SQLException e) {
            logger.log(Level.WARNING, "[KunxunAuth] 吊销设备失败", e);
            return false;
        }
    }

    /** 全量吊销某个账号的设备（改密 / 被盗处置） */
    public int revokeAll(String username) {
        try {
            return devices.revokeAll(username);
        } catch (SQLException e) {
            logger.log(Level.WARNING, "[KunxunAuth] 全量吊销设备失败", e);
            return 0;
        }
    }

    public long totalBound() {
        try {
            return devices.count();
        } catch (SQLException e) {
            return 0L;
        }
    }

    private static boolean sameUser(String left, String right) {
        return left != null && right != null && left.equalsIgnoreCase(right);
    }

    // ==================================================================== 发包

    /**
     * 首次发出之后过这么久，才允许反射注入连接级名单。
     *
     * <p>为什么不从第 0 毫秒就注入：那会儿客户端还在配置阶段开场，通道协商没开始，
     * 包发过去只会被当成「不认识的通道」丢掉，白白浪费一次机会、还可能招客户端报错。
     * 但也不能拖到 4 秒 —— 实测真正需要的就是「客户端认了这条通道之后马上再发一份」，
     * 拖久了等应答的窗口就罩不住了。
     */
    private static final long INJECT_AFTER_MILLIS = 1000L;

    /**
     * 把同一份挑战发到两类客户端各自的通道上。
     *
     * <p>Fabric / NeoForge 用独立通道（原生 {@code writeUtf}）；Forge 复用同一条通道，
     * 包体前面加 VarInt 序号。
     *
     * @param elapsedMillis 距挑战创建过了多久
     * @param say           日志节流器，两条通道各自只留「首投」和「真正发出」两条
     */
    private void deliver(PlayerConnection connection, ChallengeRegistry.Handshake handshake,
                         long elapsedMillis, Say say) {
        String payload = handshake.payload();
        send(connection, DeviceProtocol.CHANNEL_CHALLENGE, DeviceProtocol.challengeBody(payload),
                elapsedMillis, say);
        send(connection, DeviceProtocol.CHANNEL, DeviceProtocol.forgeChallengeBody(payload),
                elapsedMillis, say);
    }

    /**
     * 在挑战还有效的这段时间里反复补发。
     *
     * <p>首次发送发生在配置阶段刚开场的那一刻，而客户端的通道登记（Forge 走
     * {@code forge:channel_registration}、Fabric / NeoForge 走 {@code minecraft:register}）
     * 至少要一个来回才到服务端，首次那份包大概率赶不上。补发就是用来跨过这段空窗的：
     * 客户端的登记一旦到达，同一次补发立刻就能命中。
     *
     * <p>应答一到（{@code future} 完成）或者连接断开就立刻自停，不做无谓的重复发包。
     *
     * @param say 与首次发送共用的日志节流器，免得同一个通道记两遍
     */
    private void scheduleRedelivery(PlayerConnection connection, ChallengeRegistry.Handshake handshake,
                                    Say say) {
        long started = System.currentTimeMillis();
        long deadline = started
                + Math.max(1L, challengeTtlSeconds()) * 1000L
                + REDELIVER_PERIOD_MILLIS;
        try {
            Bukkit.getAsyncScheduler().runAtFixedRate(plugin, task -> {
                if (handshake.future().isDone() || !connection.isConnected()
                        || System.currentTimeMillis() > deadline) {
                    task.cancel();
                    return;
                }
                deliver(connection, handshake, System.currentTimeMillis() - started, say);
            }, REDELIVER_INITIAL_DELAY_MILLIS, REDELIVER_PERIOD_MILLIS, TimeUnit.MILLISECONDS);
        } catch (Throwable t) {
            // 调度器不可用：退化成「只发一次」，不影响密码登录
            logger.log(Level.FINE, "[KunxunAuth] 设备挑战补发任务未能启动: " + t);
        }
    }

    /**
     * 在一条通道上把挑战投出去。
     *
     * <p>能不能发由两层决定，两层都在这里处理：插件级的出站登记已经在
     * {@code onEnable} 做过了（少了它 {@code sendPluginMessage} 会直接抛
     * {@code ChannelNotRegisteredException}），剩下的是连接级的
     * 「客户端登记过这条通道没有」。
     *
     * <p>连接级这一层<b>不再拦着不发</b>。早先的写法是「没登记就 return」，
     * 那正是绑定过之后次次失败的元凶：客户端从建连到真正认这条通道要 2~3.5 秒，
     * 而等应答的窗口只有 3 秒 —— 中间那些「登记刚好到、本来可以正常发」的时机
     * 全被这个提前返回吃掉了，剩下的时间又不够再走一个来回。现在一律照投：
     * 登记还没到，Paper 自己会静默丢包，没有副作用；登记一到，立刻命中。
     *
     * <p>反射注入保留，但推迟到 {@link #INJECT_AFTER_MILLIS} 之后。实测 Forge
     * 客户端始终只登记 {@code kunxunauth:device}，{@code kunxunauth:challenge}
     * 从来没进过连接级名单，只有注入才发得出去。
     */
    private void send(PlayerConnection connection, String channel, byte[] body, long elapsedMillis,
                      Say say) {
        boolean first = elapsedMillis == 0L;
        if (!(connection instanceof PlayerConfigurationConnection configurationConnection)
                || !connection.isConnected()) {
            if (first) {
                logger.info("[KunxunAuth] 设备挑战没发出去 · 通道=" + channel
                        + " · 连接=" + connection.getClass().getName()
                        + " · connected=" + connection.isConnected());
            }
            return;
        }
        boolean listed = listening(connection, channel);
        boolean injected = false;
        if (!listed && elapsedMillis >= INJECT_AFTER_MILLIS) {
            // Paper 会因为连接级名单里没有这条通道而静默丢包，先替它补上
            injected = true;
            addChannel(connection, channel);
            listed = listening(connection, channel);
        }
        try {
            configurationConnection.sendPluginMessage(plugin, channel, body);
        } catch (RuntimeException e) {
            // 首次失败必须留痕；补发失败每 500ms 一次，落了日志就是刷屏，压到 FINE
            logger.log(first || say.error(channel) ? Level.INFO : Level.FINE,
                    "[KunxunAuth] 设备通道 " + channel + " 发包失败: "
                            + e.getClass().getSimpleName() + " " + e.getMessage());
            return;
        }
        if (listed ? say.delivered(channel) : first && say.attempted(channel)) {
            logger.info("[KunxunAuth] 设备挑战已投出 · 通道=" + channel
                    + " · 客户端已登记=" + listed
                    + " · 反射注入=" + injected
                    + " · 距创建=" + elapsedMillis + "ms"
                    + " · 负载=" + body.length + " 字节");
        }
    }

    /**
     * 补发日志的节流器。
     *
     * <p>补发是每 500ms 一次、连续 10 秒的循环，任何一个条件写宽了都会变成刷屏源
     * （上一版就是这么把 108 行异常刷进日志的）。这里给每条通道各留三个不重复的名额：
     * 「第一次尝试投出」「第一次真正发出去」「第一次发失败」，之后一律闭嘴。
     */
    private static final class Say {
        private final Set<String> attempted = ConcurrentHashMap.newKeySet();
        private final Set<String> delivered = ConcurrentHashMap.newKeySet();
        private final Set<String> errors = ConcurrentHashMap.newKeySet();

        boolean attempted(String channel) {
            return attempted.add(channel);
        }

        boolean delivered(String channel) {
            return delivered.add(channel);
        }

        boolean error(String channel) {
            return errors.add(channel);
        }
    }

    /** 这条连接上客户端是否已经把该通道登记进来。只看，不改 */
    private static boolean listening(PlayerConnection connection, String channel) {
        Method method = CHANNELS;
        if (method == null) {
            return false;
        }
        try {
            Object value = method.invoke(connection);
            return value instanceof Collection<?> collection && collection.contains(channel);
        } catch (Throwable t) {
            return false;
        }
    }

    private void addChannel(PlayerConnection connection, String channel) {
        Method method = ADD_CHANNEL;
        if (method == null) {
            return;
        }
        try {
            method.invoke(connection, channel);
        } catch (Throwable t) {
            logger.log(Level.FINE, "[KunxunAuth] 登记设备通道 " + channel + " 失败: " + t);
        }
    }

    /**
     * 反射取 {@code io.papermc.paper.connection.PluginMessageBridgeImpl} 上的方法。
     *
     * <p>这个类不在 paper-api 里（是服务端实现的一部分），所以只能反射；
     * 换了 Paper 版本方法没了就返回 null，设备免密降级为「等客户端自己登记」。
     */
    private static Method resolveMethod(String name, Class<?>... parameters) {
        try {
            Class<?> bridge = Class.forName("io.papermc.paper.connection.PluginMessageBridgeImpl");
            Method method;
            try {
                method = bridge.getMethod(name, parameters);
            } catch (NoSuchMethodException e) {
                method = bridge.getDeclaredMethod(name, parameters);
            }
            method.setAccessible(true);
            return method;
        } catch (Throwable t) {
            return null;
        }
    }
}
