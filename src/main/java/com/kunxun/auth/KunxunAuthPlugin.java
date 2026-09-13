package com.kunxun.auth;

import com.kunxun.auth.command.AdminCommand;
import com.kunxun.auth.command.DeviceCommand;
import com.kunxun.auth.command.PlayerAuthCommand;
import com.kunxun.auth.config.AuthConfig;
import com.kunxun.auth.config.Messages;
import com.kunxun.auth.config.SecretStore;
import com.kunxun.auth.data.AccountRepository;
import com.kunxun.auth.data.Database;
import com.kunxun.auth.device.ChallengeRegistry;
import com.kunxun.auth.device.DeviceChannelListener;
import com.kunxun.auth.device.DeviceRepository;
import com.kunxun.auth.device.DeviceService;
import com.kunxun.auth.diagnostics.SetupGuide;
import com.kunxun.auth.diagnostics.VoiceDiagnostics;
import com.kunxun.auth.dialog.DialogFactory;
import com.kunxun.auth.dialog.PreJoinListener;
import com.kunxun.auth.listener.ProtectionListener;
import com.kunxun.auth.mail.MailService;
import com.kunxun.auth.session.AuthService;
import com.kunxun.auth.session.DialogCapability;
import com.kunxun.auth.session.FreezeService;
import com.kunxun.auth.session.SessionManager;
import com.kunxun.auth.util.PasswordHasher;
import com.kunxun.auth.util.RateLimiter;
import com.kunxun.auth.util.VerificationCodes;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.PluginCommand;
import org.bukkit.command.TabCompleter;
import org.bukkit.entity.Player;
import org.bukkit.event.HandlerList;
import org.bukkit.event.Listener;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.scheduler.BukkitTask;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.logging.Level;

/**
 * KunxunAuth 主类。
 *
 * <p>插件要解决的问题：让玩家在「还没进入世界」的加载界面完成登录 —— 新玩家走
 * 邮箱验证码 + 设置密码，老玩家只输密码。实现方式是抓住配置阶段事件
 * （{@code AsyncPlayerConnectionConfigureEvent}）并阻塞在那里，用 Paper 原生
 * 对话框和玩家交互；看不到对话框的旧客户端自动降级为聊天命令 + 冻结保护。
 *
 * <p>所有组件都在这里装配，其它类只通过本类的访问器拿依赖，
 * 这样 {@code /kunxunauth reload} 可以直接整体重建。
 */
public final class KunxunAuthPlugin extends JavaPlugin {

    /** SQLite 也统一用这个表前缀，方便以后两种后端互相迁移 */
    private static final String TABLE_PREFIX = "kunxun_";

    /** 验证码 / 限流窗口的清理周期（tick），5 分钟 */
    private static final long SWEEP_INTERVAL_TICKS = 20L * 60L * 5L;

    private static final long HOUR_MILLIS = 3_600_000L;

    private AuthConfig config;
    private Messages messages;

    private Database database;
    private AccountRepository repository;
    private PasswordHasher hasher;
    private VerificationCodes codes;
    private RateLimiter limiter;
    private MailService mail;
    private SessionManager sessions;
    private FreezeService freeze;
    private DialogCapability capability;
    private DialogFactory dialogs;
    private AuthService authService;

    private DeviceRepository deviceRepository;
    private ChallengeRegistry deviceChallenges;
    private DeviceService devices;
    /** 设备应答的入站监听器；未启用设备免密时为 null */
    private DeviceChannelListener deviceListener;

    /** 首次开服引导（发信邮箱没配好时在控制台打教程） */
    private SetupGuide setupGuide;
    /** 语音聊天的端口/版本诊断（只读配置） */
    private VoiceDiagnostics voiceDiagnostics;

    private final List<Listener> listeners = new ArrayList<>();
    private BukkitTask sweepTask;

    // ==================================================================== 生命周期

    @Override
    public void onEnable() {
        try {
            bootstrap();
        } catch (Throwable t) {
            getLogger().log(Level.SEVERE, "[KunxunAuth] 初始化失败，插件将被禁用", t);
            getServer().getPluginManager().disablePlugin(this);
            return;
        }
        scheduleSweep();

        getLogger().info("KunxunAuth 已启用 · 数据库=" + database.type()
                + " · 邮件=" + (mail.available() ? "可用" : "不可用")
                + " · 预进服对话框=" + (config.preJoin().enable() ? "开启" : "关闭")
                + " · 设备免密=" + (config.device().enable() ? "开启" : "关闭"));

        // 没配发信邮箱时，把「该填什么、去哪填、怎么开 SMTP」在控制台讲一遍。
        // 面向的是第一次开服、也不知道授权码是什么的人：不给教程，他们只会以为插件坏了。
        setupGuide.logIfNeeded(config.mail().enable(), mail.available());

        // 语音聊天的端口/版本诊断（只读配置，不参与语音协议）
        if (config.voice().diagnose()) {
            voiceDiagnostics.log();
        }
    }

    @Override
    public void onDisable() {
        cancelSweep();
        unregisterListeners();
        shutdownServices();
        getLogger().info("KunxunAuth 已停用");
    }

    /** 依据当前配置文件重建全部组件并重新注册监听器 / 命令 */
    private void bootstrap() {
        prepareSecretFile();
        this.config = AuthConfig.load(this);
        this.messages = Messages.load(this, config.language());
        saveResourceIfMissing("email-template.html");

        this.database = openDatabase();
        try {
            this.database.initSchema(config.register().maxAccountsPerEmail() == 1);
        } catch (SQLException e) {
            throw new IllegalStateException("建表失败: " + e.getMessage(), e);
        }

        this.repository = new AccountRepository(database);
        this.hasher = new PasswordHasher(config.password().pbkdf2Iterations());
        this.codes = new VerificationCodes();
        this.limiter = new RateLimiter();
        this.mail = new MailService(config.mail(), getDataFolder(), getLogger());
        this.sessions = new SessionManager();
        this.freeze = new FreezeService(this, config, messages);
        this.capability = new DialogCapability(getLogger(),
                config.preJoin().assumeDialogCapableWithoutViaVersion(),
                config.preJoin().dialogMinProtocol());
        this.dialogs = new DialogFactory(messages, config, mail.available());
        this.deviceRepository = new DeviceRepository(database);
        this.deviceChallenges = new ChallengeRegistry();
        this.devices = new DeviceService(config, deviceRepository, deviceChallenges, this, getLogger());
        this.authService = new AuthService(config, messages, repository, hasher, codes, mail,
                limiter, sessions, dialogs, devices, getLogger());
        this.setupGuide = new SetupGuide(messages, getLogger());
        this.voiceDiagnostics = new VoiceDiagnostics(this, getLogger());

        registerListeners();
        registerDeviceChannels();
        registerCommands();
        capability.logSummary();
    }

    /** 把内建资源释放到插件目录（不存在时才写），方便管理员按自己样式修改 */
    private void saveResourceIfMissing(String name) {
        File file = new File(getDataFolder(), name);
        if (file.isFile()) {
            return;
        }
        try {
            saveResource(name, false);
        } catch (IllegalArgumentException e) {
            getLogger().warning("插件内缺少内建资源 " + name + "，将退回使用内建默认内容");
        }
    }

    /**
     * 准备 {@code secret.yml}（SMTP 授权码等敏感凭据）。
     *
     * <p>只在缺失时从 jar 里释放一份<b>空模板</b>；真实凭据永远不进 jar。
     * 另外尽量把文件权限收到 600（仅属主可读写）—— 服务器上通常还跑着网页服务、
     * 面板、备份脚本，权限松了等于把授权码摆在明面上；Windows 上不支持则静默跳过。
     */
    private void prepareSecretFile() {
        File file = new File(getDataFolder(), SecretStore.FILE_NAME);
        if (!file.isFile()) {
            try {
                saveResource(SecretStore.FILE_NAME, false);
            } catch (IllegalArgumentException e) {
                getLogger().warning("插件内缺少 " + SecretStore.FILE_NAME + " 模板，已跳过创建");
                return;
            }
        }
        try {
            if (Files.getFileAttributeView(file.toPath(), PosixFileAttributeView.class) != null) {
                Files.setPosixFilePermissions(file.toPath(), PosixFilePermissions.fromString("rw-------"));
            }
        } catch (Exception e) {
            getLogger().fine("无法调整 " + SecretStore.FILE_NAME + " 权限：" + e.getMessage());
        }
    }

    private Database openDatabase() {
        try {
            if (config.databaseType() == AuthConfig.DatabaseType.MYSQL) {
                AuthConfig.MySqlSettings settings = config.mysql();
                getLogger().info("正在连接外部数据库 " + settings.host() + ":" + settings.port()
                        + "/" + settings.database());
                return Database.mysql(settings, getLogger());
            }
            return Database.sqlite(config.sqlite().file(), TABLE_PREFIX, getLogger());
        } catch (SQLException e) {
            throw new IllegalStateException("数据库初始化失败: " + e.getMessage(), e);
        }
    }

    // ==================================================================== 注册

    private void registerListeners() {
        listeners.clear();
        listeners.add(new PreJoinListener(config, messages, authService, sessions, capability, devices,
                getLogger()));
        listeners.add(new ProtectionListener(config, messages, sessions, freeze, voiceDiagnostics));
        listeners.forEach(listener -> getServer().getPluginManager().registerEvents(listener, this));
    }

    private void unregisterListeners() {
        listeners.forEach(HandlerList::unregisterAll);
        listeners.clear();
    }

    /**
     * 登记设备挑战的两条通道 —— <b>入站和出站都要登记</b>。
     *
     * <p>入站（收客户端回的应答）：没有登记过的通道，Paper 根本不会把包投给
     * 插件的 {@code PluginMessageListener}。
     *
     * <p>出站（把挑战发给客户端）：漏登记会让每一次发包在写包之前就被
     * {@code StandardMessenger.validatePluginMessage} 拒掉，抛
     * {@code ChannelNotRegisteredException}。它是插件级台账，和连接级那份
     * 「客户端登记了哪些通道」的名单是两码事，所以只登记入站并不够 ——
     * 之前设备免密一直发不出挑战，就是缺了这一半。
     *
     * <p>设备免密关掉时两边都不登记 —— 不认的通道连解析都不会发生。
     */
    private void registerDeviceChannels() {
        unregisterDeviceChannels();
        if (!config.device().enable()) {
            return;
        }
        deviceListener = new DeviceChannelListener(devices, getLogger());
        for (String channel : DeviceChannelListener.CHANNELS) {
            try {
                getServer().getMessenger().registerIncomingPluginChannel(this, channel, deviceListener);
            } catch (IllegalArgumentException e) {
                // 通道名不合法（几乎只会发生在有人改了常量），只影响设备免密
                getLogger().warning("[KunxunAuth] 设备入站通道 " + channel + " 登记失败: " + e.getMessage());
            }
        }
        for (String channel : DeviceChannelListener.OUTGOING) {
            try {
                getServer().getMessenger().registerOutgoingPluginChannel(this, channel);
            } catch (IllegalArgumentException e) {
                getLogger().warning("[KunxunAuth] 设备出站通道 " + channel + " 登记失败: " + e.getMessage());
            }
        }
    }

    private void unregisterDeviceChannels() {
        if (deviceListener == null) {
            return;
        }
        for (String channel : DeviceChannelListener.CHANNELS) {
            try {
                getServer().getMessenger().unregisterIncomingPluginChannel(this, channel, deviceListener);
            } catch (Throwable t) {
                // 插件正在卸载时再抛异常没有意义，忽略
            }
        }
        for (String channel : DeviceChannelListener.OUTGOING) {
            try {
                getServer().getMessenger().unregisterOutgoingPluginChannel(this, channel);
            } catch (Throwable t) {
                // 同上
            }
        }
        deviceListener = null;
    }

    private void registerCommands() {
        PlayerAuthCommand playerCommand = new PlayerAuthCommand(this, config, messages, authService,
                sessions, freeze, getLogger());
        bind("register", playerCommand);
        bind("verify", playerCommand);
        bind("login", playerCommand);
        bind("resetpassword", playerCommand);
        bind("kunxundevice", new DeviceCommand(this));
        bind("kunxunauth", new AdminCommand(this));
    }

    private void bind(String name, CommandExecutor executor) {
        PluginCommand command = getCommand(name);
        if (command == null) {
            getLogger().warning("plugin.yml 里没有声明命令 " + name + "，已跳过注册");
            return;
        }
        command.setExecutor(executor);
        if (executor instanceof TabCompleter completer) {
            command.setTabCompleter(completer);
        }
    }

    private void scheduleSweep() {
        sweepTask = getServer().getScheduler().runTaskTimerAsynchronously(this,
                this::sweep, SWEEP_INTERVAL_TICKS, SWEEP_INTERVAL_TICKS);
    }

    private void cancelSweep() {
        if (sweepTask != null) {
            sweepTask.cancel();
            sweepTask = null;
        }
    }

    private void sweep() {
        try {
            codes.sweep();
            limiter.sweep(HOUR_MILLIS);
            if (devices != null) {
                // 兜底清掉没人再等的挑战（正常路径由等待方自己超时销毁）
                devices.sweep();
            }
        } catch (Throwable t) {
            getLogger().log(Level.WARNING, "[KunxunAuth] 定期清理任务出错", t);
        }
    }

    private void shutdownServices() {
        unregisterDeviceChannels();
        devices = null;
        deviceChallenges = null;
        deviceRepository = null;
        if (mail != null) {
            mail.close();
            mail = null;
        }
        if (freeze != null) {
            freeze.shutdown();
            freeze = null;
        }
        if (database != null) {
            database.close();
            database = null;
        }
    }

    // ==================================================================== 热重载

    /**
     * 供 {@code /kunxunauth reload} 调用：整体重建配置、数据库连接与全部服务。
     *
     * <p>已认证玩家集合会被搬到新的会话管理器里，避免重载把在线玩家打回未登录状态。
     */
    public void reloadEverything() {
        Set<UUID> authenticated = sessions == null ? Set.of() : sessions.authenticatedSnapshot();

        cancelSweep();
        unregisterListeners();
        shutdownServices();
        bootstrap();
        sessions.restoreAuthenticated(authenticated);
        scheduleSweep();

        // 重载后重新冻结「在线但没通过验证」的玩家（旧客户端降级路线）
        for (Player player : getServer().getOnlinePlayers()) {
            if (!sessions.isAuthenticated(player.getUniqueId())
                    && !player.hasPermission("kunxunauth.bypass")) {
                freeze.freeze(player);
            }
        }

        getLogger().info("配置已重新加载");
    }

    // ==================================================================== 访问器

    public AuthConfig config() {
        return config;
    }

    public Messages messages() {
        return messages;
    }

    public AccountRepository repository() {
        return repository;
    }

    public PasswordHasher hasher() {
        return hasher;
    }

    public VerificationCodes codes() {
        return codes;
    }

    public RateLimiter limiter() {
        return limiter;
    }

    public SessionManager sessions() {
        return sessions;
    }

    public FreezeService freeze() {
        return freeze;
    }

    public DialogCapability capability() {
        return capability;
    }

    public DialogFactory dialogs() {
        return dialogs;
    }

    public AuthService authService() {
        return authService;
    }

    /** 设备免密登录门面；设备功能关闭时仍然非 null，只是 enabled() 为 false */
    public DeviceService devices() {
        return devices;
    }

    /** 首次开服引导（{@code /kunxunauth setup} 用它打印邮箱配置教程） */
    public SetupGuide setupGuide() {
        return setupGuide;
    }

    /** 语音聊天诊断（{@code /kunxunauth setup} 用它回显端口/版本结论） */
    public VoiceDiagnostics voiceDiagnostics() {
        return voiceDiagnostics;
    }

    public Database database() {
        return database;
    }

    /** SMTP 是否配置完整、可以真正发信 */
    public boolean mailAvailable() {
        return mail != null && mail.available();
    }
}
