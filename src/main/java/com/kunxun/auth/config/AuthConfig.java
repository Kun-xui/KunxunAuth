package com.kunxun.auth.config;

import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

/**
 * config.yml 的强类型视图。
 *
 * <p>所有取值都在构造时一次性读出，运行期不再访问 Bukkit 的 Configuration
 * （避免异步线程里碰非线程安全对象）。{@code /kunxunauth reload} 时整体重建实例。
 */
public final class AuthConfig {

    public enum DatabaseType { SQLITE, MYSQL }

    /** 旧客户端（看不到对话框）的处理方式 */
    public enum LegacyMode {
        /** 放行进世界，用聊天命令 + 冻结保护完成验证 */
        CHAT,
        /** 直接踢出，要求升级客户端 */
        KICK
    }

    public record SqliteSettings(File file) {
    }

    public record MySqlSettings(String host, int port, String database, String username, String password,
                                String tablePrefix, boolean useSsl, String parameters, int poolSize) {
    }

    public record PreJoinSettings(boolean enable, int timeoutSeconds, boolean allowCloseWithEscape,
                                  boolean cancelKicks, int dialogMinProtocol,
                                  boolean assumeDialogCapableWithoutViaVersion, LegacyMode legacyMode) {
    }

    public record LoginSettings(int timeoutSeconds, int maxFailedAttempts, int lockoutMinutes,
                                int sessionMinutes, int minPasswordLength, int maxPasswordLength) {
    }

    public record RegisterSettings(boolean allowRegistration, boolean requireEmailVerification,
                                   int codeExpireMinutes, int codeMaxAttempts, int resendCooldownSeconds,
                                   int maxRegistrationsPerIpPerHour, int maxCodesPerIpPerHour,
                                   int maxAccountsPerEmail, List<String> blacklistDomains,
                                   List<String> whitelistDomains) {
    }

    public record PasswordSettings(int pbkdf2Iterations) {
    }

    public record MailSettings(boolean enable, String host, int port, boolean starttls, boolean ssl,
                               String account, String password, String senderName, String subject,
                               int connectionTimeoutMs, String templateFile, String serverName) {
    }

    public record MiscSettings(String welcomeMessage, boolean hideUnauthenticatedFromOthers,
                               boolean logVerificationCodes, int maxConnectionsPerIp,
                               boolean maskPlayerIp, int adminResetGrantMinutes) {
    }

    /**
     * 设备免密登录（客户端模组 Ed25519 签名）。
     *
     * <p>{@code serverId} 用来把签名绑死到本服务器，避免 A 服签出的应答被拿到 B 服重放；
     * 留空时插件会在数据目录生成一个随机 ID 并持久化，服务重装/换目录才会变。
     */
    public record DeviceSettings(boolean enable, String serverId, int maxDevicesPerAccount,
                                 int challengeTimeoutSeconds, int bindPromptSeconds,
                                 boolean showBindPrompt, boolean revokeOnPasswordChange) {
    }

    private final String language;
    private final DatabaseType databaseType;
    private final SqliteSettings sqlite;
    private final MySqlSettings mysql;
    private final PreJoinSettings preJoin;
    private final LoginSettings login;
    private final RegisterSettings register;
    private final PasswordSettings password;
    private final MailSettings mail;
    private final MiscSettings misc;
    private final DeviceSettings device;

    private AuthConfig(String language, DatabaseType databaseType, SqliteSettings sqlite, MySqlSettings mysql,
                       PreJoinSettings preJoin, LoginSettings login, RegisterSettings register,
                       PasswordSettings password, MailSettings mail, MiscSettings misc,
                       DeviceSettings device) {
        this.language = language;
        this.databaseType = databaseType;
        this.sqlite = sqlite;
        this.mysql = mysql;
        this.preJoin = preJoin;
        this.login = login;
        this.register = register;
        this.password = password;
        this.mail = mail;
        this.misc = misc;
        this.device = device;
    }

    // ------------------------------------------------------------------ 读取

    public static AuthConfig load(JavaPlugin plugin) {
        plugin.saveDefaultConfig();
        plugin.reloadConfig();
        FileConfiguration c = plugin.getConfig();
        File dataFolder = plugin.getDataFolder();

        // 敏感凭据（SMTP 授权码 / 数据库密码）走独立来源，不跟着 config.yml 一起被打包分发
        SecretStore secrets = SecretStore.load(plugin);
        SecretStore.Credential mysqlPassword =
                secrets.mysqlPassword(c.getString("database.mysql.password", ""));
        warnIfInConfig(plugin, "外部数据库密码", "database.mysql.password", mysqlPassword);

        String language = c.getString("language", "zh_CN");

        DatabaseType type = "mysql".equalsIgnoreCase(c.getString("database.type", "sqlite"))
                ? DatabaseType.MYSQL : DatabaseType.SQLITE;

        String sqliteFile = c.getString("database.sqlite.file", "accounts.db");
        SqliteSettings sqlite = new SqliteSettings(new File(dataFolder, sqliteFile));

        MySqlSettings mysql = new MySqlSettings(
                c.getString("database.mysql.host", "127.0.0.1"),
                c.getInt("database.mysql.port", 3306),
                c.getString("database.mysql.database", "kunxun_auth"),
                c.getString("database.mysql.username", "root"),
                mysqlPassword.value(),
                c.getString("database.mysql.table-prefix", "kunxun_"),
                c.getBoolean("database.mysql.use-ssl", false),
                c.getString("database.mysql.parameters", ""),
                Math.max(1, c.getInt("database.mysql.pool-size", 4)));

        LegacyMode legacyMode;
        try {
            legacyMode = LegacyMode.valueOf(
                    c.getString("pre-join.legacy-client-mode", "chat").trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            legacyMode = LegacyMode.CHAT;
        }

        PreJoinSettings preJoin = new PreJoinSettings(
                c.getBoolean("pre-join.enable", true),
                Math.max(10, c.getInt("pre-join.timeout-seconds", 300)),
                c.getBoolean("pre-join.allow-close-with-escape", false),
                c.getBoolean("pre-join.cancel-kicks", true),
                c.getInt("pre-join.dialog-min-protocol", 771),
                c.getBoolean("pre-join.assume-dialog-capable-without-viaversion", true),
                legacyMode);

        LoginSettings login = new LoginSettings(
                Math.max(10, c.getInt("login.timeout-seconds", 120)),
                Math.max(1, c.getInt("login.max-failed-attempts", 5)),
                Math.max(0, c.getInt("login.lockout-minutes", 10)),
                Math.max(0, c.getInt("login.session-minutes", 0)),
                Math.max(4, c.getInt("login.min-password-length", 6)),
                Math.max(8, c.getInt("login.max-password-length", 64)));

        RegisterSettings register = new RegisterSettings(
                c.getBoolean("register.allow-registration", true),
                c.getBoolean("register.require-email-verification", true),
                Math.max(1, c.getInt("register.code-expire-minutes", 10)),
                Math.max(1, c.getInt("register.code-max-attempts", 5)),
                Math.max(0, c.getInt("register.code-resend-cooldown-seconds", 60)),
                Math.max(0, c.getInt("register.max-registrations-per-ip-per-hour", 3)),
                Math.max(0, c.getInt("register.max-codes-per-ip-per-hour", 10)),
                Math.max(0, c.getInt("register.max-accounts-per-email", 1)),
                lowerList(c.getStringList("register.email-blacklist-domains")),
                lowerList(c.getStringList("register.email-whitelist-domains")));

        PasswordSettings password = new PasswordSettings(
                Math.max(10000, c.getInt("password.pbkdf2-iterations", 210000)));

        SecretStore.Credential mailAccount = secrets.mailAccount(c.getString("mail.account", ""));
        SecretStore.Credential mailPassword = secrets.mailPassword(c.getString("mail.password", ""));
        warnIfInConfig(plugin, "邮箱授权码", "mail.password", mailPassword);

        MailSettings mail = new MailSettings(
                c.getBoolean("mail.enable", true),
                c.getString("mail.host", "smtp.qq.com"),
                c.getInt("mail.port", 587),
                c.getBoolean("mail.starttls", true),
                c.getBoolean("mail.ssl", false),
                mailAccount.value(),
                mailPassword.value(),
                c.getString("mail.sender-name", "Minecraft Server"),
                c.getString("mail.subject", "Minecraft 服务器登录验证码"),
                Math.max(1000, c.getInt("mail.connection-timeout-ms", 10000)),
                c.getString("mail.template-file", "email-template.html"),
                c.getString("mail.server-name", "Minecraft Server"));

        plugin.getLogger().info("[KunxunAuth] 发件账号来源=" + mailAccount.describe()
                + " · 邮箱授权码来源=" + mailPassword.describe());

        MiscSettings misc = new MiscSettings(
                c.getString("misc.welcome-message", ""),
                c.getBoolean("misc.hide-unauthenticated-from-others", false),
                c.getBoolean("misc.log-verification-codes", false),
                Math.max(0, c.getInt("misc.max-connections-per-ip", 5)),
                c.getBoolean("misc.mask-player-ip", true),
                Math.max(1, c.getInt("misc.admin-reset-grant-minutes", 15)));

        DeviceSettings device = new DeviceSettings(
                c.getBoolean("device.enable", true),
                resolveServerId(plugin, c.getString("device.server-id", "")),
                Math.max(1, c.getInt("device.max-devices-per-account", 3)),
                Math.max(1, c.getInt("device.challenge-timeout-seconds", 3)),
                Math.max(5, c.getInt("device.bind-prompt-seconds", 20)),
                c.getBoolean("device.show-bind-prompt", true),
                c.getBoolean("device.revoke-on-password-change", true));

        return new AuthConfig(language, type, sqlite, mysql, preJoin, login, register, password, mail, misc,
                device);
    }

    /** 留空的 server-id 会落到这个文件里长期复用 */
    private static final String DEVICE_ID_FILE = "device-server-id.txt";

    /** 生成 server-id 用；这个值参与签名，猜中即等于可跨服重放，不能用可预测的随机源 */
    private static final SecureRandom SERVER_ID_RANDOM = new SecureRandom();

    /**
     * 服务器设备标识：config.yml 里填了就用填的，留空则生成一个随机 ID 落到
     * {@code device-server-id.txt} 并长期复用。
     *
     * <p>这个值参与签名。它一旦变化，玩家手里<b>所有</b>已绑定设备都会验签失败，
     * 只能重新绑一遍 —— 所以必须落盘，而不是每次启动重新生成：否则重启一次就等于
     * 把所有设备绑定清零。多台服务器共用一个账号库时，各服要填不同的固定值，
     * 否则 A 服签出的应答可以被拿到 B 服重放。
     */
    private static String resolveServerId(JavaPlugin plugin, String configured) {
        String value = configured == null ? "" : configured.trim();
        if (!value.isEmpty()) {
            return value;
        }
        File file = new File(plugin.getDataFolder(), DEVICE_ID_FILE);
        try {
            if (file.isFile()) {
                String saved = Files.readString(file.toPath(), StandardCharsets.UTF_8).trim();
                if (!saved.isEmpty()) {
                    return saved;
                }
            }
            String generated = randomServerId();
            File parent = file.getParentFile();
            if (parent != null && !parent.exists() && !parent.mkdirs()) {
                plugin.getLogger().warning("[KunxunAuth] 无法创建插件目录，设备标识只能临时使用");
                return generated;
            }
            Files.writeString(file.toPath(), generated, StandardCharsets.UTF_8);
            plugin.getLogger().info("[KunxunAuth] 已生成服务器设备标识（" + DEVICE_ID_FILE
                    + "）。它参与设备签名，删掉它等于让所有已绑定设备失效。");
            return generated;
        } catch (IOException e) {
            // 只告警不阻断：设备免密降级为「每次启动换一个 ID」，密码登录不受影响
            plugin.getLogger().warning("[KunxunAuth] 读写 " + DEVICE_ID_FILE
                    + " 失败，本次启动将使用临时标识：" + e.getMessage());
            return randomServerId();
        }
    }

    private static String randomServerId() {
        byte[] raw = new byte[12];
        SERVER_ID_RANDOM.nextBytes(raw);
        return "srv-" + Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    }

    private static List<String> lowerList(List<String> input) {
        return input.stream()
                .map(value -> value == null ? "" : value.trim().toLowerCase(Locale.ROOT))
                .filter(value -> !value.isEmpty())
                .toList();
    }

    /**
     * config.yml 里还留着明文凭据时提醒管理员。
     *
     * <p>不是硬报错：老配置直接升级上来也不能炸服，但要把风险说清楚。
     */
    private static void warnIfInConfig(JavaPlugin plugin, String label, String path,
                                       SecretStore.Credential credential) {
        if (credential.source() != SecretStore.Source.CONFIG) {
            return;
        }
        plugin.getLogger().warning("[KunxunAuth] " + label + " 仍写在 config.yml 的 " + path
                + " —— 该文件会随插件被复制/备份/分发。请把它移到 " + SecretStore.FILE_NAME
                + " 或环境变量，并清空 config.yml 中的这一项。");
    }

    // ------------------------------------------------------------------ 访问

    public String language() {
        return language;
    }

    public DatabaseType databaseType() {
        return databaseType;
    }

    public SqliteSettings sqlite() {
        return sqlite;
    }

    public MySqlSettings mysql() {
        return mysql;
    }

    public PreJoinSettings preJoin() {
        return preJoin;
    }

    public LoginSettings login() {
        return login;
    }

    public RegisterSettings register() {
        return register;
    }

    public PasswordSettings password() {
        return password;
    }

    public MailSettings mail() {
        return mail;
    }

    public MiscSettings misc() {
        return misc;
    }

    public DeviceSettings device() {
        return device;
    }
}
