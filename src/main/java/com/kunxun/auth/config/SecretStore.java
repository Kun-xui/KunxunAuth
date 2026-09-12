package com.kunxun.auth.config;

import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.util.logging.Level;

/**
 * 敏感凭据仓库（SMTP 授权码 / 数据库密码）。
 *
 * <p>为什么不能写在 config.yml 里：config.yml 是打进 jar 的默认配置，任何拿到插件
 * 文件的人解压就能看到授权码；而且这个文件还会被复制、备份、丢进群里。所以凭据统一
 * 挪到插件目录下的 {@code secret.yml}，并且允许用环境变量覆盖（适合 Docker / 面板部署）：
 *
 * <pre>
 *   KUNXUN_MAIL_ACCOUNT     发件邮箱账号
 *   KUNXUN_MAIL_PASSWORD    邮箱授权码
 *   KUNXUN_MYSQL_PASSWORD   外部数据库密码
 * </pre>
 *
 * <p>取值优先级：<b>环境变量 &gt; secret.yml &gt; config.yml</b>。
 * 最后一级只是为了兼容老配置不炸服，一旦真的用上会打告警提醒迁移。
 */
public final class SecretStore {

    /** 凭据文件名（位于插件数据目录，不进 jar 的有效值） */
    public static final String FILE_NAME = "secret.yml";

    /** 环境变量名 */
    public static final String ENV_MAIL_ACCOUNT = "KUNXUN_MAIL_ACCOUNT";
    public static final String ENV_MAIL_PASSWORD = "KUNXUN_MAIL_PASSWORD";
    public static final String ENV_MYSQL_PASSWORD = "KUNXUN_MYSQL_PASSWORD";

    /** 凭据来源，用于日志和告警 */
    public enum Source {
        /** 环境变量 */
        ENV,
        /** secret.yml */
        FILE,
        /** config.yml（已不推荐） */
        CONFIG,
        /** 哪儿都没有 */
        MISSING
    }

    public record Credential(String value, Source source) {

        public boolean present() {
            return !value.isEmpty();
        }

        /** 面向日志的来源描述，不包含凭据本身 */
        public String describe() {
            return switch (source) {
                case ENV -> "环境变量";
                case FILE -> FILE_NAME;
                case CONFIG -> "config.yml";
                case MISSING -> "未配置";
            };
        }
    }

    private final YamlConfiguration file;

    private SecretStore(YamlConfiguration file) {
        this.file = file;
    }

    /**
     * 读取插件目录下的 {@code secret.yml}。
     *
     * <p>文件不存在时返回空配置（不报错）——此时全靠环境变量或 config.yml 兜底。
     */
    public static SecretStore load(JavaPlugin plugin) {
        File target = new File(plugin.getDataFolder(), FILE_NAME);
        if (!target.isFile()) {
            return new SecretStore(new YamlConfiguration());
        }
        YamlConfiguration yaml = new YamlConfiguration();
        try {
            yaml.load(target);
        } catch (Exception e) {
            plugin.getLogger().log(Level.WARNING,
                    "[KunxunAuth] " + FILE_NAME + " 解析失败，将忽略该文件：" + e.getMessage(), e);
            return new SecretStore(new YamlConfiguration());
        }
        return new SecretStore(yaml);
    }

    public Credential mailAccount(String configValue) {
        return pick(ENV_MAIL_ACCOUNT, "mail.account", configValue);
    }

    public Credential mailPassword(String configValue) {
        return pick(ENV_MAIL_PASSWORD, "mail.password", configValue);
    }

    public Credential mysqlPassword(String configValue) {
        return pick(ENV_MYSQL_PASSWORD, "mysql.password", configValue);
    }

    /**
     * 按 环境变量 → secret.yml → config.yml 的顺序取第一个非空值。
     *
     * @param envKey      环境变量名
     * @param secretPath  secret.yml 里的键路径
     * @param configValue config.yml 里的兜底值
     */
    private Credential pick(String envKey, String secretPath, String configValue) {
        String env = System.getenv(envKey);
        if (env != null && !env.isBlank()) {
            return new Credential(env.trim(), Source.ENV);
        }
        String fromFile = file.getString(secretPath);
        if (fromFile != null && !fromFile.isBlank()) {
            return new Credential(fromFile.trim(), Source.FILE);
        }
        if (configValue != null && !configValue.isBlank()) {
            return new Credential(configValue.trim(), Source.CONFIG);
        }
        return new Credential("", Source.MISSING);
    }
}
