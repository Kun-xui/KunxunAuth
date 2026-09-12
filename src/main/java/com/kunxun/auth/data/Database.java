package com.kunxun.auth.data;

import com.kunxun.auth.config.AuthConfig;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

/**
 * 轻量数据库访问层。
 *
 * <p>支持两种后端：
 * <ul>
 *   <li>{@code sqlite} —— 内嵌单文件数据库，连接池固定为 1（SQLite 单写者模型），随插件目录走；</li>
 *   <li>{@code mysql}  —— 外部 MySQL / MariaDB，使用小型连接池。</li>
 * </ul>
 */
public final class Database implements AutoCloseable {

    public enum Type { SQLITE, MYSQL }

    private static final int BORROW_TIMEOUT_SECONDS = 15;

    private final Type type;
    private final String jdbcUrl;
    private final Properties properties;
    private final String tablePrefix;
    private final int poolSize;
    private final Logger logger;

    private final BlockingQueue<Connection> idle;
    private final AtomicInteger created = new AtomicInteger();
    private final Object createLock = new Object();
    private volatile boolean closed;

    private Database(Type type, String jdbcUrl, Properties properties, String tablePrefix,
                     int poolSize, Logger logger) {
        this.type = type;
        this.jdbcUrl = jdbcUrl;
        this.properties = properties;
        this.tablePrefix = tablePrefix;
        this.poolSize = poolSize;
        this.logger = logger;
        this.idle = new ArrayBlockingQueue<>(Math.max(1, poolSize));
    }

    public static Database sqlite(File file, String tablePrefix, Logger logger) throws SQLException {
        try {
            Class.forName("org.sqlite.JDBC");
        } catch (ClassNotFoundException e) {
            throw new SQLException("SQLite JDBC 驱动未加载，请确认 plugin.yml 的 libraries 已被 Paper 下载", e);
        }
        File parent = file.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new SQLException("无法创建数据库目录: " + parent);
        }
        Properties props = new Properties();
        props.setProperty("busy_timeout", "8000");
        Database database = new Database(Type.SQLITE, "jdbc:sqlite:" + file.getAbsolutePath(),
                props, tablePrefix, 1, logger);
        database.bootstrapSqlite();
        return database;
    }

    public static Database mysql(AuthConfig.MySqlSettings settings, Logger logger) throws SQLException {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            throw new SQLException("MySQL JDBC 驱动未加载，请确认 plugin.yml 的 libraries 已被 Paper 下载", e);
        }
        String parameters = settings.parameters() == null ? "" : settings.parameters();
        if (!parameters.isEmpty() && !parameters.startsWith("?")) {
            parameters = "?" + parameters;
        }
        String url = "jdbc:mysql://" + settings.host() + ":" + settings.port() + "/" + settings.database() + parameters;
        Properties props = new Properties();
        props.setProperty("user", settings.username());
        props.setProperty("password", settings.password());
        props.setProperty("useSSL", String.valueOf(settings.useSsl()));
        props.setProperty("connectTimeout", "8000");
        props.setProperty("socketTimeout", "20000");
        props.setProperty("autoReconnect", "true");
        props.setProperty("characterEncoding", "utf8");
        props.setProperty("serverTimezone", "Asia/Shanghai");
        return new Database(Type.MYSQL, url, props, settings.tablePrefix(),
                Math.max(1, settings.poolSize()), logger);
    }

    public Type type() {
        return type;
    }

    /** 给表名统一加前缀 */
    public String table(String name) {
        return tablePrefix + name;
    }

    public boolean isMysql() {
        return type == Type.MYSQL;
    }

    private void bootstrapSqlite() throws SQLException {
        // WAL 提升并发读性能；busy_timeout 已在 URL 参数设置
        try (Connection connection = open(); Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA journal_mode=WAL");
            statement.execute("PRAGMA synchronous=NORMAL");
            statement.execute("PRAGMA foreign_keys=ON");
        }
    }

    // ---------------------------------------------------------------- 建表

    public void initSchema(boolean uniqueEmail) throws SQLException {
        String accounts = table("accounts");
        String audit = table("audit");
        String backups = table("account_backups");
        String devices = table("devices");

        String accountsDdl;
        String auditDdl;
        String backupDdl;
        String devicesDdl;
        if (isMysql()) {
            accountsDdl = """
                    CREATE TABLE IF NOT EXISTS %s (
                      id            BIGINT       NOT NULL AUTO_INCREMENT,
                      username      VARCHAR(16)  NOT NULL,
                      username_lower VARCHAR(16) NOT NULL,
                      email         VARCHAR(254) NOT NULL,
                      email_lower   VARCHAR(254) NOT NULL,
                      password_hash VARCHAR(255) NOT NULL,
                      registered_at BIGINT       NOT NULL DEFAULT 0,
                      last_login_at BIGINT       NOT NULL DEFAULT 0,
                      last_ip       VARCHAR(45)  NOT NULL DEFAULT '',
                      failed_attempts INT        NOT NULL DEFAULT 0,
                      locked_until  BIGINT       NOT NULL DEFAULT 0,
                      PRIMARY KEY (id),
                      UNIQUE KEY uk_%susername_lower (username_lower),
                      KEY idx_%semail_lower (email_lower)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
                    """.formatted(accounts, tablePrefix, tablePrefix);
            auditDdl = """
                    CREATE TABLE IF NOT EXISTS %s (
                      id       BIGINT       NOT NULL AUTO_INCREMENT,
                      ts       BIGINT       NOT NULL DEFAULT 0,
                      username VARCHAR(16)  NOT NULL DEFAULT '',
                      action   VARCHAR(32)  NOT NULL DEFAULT '',
                      ip       VARCHAR(45)  NOT NULL DEFAULT '',
                      detail   VARCHAR(255) NOT NULL DEFAULT '',
                      PRIMARY KEY (id),
                      KEY idx_%sts (ts)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
                    """.formatted(audit, tablePrefix);
            backupDdl = """
                    CREATE TABLE IF NOT EXISTS %s (
                      id             BIGINT       NOT NULL AUTO_INCREMENT,
                      ts             BIGINT       NOT NULL DEFAULT 0,
                      deleted_by     VARCHAR(32)  NOT NULL DEFAULT '',
                      username       VARCHAR(16)  NOT NULL,
                      username_lower VARCHAR(16)  NOT NULL,
                      email          VARCHAR(254) NOT NULL,
                      password_hash  VARCHAR(255) NOT NULL,
                      registered_at  BIGINT       NOT NULL DEFAULT 0,
                      last_login_at  BIGINT       NOT NULL DEFAULT 0,
                      last_ip        VARCHAR(45)  NOT NULL DEFAULT '',
                      failed_attempts INT         NOT NULL DEFAULT 0,
                      locked_until   BIGINT       NOT NULL DEFAULT 0,
                      restored       TINYINT      NOT NULL DEFAULT 0,
                      PRIMARY KEY (id),
                      KEY idx_%susername_lower (username_lower)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
                    """.formatted(backups, tablePrefix);
            // 公钥是设备的主键：一台设备只能属于一个账号，所以 public_key 上必须有唯一约束。
            // 靠应用层「先查再插」挡不住并发绑定，唯一索引才是真正兜得住的那一层。
            devicesDdl = """
                    CREATE TABLE IF NOT EXISTS %s (
                      id             BIGINT       NOT NULL AUTO_INCREMENT,
                      public_key     VARCHAR(128) NOT NULL,
                      username       VARCHAR(16)  NOT NULL,
                      username_lower VARCHAR(16)  NOT NULL,
                      device_name    VARCHAR(64)  NOT NULL DEFAULT '',
                      created_at     BIGINT       NOT NULL DEFAULT 0,
                      last_seen_at   BIGINT       NOT NULL DEFAULT 0,
                      last_ip        VARCHAR(45)  NOT NULL DEFAULT '',
                      PRIMARY KEY (id),
                      UNIQUE KEY uk_%sdevice_public_key (public_key),
                      KEY idx_%sdevice_username_lower (username_lower)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
                    """.formatted(devices, tablePrefix, tablePrefix);
        } else {
            accountsDdl = """
                    CREATE TABLE IF NOT EXISTS %s (
                      id            INTEGER PRIMARY KEY AUTOINCREMENT,
                      username      TEXT    NOT NULL,
                      username_lower TEXT   NOT NULL UNIQUE,
                      email         TEXT    NOT NULL,
                      email_lower   TEXT    NOT NULL,
                      password_hash TEXT    NOT NULL,
                      registered_at INTEGER NOT NULL DEFAULT 0,
                      last_login_at INTEGER NOT NULL DEFAULT 0,
                      last_ip       TEXT    NOT NULL DEFAULT '',
                      failed_attempts INTEGER NOT NULL DEFAULT 0,
                      locked_until  INTEGER NOT NULL DEFAULT 0
                    )
                    """.formatted(accounts);
            auditDdl = """
                    CREATE TABLE IF NOT EXISTS %s (
                      id       INTEGER PRIMARY KEY AUTOINCREMENT,
                      ts       INTEGER NOT NULL DEFAULT 0,
                      username TEXT    NOT NULL DEFAULT '',
                      action   TEXT    NOT NULL DEFAULT '',
                      ip       TEXT    NOT NULL DEFAULT '',
                      detail   TEXT    NOT NULL DEFAULT ''
                    )
                    """.formatted(audit);
            backupDdl = """
                    CREATE TABLE IF NOT EXISTS %s (
                      id             INTEGER PRIMARY KEY AUTOINCREMENT,
                      ts             INTEGER NOT NULL DEFAULT 0,
                      deleted_by     TEXT    NOT NULL DEFAULT '',
                      username       TEXT    NOT NULL,
                      username_lower TEXT    NOT NULL,
                      email          TEXT    NOT NULL,
                      password_hash  TEXT    NOT NULL,
                      registered_at  INTEGER NOT NULL DEFAULT 0,
                      last_login_at  INTEGER NOT NULL DEFAULT 0,
                      last_ip        TEXT    NOT NULL DEFAULT '',
                      failed_attempts INTEGER NOT NULL DEFAULT 0,
                      locked_until   INTEGER NOT NULL DEFAULT 0,
                      restored       INTEGER NOT NULL DEFAULT 0
                    )
                    """.formatted(backups);
            devicesDdl = """
                    CREATE TABLE IF NOT EXISTS %s (
                      id             INTEGER PRIMARY KEY AUTOINCREMENT,
                      public_key     TEXT    NOT NULL UNIQUE,
                      username       TEXT    NOT NULL,
                      username_lower TEXT    NOT NULL,
                      device_name    TEXT    NOT NULL DEFAULT '',
                      created_at     INTEGER NOT NULL DEFAULT 0,
                      last_seen_at   INTEGER NOT NULL DEFAULT 0,
                      last_ip        TEXT    NOT NULL DEFAULT ''
                    )
                    """.formatted(devices);
        }

        query(connection -> {
            try (Statement statement = connection.createStatement()) {
                statement.executeUpdate(accountsDdl);
                statement.executeUpdate(auditDdl);
                statement.executeUpdate(backupDdl);
                statement.executeUpdate(devicesDdl);
                if (!isMysql()) {
                    // MySQL 的索引已在建表语句里声明，SQLite 需要单独补
                    statement.executeUpdate("CREATE INDEX IF NOT EXISTS idx_" + tablePrefix
                            + "email_lower ON " + accounts + " (email_lower)");
                    statement.executeUpdate("CREATE INDEX IF NOT EXISTS idx_" + tablePrefix
                            + "backup_username_lower ON " + backups + " (username_lower)");
                    statement.executeUpdate("CREATE INDEX IF NOT EXISTS idx_" + tablePrefix
                            + "device_username_lower ON " + devices + " (username_lower)");
                }
            }
            return null;
        });

        if (uniqueEmail) {
            ensureUniqueEmailIndex(accounts);
        } else {
            logger.info("[KunxunAuth] max-accounts-per-email != 1，未启用 email_lower 唯一索引"
                    + "（一个邮箱可否绑多个账号只由应用层判断）");
        }
    }

    /**
     * 给 {@code email_lower} 补唯一索引，把「一个邮箱只能绑一个账号」从应用层判断
     * 下沉成数据库约束。
     *
     * <p>应用层的 {@code checkEmailAvailable} 是「先查再插」，两个连接同时用同一个邮箱
     * 注册时中间存在竞态窗口（TOCTOU），唯一索引才是真正兜得住的那一层。
     *
     * <p>历史库里如果已经有重复邮箱，建索引会失败。这时只告警、不阻断启动，
     * 并把重复的记录打出来让人工处理 —— 老服升级上来不能让插件直接起不来。
     */
    private void ensureUniqueEmailIndex(String accounts) {
        String indexName = "uk_" + tablePrefix + "email_lower";
        String ddl = isMysql()
                ? "ALTER TABLE " + accounts + " ADD UNIQUE KEY " + indexName + " (email_lower)"
                : "CREATE UNIQUE INDEX IF NOT EXISTS " + indexName + " ON " + accounts + " (email_lower)";
        try {
            query(connection -> {
                try (Statement statement = connection.createStatement()) {
                    statement.executeUpdate(ddl);
                }
                return null;
            });
            logger.info("[KunxunAuth] email_lower 唯一索引已就绪（一个邮箱只能绑定一个账号）");
        } catch (SQLException e) {
            if (hasUniqueEmailIndex(accounts)) {
                // MySQL 重复执行 ALTER 会报 Duplicate key name，属于正常情况
                return;
            }
            logger.warning("[KunxunAuth] 创建 email_lower 唯一索引失败：" + e.getMessage());
            reportDuplicateEmails(accounts);
        }
    }

    /** 判断 email_lower 上是否已经存在唯一索引 */
    private boolean hasUniqueEmailIndex(String accounts) {
        try {
            return query(connection -> {
                try (ResultSet rs = connection.getMetaData()
                        .getIndexInfo(connection.getCatalog(), null, accounts, true, false)) {
                    while (rs.next()) {
                        String column = rs.getString("COLUMN_NAME");
                        if (column != null && column.equalsIgnoreCase("email_lower")) {
                            return true;
                        }
                    }
                }
                return false;
            });
        } catch (SQLException e) {
            return false;
        }
    }

    /** 把重复绑定的邮箱列到控制台，方便管理员决定保留哪个账号 */
    private void reportDuplicateEmails(String accounts) {
        String sql = "SELECT email_lower, COUNT(*) AS total FROM " + accounts
                + " GROUP BY email_lower HAVING COUNT(*) > 1";
        try {
            query(connection -> {
                try (Statement statement = connection.createStatement();
                     ResultSet rs = statement.executeQuery(sql)) {
                    int shown = 0;
                    while (rs.next() && shown < 20) {
                        logger.warning("[KunxunAuth] 邮箱重复绑定：" + rs.getString("email_lower")
                                + " → " + rs.getInt("total") + " 个账号");
                        shown++;
                    }
                    if (shown == 0) {
                        logger.warning("[KunxunAuth] 未查到重复邮箱，请检查数据库账号是否有建索引的权限");
                    }
                }
                return null;
            });
        } catch (SQLException e) {
            logger.warning("[KunxunAuth] 统计重复邮箱失败：" + e.getMessage());
        }
    }

    // -------------------------------------------------------------- 连接池

    private Connection open() throws SQLException {
        return DriverManager.getConnection(jdbcUrl, properties);
    }

    public Connection borrow() throws SQLException {
        if (closed) {
            throw new SQLException("数据库已关闭");
        }
        Connection connection = idle.poll();
        while (connection != null) {
            if (isUsable(connection)) {
                return connection;
            }
            quietClose(connection);
            created.decrementAndGet();
            connection = idle.poll();
        }

        synchronized (createLock) {
            if (created.get() < poolSize) {
                created.incrementAndGet();
                try {
                    return open();
                } catch (SQLException e) {
                    created.decrementAndGet();
                    throw e;
                }
            }
        }

        try {
            Connection waited = idle.poll(BORROW_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (waited == null) {
                throw new SQLException("等待数据库连接超时（池大小 " + poolSize + "）");
            }
            if (!isUsable(waited)) {
                quietClose(waited);
                created.decrementAndGet();
                return borrow();
            }
            return waited;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SQLException("获取数据库连接被中断", e);
        }
    }

    public void release(Connection connection) {
        if (connection == null) {
            return;
        }
        if (closed) {
            quietClose(connection);
            return;
        }
        if (!idle.offer(connection)) {
            quietClose(connection);
            created.decrementAndGet();
        }
    }

    private boolean isUsable(Connection connection) {
        try {
            return !connection.isClosed() && connection.isValid(2);
        } catch (SQLException e) {
            return false;
        }
    }

    private void quietClose(Connection connection) {
        try {
            connection.close();
        } catch (SQLException ignored) {
            // 忽略
        }
    }

    /**
     * 在一个连接里执行一段逻辑，自动归还连接。
     */
    public <T> T query(SqlFunction<T> action) throws SQLException {
        Connection connection = borrow();
        try {
            return action.apply(connection);
        } finally {
            release(connection);
        }
    }

    /** 带返回值的 JDBC 操作 */
    @FunctionalInterface
    public interface SqlFunction<T> {
        T apply(Connection connection) throws SQLException;
    }

    @Override
    public void close() {
        closed = true;
        Connection connection;
        while ((connection = idle.poll()) != null) {
            quietClose(connection);
        }
        logger.info("[KunxunAuth] 数据库连接已释放 (" + type + ")");
    }
}
