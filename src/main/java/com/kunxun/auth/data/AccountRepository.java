package com.kunxun.auth.data;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLIntegrityConstraintViolationException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * 账号表读写。全部方法都是阻塞式 JDBC，调用方需自行放在异步线程里。
 */
public final class AccountRepository {

    private final Database database;

    public AccountRepository(Database database) {
        this.database = database;
    }

    private String accounts() {
        return database.table("accounts");
    }

    private String audit() {
        return database.table("audit");
    }

    private String backups() {
        return database.table("account_backups");
    }

    private static final String COLUMNS =
            "id, username, email, password_hash, registered_at, last_login_at, last_ip, failed_attempts, locked_until";

    // ------------------------------------------------------------------ 查询

    public Optional<Account> findByUsername(String username) throws SQLException {
        String sql = "SELECT " + COLUMNS + " FROM " + accounts() + " WHERE username_lower = ?";
        return one(sql, normalize(username));
    }

    public Optional<Account> findByEmail(String email) throws SQLException {
        String sql = "SELECT " + COLUMNS + " FROM " + accounts() + " WHERE email_lower = ?";
        return one(sql, normalize(email));
    }

    public boolean existsUsername(String username) throws SQLException {
        return exists("SELECT 1 FROM " + accounts() + " WHERE username_lower = ?", normalize(username));
    }

    public boolean existsEmail(String email) throws SQLException {
        return exists("SELECT 1 FROM " + accounts() + " WHERE email_lower = ?", normalize(email));
    }

    public int countAccountsByEmail(String email) throws SQLException {
        String sql = "SELECT COUNT(*) FROM " + accounts() + " WHERE email_lower = ?";
        return database.query(connection -> {
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setString(1, normalize(email));
                try (ResultSet rs = statement.executeQuery()) {
                    return rs.next() ? rs.getInt(1) : 0;
                }
            }
        });
    }

    public long count() throws SQLException {
        return database.query(connection -> {
            try (PreparedStatement statement = connection.prepareStatement("SELECT COUNT(*) FROM " + accounts());
                 ResultSet rs = statement.executeQuery()) {
                return rs.next() ? rs.getLong(1) : 0L;
            }
        });
    }

    /** 最近 N 条审计记录，格式：时间戳|玩家|动作|IP|详情 */
    public List<String> recentAudit(int limit) throws SQLException {
        String sql = "SELECT ts, username, action, ip, detail FROM " + audit() + " ORDER BY id DESC LIMIT ?";
        return database.query(connection -> {
            List<String> result = new ArrayList<>();
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setInt(1, Math.max(1, limit));
                try (ResultSet rs = statement.executeQuery()) {
                    while (rs.next()) {
                        result.add(rs.getLong(1) + "|" + rs.getString(2) + "|" + rs.getString(3)
                                + "|" + rs.getString(4) + "|" + rs.getString(5));
                    }
                }
            }
            return result;
        });
    }

    // ------------------------------------------------------------------ 写入

    /** 插入新账号，返回自增主键 */
    public long insert(String username, String email, String passwordHash) throws SQLException {
        String sql = "INSERT INTO " + accounts()
                + " (username, username_lower, email, email_lower, password_hash, registered_at,"
                + " last_login_at, last_ip, failed_attempts, locked_until)"
                + " VALUES (?, ?, ?, ?, ?, ?, 0, '', 0, 0)";
        long now = System.currentTimeMillis();
        return database.query(connection -> {
            try (PreparedStatement statement = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
                statement.setString(1, username);
                statement.setString(2, normalize(username));
                statement.setString(3, email);
                statement.setString(4, normalize(email));
                statement.setString(5, passwordHash);
                statement.setLong(6, now);
                statement.executeUpdate();
                try (ResultSet keys = statement.getGeneratedKeys()) {
                    return keys.next() ? keys.getLong(1) : -1L;
                }
            }
        });
    }

    public void updateLoginSuccess(long id, String ip) throws SQLException {
        String sql = "UPDATE " + accounts()
                + " SET last_login_at = ?, last_ip = ?, failed_attempts = 0, locked_until = 0 WHERE id = ?";
        long now = System.currentTimeMillis();
        database.query(connection -> {
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setLong(1, now);
                statement.setString(2, ip == null ? "" : ip);
                statement.setLong(3, id);
                return statement.executeUpdate();
            }
        });
    }

    public void updateFailedAttempts(long id, int attempts, long lockedUntil) throws SQLException {
        String sql = "UPDATE " + accounts() + " SET failed_attempts = ?, locked_until = ? WHERE id = ?";
        database.query(connection -> {
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setInt(1, attempts);
                statement.setLong(2, lockedUntil);
                statement.setLong(3, id);
                return statement.executeUpdate();
            }
        });
    }

    public void updatePassword(long id, String passwordHash) throws SQLException {
        String sql = "UPDATE " + accounts()
                + " SET password_hash = ?, failed_attempts = 0, locked_until = 0 WHERE id = ?";
        database.query(connection -> {
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setString(1, passwordHash);
                statement.setLong(2, id);
                return statement.executeUpdate();
            }
        });
    }

    /** 重置密码同时换绑邮箱（找回密码时邮箱不会变，保留此方法便于扩展） */
    public void updateEmail(long id, String email) throws SQLException {
        String sql = "UPDATE " + accounts() + " SET email = ?, email_lower = ? WHERE id = ?";
        database.query(connection -> {
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setString(1, email);
                statement.setString(2, normalize(email));
                statement.setLong(3, id);
                return statement.executeUpdate();
            }
        });
    }

    public boolean delete(String username) throws SQLException {
        String sql = "DELETE FROM " + accounts() + " WHERE username_lower = ?";
        return database.query(connection -> {
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setString(1, normalize(username));
                return statement.executeUpdate() > 0;
            }
        });
    }

    // ------------------------------------------------------------ 软删除 / 恢复

    /**
     * 备份后删除：先把整行抄进 {@code account_backups}，再删账号。
     *
     * <p>{@code /kunxunauth unregister} 是把手滑就能毁掉一个玩家存档的操作，
     * 所以这里不给「不可逆删除」这条路。备份表只在管理员显式清理时才需要动，
     * 平时它就是一个安静的后悔药。
     *
     * @return true = 确实删掉了一个账号
     */
    public boolean deleteWithBackup(String username, String deletedBy) throws SQLException {
        String key = normalize(username);
        Account account = findByUsername(username).orElse(null);
        if (account == null) {
            return false;
        }
        String insert = "INSERT INTO " + backups() + " (ts, deleted_by, username, username_lower,"
                + " email, password_hash, registered_at, last_login_at, last_ip,"
                + " failed_attempts, locked_until, restored) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)";
        String delete = "DELETE FROM " + accounts() + " WHERE username_lower = ?";
        return database.query(connection -> {
            boolean originalAutoCommit = connection.getAutoCommit();
            connection.setAutoCommit(false);
            try {
                try (PreparedStatement statement = connection.prepareStatement(insert)) {
                    statement.setLong(1, System.currentTimeMillis());
                    statement.setString(2, limit(deletedBy, 32));
                    statement.setString(3, account.username());
                    statement.setString(4, key);
                    statement.setString(5, account.email());
                    statement.setString(6, account.passwordHash());
                    statement.setLong(7, account.registeredAt());
                    statement.setLong(8, account.lastLoginAt());
                    statement.setString(9, account.lastIp() == null ? "" : account.lastIp());
                    statement.setInt(10, account.failedAttempts());
                    statement.setLong(11, account.lockedUntil());
                    statement.executeUpdate();
                }
                int removed;
                try (PreparedStatement statement = connection.prepareStatement(delete)) {
                    statement.setString(1, key);
                    removed = statement.executeUpdate();
                }
                connection.commit();
                return removed > 0;
            } catch (SQLException e) {
                connection.rollback();
                throw e;
            } finally {
                connection.setAutoCommit(originalAutoCommit);
            }
        });
    }

    /**
     * 从最近的备份里把账号恢复回来。
     *
     * @return true = 恢复成功；false = 没有可用备份或玩家名已被占用
     */
    public boolean restoreLatest(String username) throws SQLException {
        String key = normalize(username);
        String select = "SELECT username, email, password_hash, registered_at, last_login_at,"
                + " last_ip, failed_attempts, locked_until FROM " + backups()
                + " WHERE username_lower = ? AND restored = 0 ORDER BY id DESC";
        String insert = "INSERT INTO " + accounts() + " (username, username_lower, email,"
                + " email_lower, password_hash, registered_at, last_login_at, last_ip,"
                + " failed_attempts, locked_until) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        return database.query(connection -> {
            if (existsUsername(username)) {
                return false;
            }
            String[] row = null;
            long backupId = 0L;
            try (PreparedStatement statement = connection.prepareStatement(select)) {
                statement.setString(1, key);
                try (ResultSet rs = statement.executeQuery()) {
                    if (rs.next()) {
                        backupId = rs.getLong("id");
                        row = new String[]{
                                rs.getString("username"),
                                rs.getString("email"),
                                rs.getString("password_hash"),
                                String.valueOf(rs.getLong("registered_at")),
                                String.valueOf(rs.getLong("last_login_at")),
                                rs.getString("last_ip") == null ? "" : rs.getString("last_ip"),
                                String.valueOf(rs.getInt("failed_attempts")),
                                String.valueOf(rs.getLong("locked_until"))
                        };
                    }
                }
            }
            if (row == null) {
                return false;
            }
            boolean originalAutoCommit = connection.getAutoCommit();
            connection.setAutoCommit(false);
            try {
                try (PreparedStatement statement = connection.prepareStatement(insert)) {
                    statement.setString(1, row[0]);
                    statement.setString(2, normalize(row[0]));
                    statement.setString(3, row[1]);
                    statement.setString(4, normalize(row[1]));
                    statement.setString(5, row[2]);
                    statement.setLong(6, Long.parseLong(row[3]));
                    statement.setLong(7, Long.parseLong(row[4]));
                    statement.setString(8, row[5]);
                    statement.setInt(9, Integer.parseInt(row[6]));
                    statement.setLong(10, Long.parseLong(row[7]));
                    statement.executeUpdate();
                }
                if (backupId > 0) {
                    String mark = "UPDATE " + backups() + " SET restored = 1 WHERE id = ?";
                    try (PreparedStatement statement = connection.prepareStatement(mark)) {
                        statement.setLong(1, backupId);
                        statement.executeUpdate();
                    }
                }
                connection.commit();
                return true;
            } catch (SQLException e) {
                connection.rollback();
                throw e;
            } finally {
                connection.setAutoCommit(originalAutoCommit);
            }
        });
    }

    public void audit(String username, String action, String ip, String detail) {
        String sql = "INSERT INTO " + audit() + " (ts, username, action, ip, detail) VALUES (?, ?, ?, ?, ?)";
        try {
            database.query(connection -> {
                try (PreparedStatement statement = connection.prepareStatement(sql)) {
                    statement.setLong(1, System.currentTimeMillis());
                    statement.setString(2, limit(username, 16));
                    statement.setString(3, limit(action, 32));
                    statement.setString(4, limit(ip, 45));
                    statement.setString(5, limit(detail, 255));
                    return statement.executeUpdate();
                }
            });
        } catch (SQLException e) {
            // 审计失败不能影响主流程
        }
    }

    // ------------------------------------------------------------------ 内部

    private Optional<Account> one(String sql, String parameter) throws SQLException {
        return database.query(connection -> {
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setString(1, parameter);
                try (ResultSet rs = statement.executeQuery()) {
                    return rs.next() ? Optional.of(map(rs)) : Optional.<Account>empty();
                }
            }
        });
    }

    private boolean exists(String sql, String parameter) throws SQLException {
        return database.query(connection -> {
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setString(1, parameter);
                try (ResultSet rs = statement.executeQuery()) {
                    return rs.next();
                }
            }
        });
    }

    private static Account map(ResultSet rs) throws SQLException {
        return new Account(
                rs.getLong("id"),
                rs.getString("username"),
                rs.getString("email"),
                rs.getString("password_hash"),
                rs.getLong("registered_at"),
                rs.getLong("last_login_at"),
                rs.getString("last_ip"),
                rs.getInt("failed_attempts"),
                rs.getLong("locked_until"));
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    /**
     * 判断异常是不是唯一约束冲突（{@code username_lower} 或 {@code email_lower} 撞车）。
     *
     * <p>两种后端的判定方式不一样，所以不靠英文报错文本做匹配：
     * SQLite 的 SQLState 是 {@code 23000}、错误码 19（CONSTRAINT）；
     * MySQL 的 SQLState 同样是 {@code 23000}、错误码 1062（ER_DUP_ENTRY）。
     * 只要链条上任意一层是完整性约束异常就算命中。
     */
    public static boolean isUniqueViolation(SQLException error) {
        for (Throwable t = error; t != null; t = t.getCause()) {
            if (t instanceof SQLIntegrityConstraintViolationException) {
                return true;
            }
            if (t instanceof SQLException sql) {
                String state = sql.getSQLState();
                if (state != null && state.startsWith("23")) {
                    return true;
                }
                if (sql.getErrorCode() == 1062 || sql.getErrorCode() == 19) {
                    return true;
                }
            }
        }
        return false;
    }

    private static String limit(String value, int max) {
        if (value == null) {
            return "";
        }
        return value.length() <= max ? value : value.substring(0, max);
    }

    /** 暴露底层连接给需要事务的调用方 */
    public Database database() {
        return database;
    }

    /** 供子类/测试使用的原始连接入口 */
    public Connection rawConnection() throws SQLException {
        return database.borrow();
    }
}
