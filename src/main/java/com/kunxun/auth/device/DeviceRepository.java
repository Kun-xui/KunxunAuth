package com.kunxun.auth.device;

import com.kunxun.auth.data.Database;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * 设备表读写。全是阻塞式 JDBC，调用方需自行放在异步线程里。
 *
 * <p>吊销 = 直接把这一行删掉。留一个 {@code revoked} 标记看着更「温柔」，
 * 但那样每一条验签路径都得记得带上 {@code AND revoked = 0}，
 * 漏一处就是一个长期后门；删掉之后，不存在的公钥自然就验不过。
 */
public final class DeviceRepository {

    private static final String COLUMNS =
            "id, public_key, username, device_name, created_at, last_seen_at, last_ip, device_fingerprint";

    private final Database database;

    public DeviceRepository(Database database) {
        this.database = database;
    }

    private String devices() {
        return database.table("devices");
    }

    // ------------------------------------------------------------------ 查询

    public Optional<DeviceRecord> findByPublicKey(String publicKey) throws SQLException {
        if (publicKey == null || publicKey.isEmpty()) {
            return Optional.empty();
        }
        String sql = "SELECT " + COLUMNS + " FROM " + devices() + " WHERE public_key = ?";
        return database.query(connection -> {
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setString(1, publicKey);
                try (ResultSet rs = statement.executeQuery()) {
                    return rs.next() ? Optional.of(map(rs)) : Optional.<DeviceRecord>empty();
                }
            }
        });
    }

    public List<DeviceRecord> listByUsername(String username) throws SQLException {
        String sql = "SELECT " + COLUMNS + " FROM " + devices()
                + " WHERE username_lower = ? ORDER BY id ASC";
        return database.query(connection -> {
            List<DeviceRecord> result = new ArrayList<>();
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setString(1, normalize(username));
                try (ResultSet rs = statement.executeQuery()) {
                    while (rs.next()) {
                        result.add(map(rs));
                    }
                }
            }
            return result;
        });
    }

    public int countByUsername(String username) throws SQLException {
        String sql = "SELECT COUNT(*) FROM " + devices() + " WHERE username_lower = ?";
        return database.query(connection -> {
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setString(1, normalize(username));
                try (ResultSet rs = statement.executeQuery()) {
                    return rs.next() ? rs.getInt(1) : 0;
                }
            }
        });
    }

    public long count() throws SQLException {
        return database.query(connection -> {
            try (PreparedStatement statement =
                         connection.prepareStatement("SELECT COUNT(*) FROM " + devices());
                 ResultSet rs = statement.executeQuery()) {
                return rs.next() ? rs.getLong(1) : 0L;
            }
        });
    }

    // ------------------------------------------------------------------ 写入

    /**
     * 绑定一台设备。
     *
     * <p>公钥上有唯一约束，所以「同一台设备被两个账号抢绑」这件事由数据库兜住，
     * 应用层的 count 检查只负责给出友好提示。
     *
     * @param fingerprint 客户端上报的硬件指纹摘要；v1 老模组没有这一项，传空串
     * @return true = 插入成功；false = 这把公钥已经绑过了
     */
    public boolean bind(String username, String publicKey, String deviceName, String fingerprint, String ip)
            throws SQLException {
        String sql = "INSERT INTO " + devices()
                + " (public_key, username, username_lower, device_name, created_at, last_seen_at, last_ip,"
                + " device_fingerprint) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
        long now = System.currentTimeMillis();
        try {
            database.query(connection -> {
                try (PreparedStatement statement = connection.prepareStatement(sql)) {
                    statement.setString(1, publicKey);
                    statement.setString(2, username);
                    statement.setString(3, normalize(username));
                    statement.setString(4, limit(deviceName, DeviceProtocol.MAX_DEVICE_NAME));
                    statement.setLong(5, now);
                    statement.setLong(6, now);
                    statement.setString(7, limit(ip, 45));
                    statement.setString(8, fingerprintOf(fingerprint));
                    return statement.executeUpdate();
                }
            });
            return true;
        } catch (SQLException e) {
            if (com.kunxun.auth.data.AccountRepository.isUniqueViolation(e)) {
                return false;
            }
            throw e;
        }
    }

    /**
     * 补记 / 覆盖一台设备的指纹。
     *
     * <p>用在「这台设备本来没有指纹记录」的补登上：老模组（v1 应答）绑定的设备
     * 指纹栏是空的，玩家后来升级到新模组，第一次带指纹登录时把这一栏补上，
     * 之后就能走指纹校验。已经存过指纹时不会被改写 —— 那属于「换机器」，
     * 由 {@code DeviceService} 明确吊销后重新绑定，而不是悄悄换掉证据。
     *
     * @return true = 确实更新了一行
     */
    public boolean fillFingerprintIfMissing(String publicKey, String fingerprint) throws SQLException {
        if (publicKey == null || publicKey.isEmpty()) {
            return false;
        }
        String value = fingerprintOf(fingerprint);
        if (value.isEmpty()) {
            return false;
        }
        String sql = "UPDATE " + devices() + " SET device_fingerprint = ?"
                + " WHERE public_key = ? AND (device_fingerprint IS NULL OR device_fingerprint = '')";
        return database.query(connection -> {
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setString(1, value);
                statement.setString(2, publicKey);
                return statement.executeUpdate() > 0;
            }
        });
    }

    /** 按公钥直接删一行，不分账号（调用方已经确认过归属时使用） */
    public boolean deleteByPublicKey(String publicKey) throws SQLException {
        String sql = "DELETE FROM " + devices() + " WHERE public_key = ?";
        return database.query(connection -> {
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setString(1, publicKey);
                return statement.executeUpdate() > 0;
            }
        });
    }

    /** 删掉一台设备（吊销）。返回是否真的删掉了 */
    public boolean revoke(String publicKey) throws SQLException {
        return deleteByPublicKey(publicKey);
    }

    /**
     * 只允许玩家删自己的设备。
     *
     * <p>带 {@code username_lower} 条件不是为了「顺手」，而是防止把别人的公钥
     * 拼进请求里就能吊销别人的设备。
     */
    public boolean revokeOwned(String username, String publicKey) throws SQLException {
        String sql = "DELETE FROM " + devices() + " WHERE public_key = ? AND username_lower = ?";
        return database.query(connection -> {
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setString(1, publicKey);
                statement.setString(2, normalize(username));
                return statement.executeUpdate() > 0;
            }
        });
    }

    /** 一键吊销某个账号的全部设备（改密 / 账号被盗后的第一处置动作） */
    public int revokeAll(String username) throws SQLException {
        String sql = "DELETE FROM " + devices() + " WHERE username_lower = ?";
        return database.query(connection -> {
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setString(1, normalize(username));
                return statement.executeUpdate();
            }
        });
    }

    /** 记录这台设备最后一次免密登录的时间和 IP */
    public void touch(String publicKey, String ip) {
        String sql = "UPDATE " + devices() + " SET last_seen_at = ?, last_ip = ? WHERE public_key = ?";
        try {
            database.query(connection -> {
                try (PreparedStatement statement = connection.prepareStatement(sql)) {
                    statement.setLong(1, System.currentTimeMillis());
                    statement.setString(2, limit(ip, 45));
                    statement.setString(3, publicKey);
                    return statement.executeUpdate();
                }
            });
        } catch (SQLException e) {
            // 只是刷新一下时间戳，失败不影响本次登录
        }
    }

    /** 删除账号时顺手清掉它的设备，避免备份表恢复了账号但设备表里留着孤儿行 */
    public int removeForDeletedAccount(String username) {
        try {
            return revokeAll(username);
        } catch (SQLException e) {
            return 0;
        }
    }

    // ------------------------------------------------------------------ 内部

    private static DeviceRecord map(ResultSet rs) throws SQLException {
        return new DeviceRecord(
                rs.getLong("id"),
                rs.getString("public_key"),
                rs.getString("username"),
                rs.getString("device_name"),
                rs.getLong("created_at"),
                rs.getLong("last_seen_at"),
                rs.getString("last_ip"),
                rs.getString("device_fingerprint") == null ? "" : rs.getString("device_fingerprint"));
    }

    private static String fingerprintOf(String fingerprint) {
        return limit(DeviceProtocol.normalizeFingerprint(fingerprint), DeviceProtocol.MAX_FINGERPRINT);
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    private static String limit(String value, int max) {
        if (value == null) {
            return "";
        }
        return value.length() <= max ? value : value.substring(0, max);
    }
}
