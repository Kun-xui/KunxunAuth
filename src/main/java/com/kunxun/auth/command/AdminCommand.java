package com.kunxun.auth.command;

import com.kunxun.auth.KunxunAuthPlugin;
import com.kunxun.auth.config.AuthConfig;
import com.kunxun.auth.config.Messages;
import com.kunxun.auth.data.Account;
import com.kunxun.auth.device.DeviceRecord;
import com.kunxun.auth.util.Emails;
import net.kyori.adventure.text.Component;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import org.bukkit.entity.Player;

import java.security.SecureRandom;
import java.sql.SQLException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

/**
 * 管理命令 {@code /kunxunauth}。
 *
 * <p>配置与消息每次都从主类现取，这样 {@code /kunxunauth reload} 之后
 * 命令自己也会用上新的消息文件。
 */
public final class AdminCommand implements CommandExecutor, TabCompleter {

    private static final DateTimeFormatter TIME_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /** 生成重置码用；重置码是账号恢复凭据，不能用可预测的 Random */
    private static final SecureRandom RESET_RANDOM = new SecureRandom();

    private final KunxunAuthPlugin plugin;

    public AdminCommand(KunxunAuthPlugin plugin) {
        this.plugin = plugin;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        Messages messages = plugin.messages();
        if (!sender.hasPermission("kunxunauth.admin")) {
            sender.sendMessage(messages.get("no-permission"));
            return true;
        }
        if (args.length == 0) {
            sendHelp(sender);
            return true;
        }
        switch (args[0].toLowerCase(Locale.ROOT)) {
            case "help" -> sendHelp(sender);
            case "reload" -> reload(sender);
            case "stats" -> stats(sender);
            case "info" -> info(sender, args);
            case "unregister" -> unregister(sender, args);
            case "restore" -> restore(sender, args);
            case "setpassword" -> setPassword(sender, args);
            case "unlock" -> unlock(sender, args);
            case "devices" -> devices(sender, args);
            case "revokeall" -> revokeAll(sender, args);
            default -> sender.sendMessage(messages.get("unknown-command"));
        }
        return true;
    }

    private void sendHelp(CommandSender sender) {
        plugin.messages().lines("admin.help").forEach(sender::sendMessage);
    }

    // ------------------------------------------------------------------ reload

    private void reload(CommandSender sender) {
        if (plugin.getServer().isPrimaryThread()) {
            doReload(sender);
            return;
        }
        // 来自 RCON 等非主线程：切回主线程执行并等待完成。
        // 必须等待，否则命令输出会在 onCommand 返回后丢失（RCON 连接随即关闭输出通道）。
        CompletableFuture<Void> done = new CompletableFuture<>();
        plugin.getServer().getScheduler().runTask(plugin, () -> {
            try {
                doReload(sender);
            } finally {
                done.complete(null);
            }
        });
        try {
            done.get(30, TimeUnit.SECONDS);
        } catch (Exception e) {
            plugin.getLogger().log(Level.WARNING, "[KunxunAuth] 等待主线程重新加载超时", e);
        }
    }

    private void doReload(CommandSender sender) {
        try {
            plugin.reloadEverything();
            sender.sendMessage(plugin.messages().get("reload-success"));
        } catch (Throwable t) {
            plugin.getLogger().log(Level.SEVERE, "[KunxunAuth] 重新加载失败", t);
            sender.sendMessage(plugin.messages().get("reload-failed"));
        }
    }

    // ------------------------------------------------------------------- stats

    private void stats(CommandSender sender) {
        Messages messages = plugin.messages();
        long accounts;
        try {
            accounts = plugin.repository().count();
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "[KunxunAuth] 统计账号数失败", e);
            sender.sendMessage(messages.get("internal-error"));
            return;
        }
        AuthConfig config = plugin.config();
        List<Component> lines = new ArrayList<>();
        lines.add(messages.plain("admin.stats-header"));
        lines.add(statLine(messages, "数据库类型", config.databaseType().name().toLowerCase(Locale.ROOT)));
        lines.add(statLine(messages, "注册账号数", accounts));
        lines.add(statLine(messages, "已认证在线", plugin.sessions().authenticatedCount()));
        lines.add(statLine(messages, "冻结中玩家", plugin.freeze().frozenCount()));
        lines.add(statLine(messages, "配置阶段会话", plugin.sessions().configSessionCount()));
        lines.add(statLine(messages, "待验证验证码", plugin.codes().size()));
        lines.add(statLine(messages, "已绑定设备", plugin.devices().totalBound()));
        lines.add(statLine(messages, "邮件服务", plugin.mailAvailable() ? "可用" : "不可用"));
        lines.add(statLine(messages, "ViaVersion", plugin.capability().viaPresent() ? "已安装" : "未安装"));
        lines.forEach(sender::sendMessage);
    }

    private Component statLine(Messages messages, String key, Object value) {
        return messages.plain("admin.stats-line", "key", key, "value", value);
    }

    // -------------------------------------------------------------------- info

    private void info(CommandSender sender, String[] args) {
        Messages messages = plugin.messages();
        if (args.length < 2) {
            sender.sendMessage(messages.get("admin.usage-info"));
            return;
        }
        String name = args[1];
        Account account;
        try {
            account = plugin.repository().findByUsername(name).orElse(null);
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "[KunxunAuth] 查询账号失败: " + name, e);
            sender.sendMessage(messages.get("internal-error"));
            return;
        }
        if (account == null) {
            sender.sendMessage(messages.get("admin.player-not-found", "player", name));
            return;
        }
        List<Component> lines = new ArrayList<>();
        lines.add(messages.plain("admin.info-header", "player", account.username()));
        lines.add(messages.plain("admin.info-email", "email", Emails.mask(account.email())));
        lines.add(messages.plain("admin.info-registered", "time", formatTime(account.registeredAt())));
        lines.add(messages.plain("admin.info-last-login", "time", formatTime(account.lastLoginAt())));
        lines.add(messages.plain("admin.info-last-ip", "ip", displayIp(account.lastIp())));
        String locked = account.isLocked(System.currentTimeMillis())
                ? "已锁定（剩余 " + account.lockedMinutesLeft(System.currentTimeMillis()) + " 分钟）"
                : "正常";
        lines.add(messages.plain("admin.info-locked", "locked", locked));
        lines.forEach(sender::sendMessage);
    }

    // -------------------------------------------------------------- unregister

    /**
     * 删除账号。
     *
     * <p>要求显式加 {@code confirm} 才真的动手：这条命令只差一个字母就能
     * 抹掉别人的账号，而聊天框里打错字太常见了。不加 confirm 时先回显
     * 「即将删除谁」，让人有机会发现自己认错了人。
     */
    private void unregister(CommandSender sender, String[] args) {
        Messages messages = plugin.messages();
        if (args.length < 2) {
            sender.sendMessage(messages.get("admin.usage-unregister"));
            return;
        }
        String name = args[1];
        Account account;
        try {
            account = plugin.repository().findByUsername(name).orElse(null);
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "[KunxunAuth] 查询删除目标失败: " + name, e);
            sender.sendMessage(messages.get("internal-error"));
            return;
        }
        if (account == null) {
            sender.sendMessage(messages.get("admin.player-not-found", "player", name));
            return;
        }
        boolean confirmed = args.length >= 3 && "confirm".equalsIgnoreCase(args[2]);
        if (!confirmed) {
            sender.sendMessage(messages.get("admin.unregister-preview",
                    "player", account.username(),
                    "email", Emails.mask(account.email()),
                    "time", formatTime(account.registeredAt())));
            sender.sendMessage(messages.get("admin.unregister-confirm-hint", "player", account.username()));
            return;
        }
        try {
            plugin.repository().deleteWithBackup(account.username(), senderName(sender));
            plugin.repository().audit(senderName(sender), "ADMIN_UNREGISTER", "", account.username());
            // 账号没了，设备绑定必须一起清掉：否则同名账号被重新注册时，
            // 上一任号主手里那台设备仍然能免密登录到新号主的账号里。
            int dropped = plugin.devices().revokeAll(account.username());
            if (dropped > 0) {
                plugin.getLogger().info("[KunxunAuth] 删除账号 " + account.username()
                        + " 时连带清理了 " + dropped + " 台设备绑定");
            }
            sender.sendMessage(messages.get("admin.account-deleted", "player", account.username()));
            sender.sendMessage(messages.get("admin.unregister-undo-hint", "player", account.username()));
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "[KunxunAuth] 删除账号失败: " + name, e);
            sender.sendMessage(messages.get("internal-error"));
        }
    }

    // ----------------------------------------------------------------- restore

    /** 从最近一次删除备份里把账号捞回来 */
    private void restore(CommandSender sender, String[] args) {
        Messages messages = plugin.messages();
        if (args.length < 2) {
            sender.sendMessage(messages.get("admin.usage-restore"));
            return;
        }
        String name = args[1];
        try {
            if (plugin.repository().restoreLatest(name)) {
                plugin.repository().audit(senderName(sender), "ADMIN_RESTORE", "", name);
                sender.sendMessage(messages.get("admin.account-restored", "player", name));
            } else {
                sender.sendMessage(messages.get("admin.restore-none", "player", name));
            }
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "[KunxunAuth] 恢复账号失败: " + name, e);
            sender.sendMessage(messages.get("internal-error"));
        }
    }

    // ------------------------------------------------------------- setpassword

    /**
     * 签发一次性密码重置码。
     *
     * <p>以前这里是 {@code setpassword <玩家> <密码>}，明文密码会作为命令参数
     * 被服务端日志、RCON 日志、面板的命令历史原样记下来，等于把玩家的密码
     * 散播到一堆没人清理的文本里。现在改成只签发一个一次性码：码只回显给
     * 执行命令的人，玩家自己在登录界面把它换成新密码。
     */
    private void setPassword(CommandSender sender, String[] args) {
        Messages messages = plugin.messages();
        if (args.length < 2) {
            sender.sendMessage(messages.get("admin.usage-setpassword"));
            return;
        }
        if (args.length > 2) {
            // 防止有人习惯性沿用旧写法把密码贴上：直接拒绝，绝不让它落进日志
            sender.sendMessage(messages.get("admin.usage-setpassword"));
            sender.sendMessage(messages.get("admin.plaintext-password-refused"));
            return;
        }
        String name = args[1];
        try {
            Account account = plugin.repository().findByUsername(name).orElse(null);
            if (account == null) {
                sender.sendMessage(messages.get("admin.player-not-found", "player", name));
                return;
            }
            int minutes = plugin.config().misc().adminResetGrantMinutes();
            String code = generateResetCode();
            plugin.sessions().grantPasswordReset(account.username(), code, minutes);
            plugin.repository().audit(senderName(sender), "ADMIN_ISSUE_RESET_CODE", "", account.username());
            sender.sendMessage(messages.get("admin.reset-code-issued",
                    "player", account.username(), "code", code, "minutes", minutes));
            sender.sendMessage(messages.get("admin.reset-code-hint"));
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "[KunxunAuth] 签发重置码失败: " + name, e);
            sender.sendMessage(messages.get("internal-error"));
        }
    }

    /**
     * 生成 8 位重置码。
     *
     * <p>去掉了容易认错的 0/O/1/I，管理员口头念给玩家时不会听错。
     */
    private static String generateResetCode() {
        final char[] alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".toCharArray();
        StringBuilder sb = new StringBuilder(8);
        for (int i = 0; i < 8; i++) {
            sb.append(alphabet[RESET_RANDOM.nextInt(alphabet.length)]);
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------ unlock

    private void unlock(CommandSender sender, String[] args) {
        Messages messages = plugin.messages();
        if (args.length < 2) {
            sender.sendMessage(messages.get("admin.usage-unlock"));
            return;
        }
        String name = args[1];
        try {
            Account account = plugin.repository().findByUsername(name).orElse(null);
            if (account == null) {
                sender.sendMessage(messages.get("admin.player-not-found", "player", name));
                return;
            }
            plugin.repository().updateFailedAttempts(account.id(), 0, 0L);
            plugin.repository().audit(senderName(sender), "ADMIN_UNLOCK", "", name);
            sender.sendMessage(messages.get("admin.account-unlocked", "player", name));
        } catch (SQLException e) {
            plugin.getLogger().log(Level.SEVERE, "[KunxunAuth] 解除锁定失败: " + name, e);
            sender.sendMessage(messages.get("internal-error"));
        }
    }

    // --------------------------------------------------------------- devices

    /** 列出某个账号已绑定的设备，供管理员核对「这个账号到底有几台机器能免密进」 */
    private void devices(CommandSender sender, String[] args) {
        Messages messages = plugin.messages();
        if (args.length < 2) {
            sender.sendMessage(messages.get("admin.usage-devices"));
            return;
        }
        String name = args[1];
        List<DeviceRecord> records = plugin.devices().list(name);
        List<Component> lines = new ArrayList<>();
        lines.add(messages.plain("admin.devices-header", "player", name, "total", records.size()));
        if (records.isEmpty()) {
            lines.add(messages.plain("admin.devices-empty"));
        } else {
            for (DeviceRecord record : records) {
                lines.add(messages.plain("admin.devices-line",
                        "key", record.keyPrefix(),
                        "name", record.displayName(),
                        "bound", formatTime(record.createdAt()),
                        "last", formatTime(record.lastSeenAt()),
                        "ip", displayIp(record.lastIp())));
            }
        }
        lines.forEach(sender::sendMessage);
    }

    /**
     * 一键吊销某个账号的全部设备。
     *
     * <p>这是「账号疑似被盗」时的第一处置动作，要和改密一起做：只改密码而设备绑定
     * 还在，攻击者手里那台机器照样能免密进来。改密路径会自动调用同样的逻辑，
     * 这条命令是给「玩家密码没泄露但设备文件外流」这类情况的兜底。
     */
    private void revokeAll(CommandSender sender, String[] args) {
        Messages messages = plugin.messages();
        if (args.length < 2) {
            sender.sendMessage(messages.get("admin.usage-revokeall"));
            return;
        }
        String name = args[1];
        int revoked = plugin.devices().revokeAll(name);
        plugin.repository().audit(senderName(sender), "ADMIN_DEVICE_REVOKE_ALL", "", name + " count=" + revoked);
        if (revoked > 0) {
            sender.sendMessage(messages.get("admin.revokeall-done", "player", name, "count", revoked));
        } else {
            sender.sendMessage(messages.get("admin.revokeall-none", "player", name));
        }
    }

    // ------------------------------------------------------------------- 工具

    private static String senderName(CommandSender sender) {
        return sender instanceof Player player ? player.getName() : "CONSOLE";
    }

    /**
     * 管理输出里的 IP。
     *
     * <p>完整 IP 加上「这个玩家叫什么」就等于一份可以直接拿去做定位的资料，
     * 而管理员查 IP 通常只是想确认「是不是同一个人 / 是不是同一段网络」，
     * 网段足够了，所以默认打码，确需完整 IP 时把 misc.mask-player-ip 关掉。
     */
    private String displayIp(String ip) {
        if (ip == null || ip.isEmpty()) {
            return "未知";
        }
        return plugin.config().misc().maskPlayerIp() ? maskIp(ip) : ip;
    }

    /** IPv4 保留前两段，IPv6 保留前两组 */
    static String maskIp(String ip) {
        if (ip.indexOf(':') >= 0) {
            String[] parts = ip.split(":");
            if (parts.length >= 2) {
                return parts[0] + ":" + parts[1] + ":****";
            }
            return "****";
        }
        String[] parts = ip.split("\\.");
        if (parts.length == 4) {
            return parts[0] + "." + parts[1] + ".*.*";
        }
        return "***";
    }

    private static String formatTime(long millis) {
        if (millis <= 0) {
            return "从未";
        }
        return TIME_FORMAT.format(Instant.ofEpochMilli(millis).atZone(ZoneId.systemDefault()));
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        if (args.length == 1) {
            return List.of("help", "reload", "stats", "info", "unregister", "restore",
                    "setpassword", "unlock", "devices", "revokeall");
        }
        if (args.length == 2) {
            String sub = args[0].toLowerCase(Locale.ROOT);
            if (List.of("info", "unregister", "restore", "setpassword", "unlock",
                    "devices", "revokeall").contains(sub)) {
                return plugin.getServer().getOnlinePlayers().stream().map(Player::getName).toList();
            }
        }
        if (args.length == 3 && "unregister".equalsIgnoreCase(args[0])) {
            return List.of("confirm");
        }
        return List.of();
    }
}
