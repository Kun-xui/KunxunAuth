package com.kunxun.auth.command;

import com.kunxun.auth.KunxunAuthPlugin;
import com.kunxun.auth.config.Messages;
import com.kunxun.auth.device.DeviceRecord;
import com.kunxun.auth.device.DeviceService;
import com.kunxun.auth.util.Text;
import net.kyori.adventure.text.Component;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * 玩家自助设备管理：{@code /kunxundevice list} 与 {@code /kunxundevice remove <序号|前缀>}。
 *
 * <p>为什么必须给玩家一条自己动手的路：绑定上限就那么几个，换了电脑不删掉旧的，
 * 新机器就绑不上；而找管理员删设备要等到有人在线上，是最容易被拖成「算了不用了」的一步。
 *
 * <p><b>只认自己的设备。</b> 查询按玩家名过滤，删除走
 * {@code revokeOwned(username, publicKey)}（SQL 里带 {@code username_lower} 条件）。
 * 就算有人把别人的公钥前缀拼进参数，也只会得到「没找到」——
 * 判定权在数据库那一层，不在命令解析这一层。
 */
public final class DeviceCommand implements CommandExecutor, TabCompleter {

    private static final DateTimeFormatter TIME_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");

    private final Plugin plugin;
    private final KunxunAuthPlugin authPlugin;

    public DeviceCommand(KunxunAuthPlugin plugin) {
        this.authPlugin = plugin;
        this.plugin = plugin;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        Messages messages = authPlugin.messages();
        if (!(sender instanceof Player player)) {
            sender.sendMessage(messages.get("player-only"));
            return true;
        }
        if (!authPlugin.config().device().enable()) {
            player.sendMessage(messages.get("device.disabled"));
            return true;
        }
        if (!player.hasPermission("kunxunauth.device")) {
            player.sendMessage(messages.get("no-permission"));
            return true;
        }
        if (!authPlugin.sessions().isAuthenticated(player.getUniqueId())) {
            // 没通过验证的人连自己有几台设备都不该知道 —— 这也是一道防止探测的闸门
            player.sendMessage(messages.get("device.not-authenticated"));
            return true;
        }
        if (args.length == 0) {
            list(player);
            return true;
        }
        switch (args[0].toLowerCase(Locale.ROOT)) {
            case "list" -> list(player);
            case "remove", "delete", "unbind" -> remove(player, args);
            default -> player.sendMessage(messages.get("device.unknown-subcommand"));
        }
        return true;
    }

    // ------------------------------------------------------------------- list

    private void list(Player player) {
        String name = player.getName();
        runAsync(() -> {
            List<DeviceRecord> records = authPlugin.devices().list(name);
            int max = authPlugin.config().device().maxDevicesPerAccount();
            Messages messages = authPlugin.messages();

            List<Component> lines = new ArrayList<>();
            lines.add(messages.plain("device.list-header",
                    "player", name, "bound", records.size(), "max", max));
            if (records.isEmpty()) {
                lines.add(messages.plain("device.list-empty"));
            } else {
                for (int i = 0; i < records.size(); i++) {
                    DeviceRecord record = records.get(i);
                    lines.add(messages.plain("device.list-line",
                            "index", i + 1,
                            "key", record.keyPrefix(),
                            "name", record.displayName(),
                            "last", formatTime(record.lastSeenAt())));
                }
                lines.add(messages.plain("device.list-usage"));
            }
            runSync(() -> lines.forEach(player::sendMessage));
        });
    }

    // ----------------------------------------------------------------- remove

    private void remove(Player player, String[] args) {
        Messages messages = authPlugin.messages();
        if (args.length < 2) {
            player.sendMessage(messages.get("device.remove-usage"));
            return;
        }
        String target = args[1].trim();
        String name = player.getName();

        runAsync(() -> {
            List<DeviceRecord> records = authPlugin.devices().list(name);
            if (records.isEmpty()) {
                send(player, messages.raw("device.list-empty"));
                return;
            }
            DeviceRecord match = resolve(records, target);
            if (match == null) {
                // 「没找到」和「匹配到多台」都归到这里，提示里带上原始输入方便玩家改
                send(player, messages.raw("device.remove-not-found", "target", target));
                return;
            }

            DeviceService service = authPlugin.devices();
            if (!service.revokeOwned(name, match.publicKey())) {
                send(player, messages.raw("device.remove-failed"));
                return;
            }
            authPlugin.repository().audit(name, "DEVICE_REVOKE_SELF", addressOf(player),
                    "device=" + match.displayName());
            int remaining = Math.max(0, records.size() - 1);
            send(player, messages.raw("device.remove-ok",
                    "name", match.displayName(), "remaining", remaining));
        });
    }

    /**
     * 把玩家输入的「序号或前缀」解成一台设备。
     *
     * <p>先按序号解：列表里就带着序号，玩家照抄最省事。解不出来再按公钥前缀匹配 ——
     * 前缀撞车（12 个字符刚好一样，概率极低但不是零）时故意返回 null 让人用序号，
     * 而不是随便挑一台删掉。
     */
    private static DeviceRecord resolve(List<DeviceRecord> records, String target) {
        try {
            int index = Integer.parseInt(target);
            if (index >= 1 && index <= records.size()) {
                return records.get(index - 1);
            }
            return null;
        } catch (NumberFormatException ignored) {
            // 不是序号，走前缀匹配
        }
        String needle = target.toLowerCase(Locale.ROOT);
        DeviceRecord found = null;
        for (DeviceRecord record : records) {
            if (record.publicKey() != null && record.publicKey().toLowerCase(Locale.ROOT).startsWith(needle)) {
                if (found != null) {
                    return null;
                }
                found = record;
            }
        }
        return found;
    }

    // ------------------------------------------------------------------- 工具

    private static String formatTime(long millis) {
        if (millis <= 0) {
            return "从未";
        }
        return TIME_FORMAT.format(Instant.ofEpochMilli(millis).atZone(ZoneId.systemDefault()));
    }

    private void send(Player player, String legacyText) {
        runSync(() -> player.sendMessage(Text.of(legacyText)));
    }

    private void runAsync(Runnable task) {
        plugin.getServer().getScheduler().runTaskAsynchronously(plugin, task);
    }

    private void runSync(Runnable task) {
        if (plugin.getServer().isPrimaryThread()) {
            task.run();
        } else {
            plugin.getServer().getScheduler().runTask(plugin, task);
        }
    }

    private static String addressOf(Player player) {
        try {
            var address = player.getAddress();
            if (address != null && address.getAddress() != null) {
                return address.getAddress().getHostAddress();
            }
        } catch (RuntimeException ignored) {
            // 掉线竞态
        }
        return "unknown";
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        if (args.length == 1) {
            return List.of("list", "remove");
        }
        if (args.length == 2 && "remove".equalsIgnoreCase(args[0])) {
            return List.of("<序号或公钥前缀>");
        }
        return List.of();
    }
}
