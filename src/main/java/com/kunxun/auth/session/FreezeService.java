package com.kunxun.auth.session;

import com.kunxun.auth.config.AuthConfig;
import com.kunxun.auth.config.Messages;
import com.kunxun.auth.util.Text;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;
import org.bukkit.scheduler.BukkitTask;

import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 未认证玩家的「冻结」状态管理。
 *
 * <p>仅用于聊天降级路线（旧客户端）：这类玩家没法在配置阶段答对话框，
 * 只能先进世界，然后用「禁止移动 + 禁止交互 + 定时提醒 + 超时踢出」兜底。
 *
 * <p>所有方法都必须在主线程调用。
 */
public final class FreezeService {

    private final Plugin plugin;
    private final AuthConfig config;
    private final Messages messages;

    private final Set<UUID> frozen = ConcurrentHashMap.newKeySet();
    private final Map<UUID, Long> deadlines = new ConcurrentHashMap<>();
    private final Map<UUID, Long> lastReminder = new ConcurrentHashMap<>();

    private BukkitTask ticker;

    public FreezeService(Plugin plugin, AuthConfig config, Messages messages) {
        this.plugin = plugin;
        this.config = config;
        this.messages = messages;
    }

    public boolean isFrozen(UUID playerId) {
        return frozen.contains(playerId);
    }

    public int frozenCount() {
        return frozen.size();
    }

    /** 冻结玩家 */
    public void freeze(Player player) {
        UUID id = player.getUniqueId();
        if (!frozen.add(id)) {
            return;
        }
        player.setInvulnerable(true);
        deadlines.put(id, System.currentTimeMillis() + config.login().timeoutSeconds() * 1000L);
        lastReminder.put(id, 0L);
        if (config.misc().hideUnauthenticatedFromOthers()) {
            applyVisibility(player, true);
        }
        ensureTicker();
    }

    /** 解除冻结 */
    public void unfreeze(Player player) {
        UUID id = player.getUniqueId();
        if (!frozen.remove(id)) {
            return;
        }
        deadlines.remove(id);
        lastReminder.remove(id);
        if (player.isOnline()) {
            player.setInvulnerable(false);
            if (config.misc().hideUnauthenticatedFromOthers()) {
                applyVisibility(player, false);
            }
        }
    }

    /** 玩家离线时的清理（没有 Player 实例可用） */
    public void forget(UUID playerId) {
        frozen.remove(playerId);
        deadlines.remove(playerId);
        lastReminder.remove(playerId);
    }

    private void applyVisibility(Player player, boolean hidden) {
        for (Player other : plugin.getServer().getOnlinePlayers()) {
            if (other.getUniqueId().equals(player.getUniqueId())) {
                continue;
            }
            if (hidden) {
                other.hidePlayer(plugin, player);
                player.hidePlayer(plugin, other);
            } else {
                other.showPlayer(plugin, player);
                player.showPlayer(plugin, other);
            }
        }
    }

    private void ensureTicker() {
        if (ticker != null && !ticker.isCancelled()) {
            return;
        }
        ticker = plugin.getServer().getScheduler().runTaskTimer(plugin, this::tick, 20L, 20L);
    }

    private void tick() {
        if (frozen.isEmpty()) {
            return;
        }
        long now = System.currentTimeMillis();
        long interval = Math.max(1, messages.intValue("chat.reminder-interval-seconds", 5)) * 1000L;
        for (UUID id : frozen) {
            Player player = plugin.getServer().getPlayer(id);
            if (player == null || !player.isOnline()) {
                forget(id);
                continue;
            }
            Long deadline = deadlines.get(id);
            if (deadline != null && now >= deadline) {
                player.kick(messages.get("kick.not-authenticated"));
                forget(id);
                continue;
            }
            Long last = lastReminder.get(id);
            if (last == null || now - last >= interval) {
                lastReminder.put(id, now);
                player.sendMessage(messages.get("chat.reminder"));
            }
        }
    }

    /** 给未认证玩家一句提示（例如命令用错时） */
    public void hint(Player player, String messageKey, Object... placeholders) {
        player.sendMessage(messages.get(messageKey, placeholders));
    }

    /** 开关插件时清理 */
    public void shutdown() {
        if (ticker != null) {
            ticker.cancel();
            ticker = null;
        }
        for (UUID id : frozen) {
            Player player = plugin.getServer().getPlayer(id);
            if (player != null && player.isOnline()) {
                player.setInvulnerable(false);
            }
        }
        frozen.clear();
        deadlines.clear();
        lastReminder.clear();
    }

    /** 未认证玩家被允许执行的命令白名单 */
    public boolean isAllowedCommand(String rawMessage) {
        String lower = rawMessage.toLowerCase(java.util.Locale.ROOT).trim();
        if (lower.startsWith("/")) {
            lower = lower.substring(1);
        }
        int space = lower.indexOf(' ');
        String label = space < 0 ? lower : lower.substring(0, space);
        int colon = label.indexOf(':');
        if (colon >= 0) {
            label = label.substring(colon + 1);
        }
        return switch (label) {
            case "login", "l", "register", "reg", "verify", "code", "resetpassword", "forgot", "resetpw" -> true;
            default -> false;
        };
    }

    /** 提醒文本预览（文档/调试用） */
    public String reminderPreview() {
        return Text.strip(messages.raw("chat.reminder"));
    }
}
