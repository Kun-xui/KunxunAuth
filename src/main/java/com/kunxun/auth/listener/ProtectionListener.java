package com.kunxun.auth.listener;

import com.kunxun.auth.config.AuthConfig;
import com.kunxun.auth.config.Messages;
import com.kunxun.auth.session.FreezeService;
import com.kunxun.auth.session.SessionManager;
import com.kunxun.auth.util.Text;
import io.papermc.paper.event.player.AsyncChatEvent;
import org.bukkit.Location;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.entity.EntityDamageByEntityEvent;
import org.bukkit.event.entity.EntityDamageEvent;
import org.bukkit.event.entity.EntityTargetLivingEntityEvent;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.inventory.InventoryDragEvent;
import org.bukkit.event.inventory.InventoryOpenEvent;
import org.bukkit.event.player.PlayerAttemptPickupItemEvent;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.player.PlayerDropItemEvent;
import org.bukkit.event.player.PlayerInteractAtEntityEvent;
import org.bukkit.event.player.PlayerInteractEntityEvent;
import org.bukkit.event.player.PlayerInteractEvent;
import org.bukkit.event.player.PlayerItemConsumeEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerMoveEvent;
import org.bukkit.event.player.PlayerPortalEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.event.player.PlayerSwapHandItemsEvent;

/**
 * 未认证玩家的行为封锁。
 *
 * <p>只对「已经进了世界但还没通过验证」的玩家生效（聊天降级路线）。
 * 走对话框的玩家在配置阶段就完成了验证，进世界时已是认证状态，不受影响。
 */
public final class ProtectionListener implements Listener {

    private static final String BYPASS_PERMISSION = "kunxunauth.bypass";

    private final AuthConfig config;
    private final Messages messages;
    private final SessionManager sessions;
    private final FreezeService freeze;

    public ProtectionListener(AuthConfig config, Messages messages, SessionManager sessions,
                              FreezeService freeze) {
        this.config = config;
        this.messages = messages;
        this.sessions = sessions;
        this.freeze = freeze;
    }

    private boolean locked(Player player) {
        return freeze.isFrozen(player.getUniqueId());
    }

    private boolean exempt(Player player) {
        return player.hasPermission(BYPASS_PERMISSION);
    }

    // ---------------------------------------------------------------- 生命周期

    @EventHandler(priority = EventPriority.MONITOR)
    public void onJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        if (sessions.isAuthenticated(player.getUniqueId())) {
            String welcome = config.misc().welcomeMessage();
            if (welcome != null && !welcome.isBlank()) {
                player.sendMessage(Text.of(welcome));
            }
            return;
        }
        if (exempt(player)) {
            sessions.authenticate(player.getUniqueId());
            return;
        }
        freeze.freeze(player);
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onQuit(PlayerQuitEvent event) {
        Player player = event.getPlayer();
        freeze.forget(player.getUniqueId());
        sessions.purge(player.getUniqueId());
    }

    // ---------------------------------------------------------------- 移动封锁

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onMove(PlayerMoveEvent event) {
        Player player = event.getPlayer();
        if (!locked(player)) {
            return;
        }
        Location from = event.getFrom();
        Location to = event.getTo();
        // 允许转头，禁止位移
        if (from.getX() != to.getX() || from.getY() != to.getY() || from.getZ() != to.getZ()) {
            event.setTo(from);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onPortal(PlayerPortalEvent event) {
        if (locked(event.getPlayer())) {
            event.setCancelled(true);
        }
    }

    // ---------------------------------------------------------------- 交互封锁

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onInteract(PlayerInteractEvent event) {
        if (locked(event.getPlayer())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onInteractEntity(PlayerInteractEntityEvent event) {
        if (locked(event.getPlayer())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onInteractAtEntity(PlayerInteractAtEntityEvent event) {
        if (locked(event.getPlayer())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onBreak(BlockBreakEvent event) {
        if (locked(event.getPlayer())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onPlace(BlockPlaceEvent event) {
        if (locked(event.getPlayer())) {
            event.setCancelled(true);
        }
    }

    // ---------------------------------------------------------------- 物品封锁

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onDrop(PlayerDropItemEvent event) {
        if (locked(event.getPlayer())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onPickup(PlayerAttemptPickupItemEvent event) {
        if (locked(event.getPlayer())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onSwapHands(PlayerSwapHandItemsEvent event) {
        if (locked(event.getPlayer())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onConsume(PlayerItemConsumeEvent event) {
        if (locked(event.getPlayer())) {
            event.setCancelled(true);
        }
    }

    // ---------------------------------------------------------------- 容器封锁

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onInventoryOpen(InventoryOpenEvent event) {
        if (event.getPlayer() instanceof Player player && locked(player)) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onInventoryClick(InventoryClickEvent event) {
        if (event.getWhoClicked() instanceof Player player && locked(player)) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onInventoryDrag(InventoryDragEvent event) {
        if (event.getWhoClicked() instanceof Player player && locked(player)) {
            event.setCancelled(true);
        }
    }

    // ---------------------------------------------------------------- 战斗封锁

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onDamageByEntity(EntityDamageByEntityEvent event) {
        if (event.getDamager() instanceof Player player && locked(player)) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onDamage(EntityDamageEvent event) {
        if (event.getEntity() instanceof Player player && locked(player)) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onTarget(EntityTargetLivingEntityEvent event) {
        if (event.getTarget() instanceof Player player && locked(player)) {
            event.setCancelled(true);
        }
    }

    // ------------------------------------------------------------ 聊天与命令

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onChat(AsyncChatEvent event) {
        Player player = event.getPlayer();
        if (!locked(player)) {
            return;
        }
        event.setCancelled(true);
        player.sendMessage(messages.get("chat.reminder"));
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onCommand(PlayerCommandPreprocessEvent event) {
        Player player = event.getPlayer();
        if (!locked(player)) {
            return;
        }
        if (freeze.isAllowedCommand(event.getMessage())) {
            return;
        }
        event.setCancelled(true);
        player.sendMessage(messages.get("chat.reminder"));
    }
}
