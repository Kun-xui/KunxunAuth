package com.kunxun.auth.command;

import com.kunxun.auth.config.AuthConfig;
import com.kunxun.auth.config.Messages;
import com.kunxun.auth.data.Account;
import com.kunxun.auth.session.AuthService;
import com.kunxun.auth.session.FreezeService;
import com.kunxun.auth.session.SessionManager;
import com.kunxun.auth.util.Emails;
import com.kunxun.auth.util.Text;
import com.kunxun.auth.util.VerificationCodes;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;

import java.sql.SQLException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 聊天降级路线使用的玩家命令：/register /verify /login /resetpassword。
 *
 * <p>JDBC 与 PBKDF2 都不能跑在主线程，所以命令体一律先丢到异步线程，
 * 需要碰实体状态（解冻、踢人）时再切回主线程。
 */
public final class PlayerAuthCommand implements CommandExecutor, TabCompleter {

    private static final long HOUR_MILLIS = 3_600_000L;

    private final Plugin plugin;
    private final AuthConfig config;
    private final Messages messages;
    private final AuthService authService;
    private final SessionManager sessions;
    private final FreezeService freeze;
    private final Logger logger;

    public PlayerAuthCommand(Plugin plugin, AuthConfig config, Messages messages, AuthService authService,
                             SessionManager sessions, FreezeService freeze, Logger logger) {
        this.plugin = plugin;
        this.config = config;
        this.messages = messages;
        this.authService = authService;
        this.sessions = sessions;
        this.freeze = freeze;
        this.logger = logger;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!(sender instanceof Player player)) {
            sender.sendMessage(messages.get("player-only"));
            return true;
        }
        switch (command.getName().toLowerCase(java.util.Locale.ROOT)) {
            case "register" -> register(player, args);
            case "verify" -> verify(player, args);
            case "login" -> login(player, args);
            case "resetpassword" -> resetPassword(player, args);
            default -> player.sendMessage(messages.get("unknown-command"));
        }
        return true;
    }

    // ================================================================ /register

    private void register(Player player, String[] args) {
        if (sessions.isAuthenticated(player.getUniqueId())) {
            player.sendMessage(messages.get("chat.already-authenticated"));
            return;
        }
        if (!config.register().allowRegistration()) {
            player.sendMessage(messages.get("kick.registration-disabled"));
            return;
        }
        if (!config.register().requireEmailVerification() || !authService.mailAvailable()) {
            player.sendMessage(messages.get("kick.need-register"));
            return;
        }
        if (args.length < 1) {
            player.sendMessage(messages.get("chat.register-usage"));
            sendAllowedDomainsHint(player);
            return;
        }
        String email = Emails.normalize(args[0]);
        String name = player.getName();
        String ip = addressOf(player);

        runAsync(() -> {
            String error = validateEmail(email);
            if (error != null) {
                send(player, error);
                return;
            }
            try {
                if (authService.repository().existsUsername(name)) {
                    send(player, messages.raw("chat.already-registered"));
                    return;
                }
            } catch (SQLException e) {
                logger.log(Level.SEVERE, "[KunxunAuth] 查询玩家名失败: " + name, e);
                send(player, messages.raw("dialog.error-internal"));
                return;
            }
            long cooldown = authService.codes().resendCooldownRemaining(
                    VerificationCodes.Purpose.REGISTER, email, config.register().resendCooldownSeconds());
            if (cooldown > 0) {
                send(player, messages.raw("dialog.error-resend-cooldown", "seconds", cooldown));
                return;
            }
            if (!authService.limiter().allow("code:" + ip,
                    config.register().maxCodesPerIpPerHour(), HOUR_MILLIS)) {
                send(player, messages.raw("dialog.error-rate-limited"));
                return;
            }
            authService.sendCodeAsync(VerificationCodes.Purpose.REGISTER, email, name)
                    .thenAccept(outcome -> runSync(() -> {
                        if (outcome == AuthService.SendOutcome.OK) {
                            sessions.pendingEmail(player.getUniqueId(), email,
                                    VerificationCodes.Purpose.REGISTER);
                            send(player, messages.raw("chat.register-code-sent",
                                    "email", Emails.mask(email),
                                    "minutes", config.register().codeExpireMinutes()));
                        } else {
                            send(player, messages.raw("dialog.error-mail-unavailable"));
                        }
                    }));
        });
    }

    // ================================================================== /verify

    private void verify(Player player, String[] args) {
        if (sessions.isAuthenticated(player.getUniqueId())) {
            player.sendMessage(messages.get("chat.already-authenticated"));
            return;
        }
        SessionManager.PendingEmail pending = sessions.pendingEmail(player.getUniqueId());
        if (pending == null) {
            player.sendMessage(messages.get("chat.verify-usage"));
            return;
        }
        if (args.length < 2) {
            player.sendMessage(messages.get("chat.verify-usage"));
            return;
        }
        String code = args[0];
        String password = args[1];
        String name = player.getName();
        String ip = addressOf(player);

        String passwordError = authService.checkPassword(password, password);
        if (passwordError != null) {
            player.sendMessage(Text.of(passwordError));
            return;
        }

        runAsync(() -> {
            VerificationCodes.Result result = authService.codes().verify(
                    pending.purpose(), pending.email(), code, config.register().codeMaxAttempts());
            if (!result.ok()) {
                send(player, codeError(result));
                return;
            }
            if (pending.purpose() == VerificationCodes.Purpose.RESET) {
                finishReset(player, pending.email(), password, ip);
            } else {
                finishRegister(player, pending.email(), password, name, ip);
            }
        });
    }

    private void finishRegister(Player player, String email, String password, String name, String ip) {
        if (!authService.limiter().allow("register:" + ip,
                config.register().maxRegistrationsPerIpPerHour(), HOUR_MILLIS)) {
            send(player, messages.raw("dialog.error-rate-limited"));
            return;
        }
        try {
            if (authService.repository().existsUsername(name)) {
                send(player, messages.raw("chat.already-registered"));
                return;
            }
            authService.repository().insert(name, email, authService.hasher().hash(password));
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[KunxunAuth] 创建账号失败: " + name, e);
            send(player, messages.raw("dialog.error-internal"));
            return;
        }
        authService.repository().audit(name, "REGISTER_CHAT", ip, Emails.mask(email));
        runSync(() -> {
            sessions.clearPendingEmail(player.getUniqueId());
            sessions.authenticate(player.getUniqueId());
            sessions.remember(player.getUniqueId(), ip, config.login().sessionMinutes());
            freeze.unfreeze(player);
            player.sendMessage(messages.get("chat.register-success", "email", Emails.mask(email)));
        });
    }

    private void finishReset(Player player, String email, String password, String ip) {
        try {
            Account account = authService.repository().findByEmail(email).orElse(null);
            if (account == null) {
                send(player, messages.raw("dialog.error-email-not-found"));
                return;
            }
            authService.repository().updatePassword(account.id(), authService.hasher().hash(password));
            authService.repository().audit(account.username(), "RESET_PASSWORD_CHAT", ip, Emails.mask(email));
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[KunxunAuth] 重置密码失败", e);
            send(player, messages.raw("dialog.error-internal"));
            return;
        }
        runSync(() -> {
            sessions.clearPendingEmail(player.getUniqueId());
            player.sendMessage(messages.get("chat.reset-success"));
        });
    }

    // =================================================================== /login

    private void login(Player player, String[] args) {
        if (sessions.isAuthenticated(player.getUniqueId())) {
            player.sendMessage(messages.get("chat.already-authenticated"));
            return;
        }
        if (args.length < 1) {
            player.sendMessage(messages.get("chat.login-usage"));
            return;
        }
        String password = args[0];
        String name = player.getName();
        String ip = addressOf(player);

        runAsync(() -> {
            Account account;
            try {
                account = authService.repository().findByUsername(name).orElse(null);
            } catch (SQLException e) {
                logger.log(Level.SEVERE, "[KunxunAuth] 查询账号失败: " + name, e);
                send(player, messages.raw("dialog.error-internal"));
                return;
            }
            if (account == null) {
                send(player, messages.raw("chat.not-registered"));
                return;
            }
            long now = System.currentTimeMillis();
            if (account.isLocked(now)) {
                send(player, messages.raw("dialog.error-account-locked",
                        "minutes", account.lockedMinutesLeft(now)));
                return;
            }
            if (!authService.hasher().verify(password, account.passwordHash())) {
                int attempts = account.failedAttempts() + 1;
                int max = config.login().maxFailedAttempts();
                long lockUntil = 0L;
                if (attempts >= max) {
                    lockUntil = now + config.login().lockoutMinutes() * 60_000L;
                    attempts = 0;
                }
                try {
                    authService.repository().updateFailedAttempts(account.id(), attempts, lockUntil);
                } catch (SQLException e) {
                    logger.log(Level.WARNING, "[KunxunAuth] 写入失败次数出错", e);
                }
                authService.repository().audit(name, "LOGIN_FAIL_LEGACY", ip, "attempts=" + attempts);
                if (lockUntil > 0) {
                    send(player, messages.raw("dialog.error-account-locked",
                            "minutes", config.login().lockoutMinutes()));
                } else {
                    send(player, messages.raw("dialog.error-password-wrong",
                            "remaining", Math.max(1, max - attempts)));
                }
                return;
            }
            try {
                authService.repository().updateLoginSuccess(account.id(), ip);
                if (authService.hasher().needsRehash(account.passwordHash())) {
                    authService.repository().updatePassword(account.id(), authService.hasher().hash(password));
                }
            } catch (SQLException e) {
                logger.log(Level.WARNING, "[KunxunAuth] 更新登录信息出错", e);
            }
            authService.repository().audit(name, "LOGIN_OK_LEGACY", ip, "");
            runSync(() -> {
                sessions.authenticate(player.getUniqueId());
                sessions.remember(player.getUniqueId(), ip, config.login().sessionMinutes());
                freeze.unfreeze(player);
                player.sendMessage(messages.get("chat.login-success"));
                String welcome = config.misc().welcomeMessage();
                if (welcome != null && !welcome.isBlank()) {
                    player.sendMessage(Text.of(welcome));
                }
            });
        });
    }

    // =========================================================== /resetpassword

    private void resetPassword(Player player, String[] args) {
        if (args.length < 1) {
            player.sendMessage(messages.get("chat.reset-usage"));
            return;
        }
        String email = Emails.normalize(args[0]);
        String name = player.getName();
        String ip = addressOf(player);

        runAsync(() -> {
            String error = validateEmail(email);
            if (error != null) {
                send(player, error);
                return;
            }
            // 邮箱有没有注册过，流程和提示都必须一样 —— 否则能被人拿来枚举账号
            boolean registered;
            try {
                registered = authService.repository().findByEmail(email).isPresent();
            } catch (SQLException e) {
                logger.log(Level.SEVERE, "[KunxunAuth] 按邮箱查询账号失败", e);
                send(player, messages.raw("dialog.error-internal"));
                return;
            }
            long cooldown = authService.codes().resendCooldownRemaining(
                    VerificationCodes.Purpose.RESET, email, config.register().resendCooldownSeconds());
            if (cooldown > 0) {
                send(player, messages.raw("dialog.error-resend-cooldown", "seconds", cooldown));
                return;
            }
            if (!authService.limiter().allow("code:" + ip,
                    config.register().maxCodesPerIpPerHour(), HOUR_MILLIS)) {
                send(player, messages.raw("dialog.error-rate-limited"));
                return;
            }
            if (!registered) {
                // 占位：签发验证码但不发信，同时登记待验证邮箱，让后续 /verify 的表现也一致
                authService.codes().issue(VerificationCodes.Purpose.RESET, email,
                        config.register().codeExpireMinutes());
                sessions.pendingEmail(player.getUniqueId(), email, VerificationCodes.Purpose.RESET);
                send(player, messages.raw("chat.reset-code-sent-neutral",
                        "email", Emails.mask(email),
                        "minutes", config.register().codeExpireMinutes()));
                return;
            }
            authService.sendCodeAsync(VerificationCodes.Purpose.RESET, email, name)
                    .thenAccept(outcome -> runSync(() -> {
                        if (outcome == AuthService.SendOutcome.OK) {
                            sessions.pendingEmail(player.getUniqueId(), email,
                                    VerificationCodes.Purpose.RESET);
                            send(player, messages.raw("chat.reset-code-sent",
                                    "email", Emails.mask(email),
                                    "minutes", config.register().codeExpireMinutes()));
                        } else {
                            send(player, messages.raw("dialog.error-mail-unavailable"));
                        }
                    }));
        });
    }

    // ================================================================= 工具

    private String validateEmail(String email) {
        if (email.isEmpty()) {
            return messages.raw("dialog.error-email-empty");
        }
        if (!Emails.isValid(email)) {
            return messages.raw("dialog.error-email-invalid");
        }
        return authService.checkDomain(email);
    }

    /** 配置了白名单时，把可用域名一并告诉玩家，省得他一个个试 */
    private void sendAllowedDomainsHint(Player player) {
        if (!authService.dialogs().hasAllowedDomains()) {
            return;
        }
        player.sendMessage(messages.get("chat.register-whitelist-hint",
                "domains", authService.dialogs().allowedDomainsText()));
    }

    private String codeError(VerificationCodes.Result result) {
        return switch (result.status()) {
            case MISSING -> messages.raw("dialog.error-code-required");
            case EXPIRED -> messages.raw("dialog.error-code-expired");
            case TOO_MANY -> messages.raw("dialog.error-code-too-many");
            case WRONG -> messages.raw("dialog.error-code-wrong", "remaining", result.remainingAttempts());
            case OK -> messages.raw("chat.reset-success");
        };
    }

    /**
     * 密码校验失败时 checkPassword 返回的已经是填好占位符的文本，
     * 这里原样发给玩家即可。
     */
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
        if (args.length == 1 && "resetpassword".equalsIgnoreCase(command.getName())) {
            return List.of("<邮箱>");
        }
        return List.of();
    }
}
