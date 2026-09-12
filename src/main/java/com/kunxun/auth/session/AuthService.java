package com.kunxun.auth.session;

import com.kunxun.auth.config.AuthConfig;
import com.kunxun.auth.config.Messages;
import com.kunxun.auth.data.Account;
import com.kunxun.auth.data.AccountRepository;
import com.kunxun.auth.device.ChallengeRegistry;
import com.kunxun.auth.device.DeviceService;
import com.kunxun.auth.dialog.AuthAction;
import com.kunxun.auth.dialog.DialogFactory;
import com.kunxun.auth.mail.MailService;
import com.kunxun.auth.util.Emails;
import com.kunxun.auth.util.PasswordHasher;
import com.kunxun.auth.util.RateLimiter;
import com.kunxun.auth.util.VerificationCodes;
import io.papermc.paper.connection.PlayerConfigurationConnection;
import io.papermc.paper.dialog.Dialog;
import io.papermc.paper.dialog.DialogResponseView;
import net.kyori.adventure.text.Component;

import java.sql.SQLException;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 认证业务逻辑：配置阶段的对话框状态机。
 *
 * <p>整个流程跑在 {@code AsyncPlayerConnectionConfigureEvent} 的处理线程上，
 * 该线程会被 {@link LoginSession} 的 future 阻塞，客户端因此停在
 * 「正在加入世界…」界面——这就是「进世界之前完成验证」的实现方式。
 *
 * <p>由于这里已经是异步线程，方法内部的 JDBC / PBKDF2 / 等待发信都是阻塞式直写，
 * 不需要再套一层线程池。
 */
public final class AuthService {

    /** 配置阶段流程的最终结论 */
    public record Decision(boolean allowed, Component kickMessage) {
        public static Decision allow() {
            return new Decision(true, null);
        }

        public static Decision deny(Component message) {
            return new Decision(false, message);
        }
    }

    private enum Mode {
        LOGIN, REGISTER_EMAIL, REGISTER_CODE, REGISTER_DIRECT, RESET_EMAIL, RESET_CODE,
        /** 管理员已签发一次性重置码，玩家直接在这里换新密码 */
        FORCE_RESET
    }

    /** 验证码发送结果 */
    public enum SendOutcome { OK, MAIL_DISABLED, MAIL_FAILED }

    /** 每 IP 的限流窗口长度 */
    private static final long HOUR_MILLIS = 3_600_000L;

    private final AuthConfig config;
    private final Messages messages;
    private final AccountRepository repository;
    private final PasswordHasher hasher;
    private final VerificationCodes codes;
    private final MailService mail;
    private final RateLimiter limiter;
    private final SessionManager sessions;
    private final DialogFactory dialogs;
    private final DeviceService devices;
    private final Logger logger;

    public AuthService(AuthConfig config, Messages messages, AccountRepository repository,
                       PasswordHasher hasher, VerificationCodes codes, MailService mail,
                       RateLimiter limiter, SessionManager sessions, DialogFactory dialogs,
                       DeviceService devices, Logger logger) {
        this.config = config;
        this.messages = messages;
        this.repository = repository;
        this.hasher = hasher;
        this.codes = codes;
        this.mail = mail;
        this.limiter = limiter;
        this.sessions = sessions;
        this.dialogs = dialogs;
        this.devices = devices;
        this.logger = logger;
    }

    // ==================================================================== 主流程

    /**
     * 阻塞式跑完整个预进服验证流程。
     *
     * @return allowed = 可以进世界；否则用 kickMessage 断开连接
     */
    public Decision runPreJoinDialogFlow(PlayerConfigurationConnection connection, LoginSession session) {
        String name = session.playerName();
        String ip = session.ip();

        Account account;
        try {
            account = repository.findByUsername(name).orElse(null);
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[KunxunAuth] 查询玩家账号失败: " + name, e);
            return Decision.deny(messages.get("dialog.error-internal"));
        }

        if (account != null && config.login().sessionMinutes() > 0
                && sessions.tryAutoLogin(session.playerId(), ip)) {
            // 会话保持命中：同一 IP 在有效期内重连免密
            repository.audit(name, "LOGIN_SESSION", ip, "");
            return Decision.allow();
        }

        boolean emailVerification = config.register().requireEmailVerification() && mail.available();

        Mode mode;
        if (account != null && sessions.passwordResetGrant(name) != null) {
            // 管理员签发了重置码：优先走改密，避免玩家拿旧密码反复试错被锁
            mode = Mode.FORCE_RESET;
        } else if (account != null) {
            mode = Mode.LOGIN;
        } else if (!config.register().allowRegistration()) {
            return Decision.deny(messages.get("kick.registration-disabled"));
        } else {
            mode = emailVerification ? Mode.REGISTER_EMAIL : Mode.REGISTER_DIRECT;
        }

        String error = null;
        String info = null;
        long deadline = System.currentTimeMillis() + config.preJoin().timeoutSeconds() * 1000L;

        // 设备挑战在这里就登记并发出去，但**不阻塞**：响应到不到、什么时候到，
        // 都由客户端自己的节奏决定，玩家的登录速度不该被一台没装模组的客户端拖住。
        ChallengeRegistry.Handshake handshake = null;
        DeviceService.Proof deviceProof = null;
        if (devices.enabled()) {
            handshake = devices.issue(connection, ChallengeRegistry.Purpose.LOGIN, name);
            if (mode == Mode.LOGIN && devices.hasAnyDevice(name)) {
                // 只有在账号名下确实绑过设备时，才值得停下来等那几秒：命中就是免密直进
                deviceProof = devices.await(connection, handshake);
                handshake = null;
                if (deviceProof != null && devices.isBoundTo(name, deviceProof.publicKey())) {
                    repository.audit(name, "LOGIN_DEVICE", ip,
                            "device=" + deviceProof.deviceName());
                    sessions.authenticate(session.playerId());
                    sessions.remember(session.playerId(), ip, config.login().sessionMinutes());
                    devices.touch(deviceProof.publicKey(), ip);
                    return Decision.allow();
                }
            }
        }

        while (true) {
            if (!connection.isConnected()) {
                return Decision.deny(null);
            }
            long remaining = deadline - System.currentTimeMillis();
            if (remaining <= 0) {
                return Decision.deny(messages.get("kick.timeout",
                        "seconds", config.preJoin().timeoutSeconds()));
            }

            Dialog dialog = switch (mode) {
                case LOGIN -> dialogs.login(error, info);
                case REGISTER_EMAIL -> dialogs.registerEmail(error, info);
                case REGISTER_CODE -> dialogs.registerCode(session.email(),
                        config.register().codeExpireMinutes(), error, info);
                case REGISTER_DIRECT -> dialogs.registerDirect(error, info);
                case RESET_EMAIL -> dialogs.resetEmail(error, info);
                case RESET_CODE -> dialogs.resetCode(session.email(),
                        config.register().codeExpireMinutes(), error, info);
                case FORCE_RESET -> dialogs.forceReset(name,
                        config.misc().adminResetGrantMinutes(), error, info);
            };
            error = null;
            info = null;

            ClickPayload click = await(connection, session, dialog, remaining);
            if (click == null) {
                if (!connection.isConnected()) {
                    return Decision.deny(null);
                }
                return Decision.deny(messages.get("kick.timeout",
                        "seconds", config.preJoin().timeoutSeconds()));
            }

            AuthAction action = AuthAction.byId(click.action());
            if (action == null) {
                continue;
            }

            switch (mode) {
                case LOGIN -> {
                    switch (action) {
                        case CANCEL -> {
                            return cancelDecision();
                        }
                        case LOGIN_FORGOT -> {
                            mode = Mode.RESET_EMAIL;
                        }
                        case LOGIN_SUBMIT -> {
                            LoginStep step = handleLoginSubmit(session, click);
                            switch (step.kind()) {
                                case SUCCESS -> {
                                    return finish(connection, session, name, ip, handshake, deviceProof);
                                }
                                case KICK -> {
                                    return Decision.deny(step.message());
                                }
                                case ERROR -> error = step.text();
                                case GONE -> {
                                    // 账号在验证期间被删除，退回归档
                                    repository.audit(name, "LOGIN_NO_ACCOUNT", ip, "");
                                    mode = emailVerification ? Mode.REGISTER_EMAIL : Mode.REGISTER_DIRECT;
                                    info = messages.raw("dialog.error-email-not-found");
                                }
                            }
                        }
                        default -> {
                            // 忽略不属于当前步骤的按钮
                        }
                    }
                }

                case REGISTER_EMAIL -> {
                    switch (action) {
                        case CANCEL -> {
                            return cancelDecision();
                        }
                        case SEND_CODE -> {
                            EmailStep step = handleEmailSubmit(session, click.input(AuthAction.INPUT_EMAIL),
                                    VerificationCodes.Purpose.REGISTER);
                            if (step.error() != null) {
                                error = step.error();
                            } else {
                                session.email(step.email());
                                mode = Mode.REGISTER_CODE;
                                info = messages.raw("dialog.info-code-sent");
                            }
                        }
                        default -> {
                        }
                    }
                }

                case REGISTER_CODE -> {
                    switch (action) {
                        case CANCEL -> {
                            codes.invalidate(VerificationCodes.Purpose.REGISTER, session.email());
                            return cancelDecision();
                        }
                        case REGISTER_RESEND -> {
                            SendOutcome outcome = resendCode(session, VerificationCodes.Purpose.REGISTER);
                            if (outcome == SendOutcome.OK) {
                                info = messages.raw("dialog.info-code-sent");
                            } else {
                                error = messages.raw("dialog.error-mail-unavailable");
                            }
                        }
                        case REGISTER_SUBMIT -> {
                            FinishStep step = handleRegisterSubmit(session, click);
                            switch (step.kind()) {
                                case SUCCESS -> {
                                    return finish(connection, session, name, ip, handshake, deviceProof);
                                }
                                case KICK -> {
                                    return Decision.deny(step.message());
                                }
                                case ERROR -> error = step.text();
                                case GONE -> mode = Mode.LOGIN;
                            }
                        }
                        default -> {
                        }
                    }
                }

                case REGISTER_DIRECT -> {
                    switch (action) {
                        case CANCEL -> {
                            return cancelDecision();
                        }
                        case REGISTER_DIRECT -> {
                            FinishStep step = handleDirectRegister(session, click);
                            switch (step.kind()) {
                                case SUCCESS -> {
                                    return finish(connection, session, name, ip, handshake, deviceProof);
                                }
                                case KICK -> {
                                    return Decision.deny(step.message());
                                }
                                case ERROR -> error = step.text();
                                case GONE -> mode = Mode.LOGIN;
                            }
                        }
                        default -> {
                        }
                    }
                }

                case RESET_EMAIL -> {
                    switch (action) {
                        case CANCEL -> {
                            return cancelDecision();
                        }
                        case BACK -> mode = Mode.LOGIN;
                        case RESET_SEND -> {
                            EmailStep step = handleEmailSubmit(session, click.input(AuthAction.INPUT_EMAIL),
                                    VerificationCodes.Purpose.RESET);
                            if (step.error() != null) {
                                error = step.error();
                            } else {
                                session.email(step.email());
                                mode = Mode.RESET_CODE;
                                // 中性措辞：无论邮箱是否注册过都显示同一句话，避免泄露账号是否存在
                                info = messages.raw("dialog.info-code-sent-neutral");
                            }
                        }
                        default -> {
                        }
                    }
                }

                case RESET_CODE -> {
                    switch (action) {
                        case CANCEL -> {
                            codes.invalidate(VerificationCodes.Purpose.RESET, session.email());
                            return cancelDecision();
                        }
                        case REGISTER_RESEND, RESET_RESEND -> {
                            SendOutcome outcome = resendCode(session, VerificationCodes.Purpose.RESET);
                            if (outcome == SendOutcome.OK) {
                                info = messages.raw("dialog.info-code-sent");
                            } else {
                                error = messages.raw("dialog.error-mail-unavailable");
                            }
                        }
                        case BACK -> mode = Mode.RESET_EMAIL;
                        case RESET_SUBMIT -> {
                            FinishStep step = handleResetSubmit(session, click);
                            switch (step.kind()) {
                                case SUCCESS -> {
                                    mode = Mode.LOGIN;
                                    info = messages.raw("chat.reset-success");
                                }
                                case KICK -> {
                                    return Decision.deny(step.message());
                                }
                                case ERROR -> error = step.text();
                                case GONE -> mode = Mode.RESET_EMAIL;
                            }
                        }
                        default -> {
                        }
                    }
                }
                case FORCE_RESET -> {
                    switch (action) {
                        case CANCEL -> {
                            return cancelDecision();
                        }
                        case FORCE_RESET -> {
                            FinishStep step = handleForceResetSubmit(session, click);
                            switch (step.kind()) {
                                case SUCCESS -> {
                                    // 改完密码直接放行进世界，不必再让玩家登一次
                                    return finish(connection, session, name, ip, handshake, deviceProof);
                                }
                                case KICK -> {
                                    return Decision.deny(step.message());
                                }
                                case ERROR -> error = step.text();
                                case GONE -> mode = Mode.LOGIN;
                            }
                        }
                        default -> {
                        }
                    }
                }
            }
        }
    }

    // ============================================================ 设备绑定

    /**
     * 验证通过之后的收尾：先问一句要不要绑定这台设备，再放人进世界。
     *
     * <p>绑定询问是「顺手一问」，不是一道关卡：无论玩家选了什么、无论设备最后绑没绑成，
     * 都不会改变「已经验证通过」这个结论 —— 所以这里永远返回 {@link Decision#allow()}。
     */
    private Decision finish(PlayerConfigurationConnection connection, LoginSession session,
                            String name, String ip,
                            ChallengeRegistry.Handshake handshake, DeviceService.Proof knownProof) {
        offerDeviceBind(connection, session, name, ip, handshake, knownProof);
        return Decision.allow();
    }

    /**
     * 登录 / 注册成功后询问是否绑定当前设备。
     *
     * <p>关键取舍：<b>客户端没应答就压根不弹这个框</b>。没有模组的玩家点「绑定本设备」
     * 只会得到一次没有任何反应的点击，那比不问更让人困惑。所以先确认这台客户端
     * 真的能对挑战签名（{@code handshake.future()} 已经完成），再问玩家。
     */
    private void offerDeviceBind(PlayerConfigurationConnection connection, LoginSession session,
                                 String name, String ip,
                                 ChallengeRegistry.Handshake handshake, DeviceService.Proof knownProof) {
        if (!devices.enabled() || !config.device().showBindPrompt()) {
            return;
        }
        AuthConfig.DeviceSettings settings = config.device();
        int bound = devices.count(name);
        if (bound >= settings.maxDevicesPerAccount()) {
            // 名额满了就别问了，问了也绑不上
            return;
        }

        DeviceService.Proof proof = knownProof;
        if (proof == null) {
            if (handshake == null || !handshake.future().isDone()) {
                return;
            }
            proof = devices.await(connection, handshake);
            if (proof == null) {
                return;
            }
        }
        if (devices.isBoundTo(name, proof.publicKey())) {
            // 这台设备本来就是这个账号的：免密登录已经走过了这条路，不必再问
            return;
        }

        ClickPayload click;
        try {
            CompletableFuture<ClickPayload> future = session.beginAwait();
            try {
                connection.getAudience().showDialog(dialogs.bindPrompt(
                        proof.deviceName(), bound, settings.maxDevicesPerAccount(), null));
                click = future.get(Math.max(1000L, settings.bindPromptSeconds() * 1000L),
                        TimeUnit.MILLISECONDS);
            } finally {
                session.endAwait();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return;
        } catch (ExecutionException | TimeoutException | CancellationException e) {
            // 玩家没点（去看别的窗口了）：当作不绑，不拦人
            return;
        } catch (RuntimeException e) {
            logger.log(Level.FINE, "[KunxunAuth] 设备绑定询问显示失败: " + e.getMessage(), e);
            return;
        }

        if (click == null || AuthAction.byId(click.action()) != AuthAction.DEVICE_BIND) {
            repository.audit(name, "DEVICE_BIND_SKIP", ip, "");
            return;
        }

        DeviceService.BindResult result = devices.bind(name, proof.publicKey(), proof.deviceName(), ip);
        repository.audit(name, result == DeviceService.BindResult.OK ? "DEVICE_BIND_OK" : "DEVICE_BIND_FAIL",
                ip, "device=" + proof.deviceName() + " result=" + result);
        if (result == DeviceService.BindResult.OK) {
            logger.info("[KunxunAuth] " + name + " 绑定了新设备「" + proof.deviceName()
                    + "」，现在共 " + devices.count(name) + " 台");
        } else if (result == DeviceService.BindResult.CONFLICT) {
            logger.warning("[KunxunAuth] 设备「" + proof.deviceName() + "」已绑在别的账号名下，拒绝 " + name);
        }
    }

    /**
     * 密码变了就把这个账号的全部设备一并吊销。
     *
     * <p>「改密」通常正是账号被盗后的第一处置动作；如果设备绑定还留着，攻击者
     * 手里那台机器照样能免密进去，等于白改。所以默认必须一起清掉，
     * 只留一个 {@code device.revoke-on-password-change} 开关给有特殊需要的服。
     *
     * @return 被吊销的设备台数
     */
    public int revokeDevicesOnPasswordChange(String username, String ip) {
        if (!config.device().enable() || !config.device().revokeOnPasswordChange()) {
            return 0;
        }
        int revoked = devices.revokeAll(username);
        if (revoked > 0) {
            repository.audit(username, "DEVICE_REVOKE_ALL", ip, "count=" + revoked);
            logger.info("[KunxunAuth] " + username + " 改密，已连带吊销 " + revoked + " 台设备");
        }
        return revoked;
    }

    // ============================================================ 各步骤处理

    /** 登录提交 */
    private LoginStep handleLoginSubmit(LoginSession session, ClickPayload click) {
        String password = click.raw(AuthAction.INPUT_PASSWORD);
        if (password.isEmpty()) {
            return LoginStep.error(messages.raw("dialog.error-password-empty"));
        }

        Account fresh;
        try {
            fresh = repository.findByUsername(session.playerName()).orElse(null);
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[KunxunAuth] 查询账号失败: " + session.playerName(), e);
            return LoginStep.error(messages.raw("dialog.error-internal"));
        }
        if (fresh == null) {
            return LoginStep.gone();
        }

        long now = System.currentTimeMillis();
        if (fresh.isLocked(now)) {
            return LoginStep.error(messages.raw("dialog.error-account-locked",
                    "minutes", fresh.lockedMinutesLeft(now)));
        }

        if (!hasher.verify(password, fresh.passwordHash())) {
            int attempts = fresh.failedAttempts() + 1;
            int max = config.login().maxFailedAttempts();
            long lockUntil = 0L;
            if (attempts >= max) {
                lockUntil = now + config.login().lockoutMinutes() * 60_000L;
                attempts = 0;
                logger.warning("[KunxunAuth] 账号 " + session.playerName() + " 连续密码错误 "
                        + max + " 次，已锁定 " + config.login().lockoutMinutes() + " 分钟");
            }
            try {
                repository.updateFailedAttempts(fresh.id(), attempts, lockUntil);
            } catch (SQLException e) {
                logger.log(Level.WARNING, "[KunxunAuth] 写入失败次数出错", e);
            }
            repository.audit(session.playerName(), "LOGIN_FAIL", session.ip(), "attempts=" + attempts);

            if (lockUntil > 0) {
                return LoginStep.error(messages.raw("dialog.error-account-locked",
                        "minutes", config.login().lockoutMinutes()));
            }
            return LoginStep.error(messages.raw("dialog.error-password-wrong",
                    "remaining", Math.max(1, max - attempts)));
        }

        try {
            repository.updateLoginSuccess(fresh.id(), session.ip());
            if (hasher.needsRehash(fresh.passwordHash())) {
                repository.updatePassword(fresh.id(), hasher.hash(password));
            }
        } catch (SQLException e) {
            logger.log(Level.WARNING, "[KunxunAuth] 更新登录信息出错", e);
        }
        repository.audit(session.playerName(), "LOGIN_OK", session.ip(), "");
        sessions.authenticate(session.playerId());
        sessions.remember(session.playerId(), session.ip(), config.login().sessionMinutes());
        return LoginStep.success();
    }

    /** 注册/找回的第 1 步：校验邮箱并验证码发信 */
    private EmailStep handleEmailSubmit(LoginSession session, String rawEmail, VerificationCodes.Purpose purpose) {
        String email = Emails.normalize(rawEmail);
        if (email.isEmpty()) {
            return EmailStep.error(messages.raw("dialog.error-email-empty"));
        }
        if (!Emails.isValid(email)) {
            return EmailStep.error(messages.raw("dialog.error-email-invalid"));
        }
        String domainError = checkDomain(email);
        if (domainError != null) {
            return EmailStep.error(domainError);
        }

        // deliver = 这封邮件是否真的发出去。
        // 找回密码时，邮箱没绑过账号就只占位不发信 —— 但「界面、提示、冷却、限流」
        // 必须和正常情况完全一样，否则攻击者能靠「到底发没发」把注册过的邮箱枚举出来。
        boolean deliver;
        if (purpose == VerificationCodes.Purpose.REGISTER) {
            String taken = checkEmailAvailable(email);
            if (taken != null) {
                return EmailStep.error(taken);
            }
            deliver = true;
        } else {
            deliver = existsAccount(email);
        }

        long cooldown = codes.resendCooldownRemaining(purpose, email,
                config.register().resendCooldownSeconds());
        if (cooldown > 0) {
            return EmailStep.error(messages.raw("dialog.error-resend-cooldown", "seconds", cooldown));
        }
        if (!limiter.allow("code:" + session.ip(),
                config.register().maxCodesPerIpPerHour(), HOUR_MILLIS)) {
            return EmailStep.error(messages.raw("dialog.error-rate-limited"));
        }

        if (!deliver) {
            // 占掉一个验证码位和冷却窗口，让两条路径的后续行为完全一致；只是不发信
            codes.issue(purpose, email, config.register().codeExpireMinutes());
            return EmailStep.ok(email);
        }

        SendOutcome outcome = sendCode(purpose, email, session.playerName());
        if (outcome != SendOutcome.OK) {
            return EmailStep.error(messages.raw("dialog.error-mail-unavailable"));
        }
        return EmailStep.ok(email);
    }

    /** 这个邮箱是否已经绑定了账号（只用于内部判断，不把结果告诉玩家） */
    private boolean existsAccount(String email) {
        try {
            return repository.findByEmail(email).isPresent();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[KunxunAuth] 按邮箱查询账号失败", e);
            return false;
        }
    }

    /** 注册第 2 步：校验验证码 + 建号 */
    private FinishStep handleRegisterSubmit(LoginSession session, ClickPayload click) {
        String email = session.email();
        String code = click.input(AuthAction.INPUT_CODE);
        if (code.isEmpty()) {
            return FinishStep.error(messages.raw("dialog.error-code-empty"));
        }
        String password = click.raw(AuthAction.INPUT_PASSWORD);
        String passwordError = checkPassword(password, click.raw(AuthAction.INPUT_PASSWORD_CONFIRM));
        if (passwordError != null) {
            return FinishStep.error(passwordError);
        }

        VerificationCodes.Result result = codes.verify(VerificationCodes.Purpose.REGISTER, email, code,
                config.register().codeMaxAttempts());
        switch (result.status()) {
            case MISSING -> {
                return FinishStep.error(messages.raw("dialog.error-code-required"));
            }
            case EXPIRED -> {
                return FinishStep.error(messages.raw("dialog.error-code-expired"));
            }
            case TOO_MANY -> {
                return FinishStep.error(messages.raw("dialog.error-code-too-many"));
            }
            case WRONG -> {
                return FinishStep.error(messages.raw("dialog.error-code-wrong",
                        "remaining", result.remainingAttempts()));
            }
            case OK -> {
                // 继续往下
            }
        }

        if (!limiter.allow("register:" + session.ip(),
                config.register().maxRegistrationsPerIpPerHour(), HOUR_MILLIS)) {
            return FinishStep.error(messages.raw("dialog.error-rate-limited"));
        }

        try {
            if (repository.existsUsername(session.playerName())) {
                // 竞态：同一玩家名在验证期间被别的连接注册掉了
                return FinishStep.gone();
            }
            String taken = checkEmailAvailable(email);
            if (taken != null) {
                return FinishStep.error(taken);
            }
            repository.insert(session.playerName(), email, hasher.hash(password));
        } catch (SQLException e) {
            if (AccountRepository.isUniqueViolation(e)) {
                // 唯一索引兜住了「先查再插」之间的竞态窗口
                return FinishStep.error(describeConflict(session.playerName()));
            }
            logger.log(Level.SEVERE, "[KunxunAuth] 创建账号失败: " + session.playerName(), e);
            return FinishStep.error(messages.raw("dialog.error-internal"));
        }

        repository.audit(session.playerName(), "REGISTER", session.ip(), Emails.mask(email));
        sessions.authenticate(session.playerId());
        sessions.remember(session.playerId(), session.ip(), config.login().sessionMinutes());
        return FinishStep.success();
    }

    /** 关闭邮箱验证时的一步注册 */
    private FinishStep handleDirectRegister(LoginSession session, ClickPayload click) {
        String email = Emails.normalize(click.input(AuthAction.INPUT_EMAIL));
        if (email.isEmpty()) {
            return FinishStep.error(messages.raw("dialog.error-email-empty"));
        }
        if (!Emails.isValid(email)) {
            return FinishStep.error(messages.raw("dialog.error-email-invalid"));
        }
        String domainError = checkDomain(email);
        if (domainError != null) {
            return FinishStep.error(domainError);
        }
        String password = click.raw(AuthAction.INPUT_PASSWORD);
        String passwordError = checkPassword(password, click.raw(AuthAction.INPUT_PASSWORD_CONFIRM));
        if (passwordError != null) {
            return FinishStep.error(passwordError);
        }

        if (!limiter.allow("register:" + session.ip(),
                config.register().maxRegistrationsPerIpPerHour(), HOUR_MILLIS)) {
            return FinishStep.error(messages.raw("dialog.error-rate-limited"));
        }
        try {
            if (repository.existsUsername(session.playerName())) {
                return FinishStep.gone();
            }
            String taken = checkEmailAvailable(email);
            if (taken != null) {
                return FinishStep.error(taken);
            }
            repository.insert(session.playerName(), email, hasher.hash(password));
        } catch (SQLException e) {
            if (AccountRepository.isUniqueViolation(e)) {
                return FinishStep.error(describeConflict(session.playerName()));
            }
            logger.log(Level.SEVERE, "[KunxunAuth] 创建账号失败: " + session.playerName(), e);
            return FinishStep.error(messages.raw("dialog.error-internal"));
        }
        repository.audit(session.playerName(), "REGISTER_DIRECT", session.ip(), Emails.mask(email));
        sessions.authenticate(session.playerId());
        sessions.remember(session.playerId(), session.ip(), config.login().sessionMinutes());
        return FinishStep.success();
    }

    /** 找回密码第 2 步：校验验证码 + 改密 */
    private FinishStep handleResetSubmit(LoginSession session, ClickPayload click) {
        String email = session.email();
        String code = click.input(AuthAction.INPUT_CODE);
        if (code.isEmpty()) {
            return FinishStep.error(messages.raw("dialog.error-code-empty"));
        }
        String password = click.raw(AuthAction.INPUT_PASSWORD);
        String passwordError = checkPassword(password, click.raw(AuthAction.INPUT_PASSWORD_CONFIRM));
        if (passwordError != null) {
            return FinishStep.error(passwordError);
        }

        VerificationCodes.Result result = codes.verify(VerificationCodes.Purpose.RESET, email, code,
                config.register().codeMaxAttempts());
        switch (result.status()) {
            case MISSING -> {
                return FinishStep.error(messages.raw("dialog.error-code-required"));
            }
            case EXPIRED -> {
                return FinishStep.error(messages.raw("dialog.error-code-expired"));
            }
            case TOO_MANY -> {
                return FinishStep.error(messages.raw("dialog.error-code-too-many"));
            }
            case WRONG -> {
                return FinishStep.error(messages.raw("dialog.error-code-wrong",
                        "remaining", result.remainingAttempts()));
            }
            case OK -> {
                // 继续往下
            }
        }

        try {
            Account account = repository.findByEmail(email).orElse(null);
            if (account == null) {
                return FinishStep.error(messages.raw("dialog.error-email-not-found"));
            }
            repository.updatePassword(account.id(), hasher.hash(password));
            repository.audit(account.username(), "RESET_PASSWORD", session.ip(), Emails.mask(email));
            revokeDevicesOnPasswordChange(account.username(), session.ip());
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[KunxunAuth] 重置密码失败", e);
            return FinishStep.error(messages.raw("dialog.error-internal"));
        }
        return FinishStep.success();
    }

    /**
     * 管理员重置码改密。
     *
     * <p>重置码是「一次性」的：校验通过、密码写库之后立刻作废，
     * 所以就算这条码后来被第三人看到也已经没用了。
     */
    private FinishStep handleForceResetSubmit(LoginSession session, ClickPayload click) {
        String name = session.playerName();
        String code = click.input(AuthAction.INPUT_RESET_CODE);
        if (code.isEmpty()) {
            return FinishStep.error(messages.raw("dialog.error-reset-code-empty"));
        }
        String password = click.raw(AuthAction.INPUT_PASSWORD);
        String passwordError = checkPassword(password, click.raw(AuthAction.INPUT_PASSWORD_CONFIRM));
        if (passwordError != null) {
            return FinishStep.error(passwordError);
        }

        SessionManager.ResetGrant grant = sessions.passwordResetGrant(name);
        if (grant == null) {
            return FinishStep.error(messages.raw("dialog.error-reset-code-expired"));
        }
        if (!constantTimeEquals(grant.code(), code.trim().toUpperCase(java.util.Locale.ROOT))) {
            repository.audit(name, "FORCE_RESET_BAD_CODE", session.ip(), "");
            return FinishStep.error(messages.raw("dialog.error-reset-code-invalid"));
        }

        Account account;
        try {
            account = repository.findByUsername(name).orElse(null);
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[KunxunAuth] 重置码改密时查询账号失败: " + name, e);
            return FinishStep.error(messages.raw("dialog.error-internal"));
        }
        if (account == null) {
            sessions.clearPasswordReset(name);
            return FinishStep.gone();
        }

        try {
            repository.updatePassword(account.id(), hasher.hash(password));
            repository.updateFailedAttempts(account.id(), 0, 0L);
            repository.audit(account.username(), "ADMIN_FORCE_RESET", session.ip(), "");
            revokeDevicesOnPasswordChange(account.username(), session.ip());
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[KunxunAuth] 重置码改密失败: " + name, e);
            return FinishStep.error(messages.raw("dialog.error-internal"));
        }

        sessions.clearPasswordReset(name);
        sessions.authenticate(session.playerId());
        sessions.remember(session.playerId(), session.ip(), config.login().sessionMinutes());
        return FinishStep.success();
    }

    /** 重置码比对用定长比较，避免因为比较提前返回而泄露前缀信息 */
    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null || a.length() != b.length()) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < a.length(); i++) {
            diff |= a.charAt(i) ^ b.charAt(i);
        }
        return diff == 0;
    }

    // ============================================================ 公共校验工具
    /**
     * 邮箱域名黑白名单校验。
     *
     * @return null = 通过；否则返回要显示给玩家的错误文本
     */
    public String checkDomain(String email) {
        String domain = Emails.domain(email);
        for (String rule : config.register().blacklistDomains()) {
            if (Emails.domainMatches(domain, rule)) {
                return messages.raw("dialog.error-email-blacklisted");
            }
        }
        List<String> whitelist = config.register().whitelistDomains();
        if (!whitelist.isEmpty()) {
            boolean allowed = whitelist.stream().anyMatch(rule -> Emails.domainMatches(domain, rule));
            if (!allowed) {
                return messages.raw("dialog.error-email-not-whitelisted",
                        "domains", dialogs.allowedDomainsText());
            }
        }
        return null;
    }

    /** 邮箱是否还能再绑定新账号 */
    public String checkEmailAvailable(String email) {
        int max = config.register().maxAccountsPerEmail();
        if (max <= 0) {
            return null;
        }
        try {
            if (repository.countAccountsByEmail(email) >= max) {
                return messages.raw("dialog.error-email-in-use");
            }
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[KunxunAuth] 统计邮箱绑定数失败", e);
            return messages.raw("dialog.error-internal");
        }
        return null;
    }

    /**
     * 唯一索引冲突后回头确认到底是谁撞了，给出准确提示。
     *
     * <p>数据库只会告诉你「冲突了」，但玩家需要知道是玩家名被占了还是邮箱被绑了。
     */
    private String describeConflict(String playerName) {
        try {
            if (repository.existsUsername(playerName)) {
                return messages.raw("dialog.error-name-taken");
            }
        } catch (SQLException e) {
            logger.log(Level.WARNING, "[KunxunAuth] 冲突复核失败", e);
        }
        return messages.raw("dialog.error-email-in-use");
    }

    /** 密码强度与一致性校验 */
    public String checkPassword(String password, String confirm) {
        if (password == null || password.isEmpty()) {
            return messages.raw("dialog.error-password-empty");
        }
        if (password.length() < config.login().minPasswordLength()) {
            return messages.raw("dialog.error-password-too-short",
                    "min", config.login().minPasswordLength());
        }
        if (password.length() > config.login().maxPasswordLength()) {
            return messages.raw("dialog.error-password-too-long",
                    "max", config.login().maxPasswordLength());
        }
        if (confirm != null && !password.equals(confirm)) {
            return messages.raw("dialog.error-password-mismatch");
        }
        return null;
    }

    /**
     * 签发并发送验证码（异步发信，返回的 future 完成即为投递结果）。
     * 供聊天降级命令复用。
     */
    public CompletableFuture<SendOutcome> sendCodeAsync(VerificationCodes.Purpose purpose, String email,
                                                        String playerName) {
        if (!mail.available()) {
            return CompletableFuture.completedFuture(SendOutcome.MAIL_DISABLED);
        }
        int expireMinutes = config.register().codeExpireMinutes();
        String code = codes.issue(purpose, email, expireMinutes);
        if (config.misc().logVerificationCodes()) {
            logger.info("[KunxunAuth] " + purpose + " 验证码 → " + email + " : " + code);
        }
        return mail.sendVerificationCode(email, playerName, code, expireMinutes)
                .handle((sent, error) -> {
                    if (error != null || !Boolean.TRUE.equals(sent)) {
                        codes.invalidate(purpose, email);
                        return SendOutcome.MAIL_FAILED;
                    }
                    return SendOutcome.OK;
                });
    }

    /** 同步版发码（配置阶段用，最多等一次 SMTP 超时） */
    public SendOutcome sendCode(VerificationCodes.Purpose purpose, String email, String playerName) {
        try {
            return sendCodeAsync(purpose, email, playerName)
                    .get(config.mail().connectionTimeoutMs() + 5000L, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return SendOutcome.MAIL_FAILED;
        } catch (ExecutionException | TimeoutException e) {
            logger.log(Level.WARNING, "[KunxunAuth] 等待验证码邮件结果失败", e);
            return SendOutcome.MAIL_FAILED;
        }
    }

    public VerificationCodes codes() {
        return codes;
    }

    /** 邮件服务是否可用（不可用时注册流程会退化为不验证邮箱） */
    public boolean mailAvailable() {
        return mail.available();
    }

    public RateLimiter limiter() {
        return limiter;
    }

    public AccountRepository repository() {
        return repository;
    }

    public PasswordHasher hasher() {
        return hasher;
    }

    public AuthConfig config() {
        return config;
    }

    public Messages messages() {
        return messages;
    }

    public SessionManager sessions() {
        return sessions;
    }

    /** 供聊天降级命令复用对话框里的提示文案（例如允许的邮箱域名列表） */
    public DialogFactory dialogs() {
        return dialogs;
    }

    // ==================================================================== 内部

    private SendOutcome resendCode(LoginSession session, VerificationCodes.Purpose purpose) {
        String email = session.email();
        long cooldown = codes.resendCooldownRemaining(purpose, email,
                config.register().resendCooldownSeconds());
        if (cooldown > 0) {
            return SendOutcome.MAIL_FAILED;
        }
        if (!limiter.allow("code:" + session.ip(),
                config.register().maxCodesPerIpPerHour(), HOUR_MILLIS)) {
            return SendOutcome.MAIL_FAILED;
        }
        return sendCode(purpose, email, session.playerName());
    }

    private Decision cancelDecision() {
        if (config.preJoin().cancelKicks()) {
            return Decision.deny(messages.get("kick.cancelled"));
        }
        return Decision.allow();
    }

    /**
     * 显示对话框并等待玩家点击。
     *
     * @return null 表示超时或连接已断开
     */
    private ClickPayload await(PlayerConfigurationConnection connection, LoginSession session,
                               Dialog dialog, long remainingMillis) {
        CompletableFuture<ClickPayload> future = session.beginAwait();
        try {
            connection.getAudience().showDialog(dialog);
            return future.get(Math.max(1000L, remainingMillis), TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        } catch (ExecutionException | TimeoutException | java.util.concurrent.CancellationException e) {
            return null;
        } catch (RuntimeException e) {
            logger.log(Level.FINE, "[KunxunAuth] 显示对话框失败: " + e.getMessage(), e);
            return null;
        } finally {
            session.endAwait();
        }
    }

    /** 从点击回传里抽取输入框内容 */
    public static ClickPayload payloadOf(String action, DialogResponseView view) {
        return new ClickPayload(action, java.util.Map.of(
                AuthAction.INPUT_EMAIL, orEmpty(view.getText(AuthAction.INPUT_EMAIL)),
                AuthAction.INPUT_CODE, orEmpty(view.getText(AuthAction.INPUT_CODE)),
                AuthAction.INPUT_PASSWORD, orEmpty(view.getText(AuthAction.INPUT_PASSWORD)),
                AuthAction.INPUT_PASSWORD_CONFIRM, orEmpty(view.getText(AuthAction.INPUT_PASSWORD_CONFIRM)),
                AuthAction.INPUT_RESET_CODE, orEmpty(view.getText(AuthAction.INPUT_RESET_CODE))));
    }

    private static String orEmpty(String value) {
        return value == null ? "" : value;
    }

    // ------------------------------------------------------------ 结果小类型

    private enum StepKind { SUCCESS, ERROR, KICK, GONE }

    private record LoginStep(StepKind kind, String text, Component message) {
        static LoginStep success() {
            return new LoginStep(StepKind.SUCCESS, null, null);
        }

        static LoginStep error(String text) {
            return new LoginStep(StepKind.ERROR, text, null);
        }

        static LoginStep gone() {
            return new LoginStep(StepKind.GONE, null, null);
        }
    }

    private record FinishStep(StepKind kind, String text, Component message) {
        static FinishStep success() {
            return new FinishStep(StepKind.SUCCESS, null, null);
        }

        static FinishStep error(String text) {
            return new FinishStep(StepKind.ERROR, text, null);
        }

        static FinishStep gone() {
            return new FinishStep(StepKind.GONE, null, null);
        }
    }

    private record EmailStep(String email, String error) {
        static EmailStep ok(String email) {
            return new EmailStep(email, null);
        }

        static EmailStep error(String error) {
            return new EmailStep(null, error);
        }
    }
}
