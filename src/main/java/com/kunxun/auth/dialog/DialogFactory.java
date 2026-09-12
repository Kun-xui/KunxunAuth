package com.kunxun.auth.dialog;

import com.kunxun.auth.config.AuthConfig;
import com.kunxun.auth.config.Messages;
import com.kunxun.auth.util.Text;
import io.papermc.paper.dialog.Dialog;
import io.papermc.paper.registry.data.dialog.ActionButton;
import io.papermc.paper.registry.data.dialog.DialogBase;
import io.papermc.paper.registry.data.dialog.action.DialogAction;
import io.papermc.paper.registry.data.dialog.body.DialogBody;
import io.papermc.paper.registry.data.dialog.input.DialogInput;
import io.papermc.paper.registry.data.dialog.type.DialogType;
import net.kyori.adventure.text.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * 组装预进服对话框。
 *
 * <p>对话框由客户端渲染，服务端只发结构化描述，所以不需要资源包/模组。
 * 所有对话框都用 {@code afterAction = WAIT_FOR_RESPONSE}：玩家点按钮后界面
 * 保持等待状态，由服务端决定「发下一个对话框」还是「断开连接」，
 * 避免界面闪回加载画面。
 */
public final class DialogFactory {

    /** 对话整体宽度 */
    private static final int BODY_WIDTH = 300;
    /** 按钮宽度 */
    private static final int BUTTON_WIDTH = 150;
    /** 输入框宽度 */
    private static final int INPUT_WIDTH = 280;

    private final Messages messages;
    private final AuthConfig config;

    public DialogFactory(Messages messages, AuthConfig config) {
        this.messages = messages;
        this.config = config;
        validateInputKeys();
    }

    /**
     * 输入框键名会被 Paper 用 {@code StringTemplate.isValidVariableName()} 校验，
     * 只允许「字母 / 数字 / 下划线」；不合法会在弹框瞬间抛异常并踢掉玩家。
     * 这里在插件启动时就先自查一遍，把问题提前暴露到控制台。
     */
    private static void validateInputKeys() {
        for (String key : List.of(AuthAction.INPUT_EMAIL, AuthAction.INPUT_CODE,
                AuthAction.INPUT_PASSWORD, AuthAction.INPUT_PASSWORD_CONFIRM,
                AuthAction.INPUT_RESET_CODE)) {
            boolean ok = !key.isEmpty()
                    && key.chars().allMatch(c -> Character.isLetterOrDigit(c) || c == '_');
            if (!ok) {
                throw new IllegalStateException("对话框输入框键名不合法: \"" + key
                        + "\"（只允许字母、数字、下划线）");
            }
        }
    }

    // ------------------------------------------------------------ 注册流程

    /** 注册第 1 步：填邮箱 */
    public Dialog registerEmail(String errorLine, String infoLine) {
        List<DialogBody> body = new ArrayList<>();
        body.add(body("dialog.register-body-step1"));
        appendAllowedDomains(body);
        appendFeedback(body, errorLine, infoLine);

        List<DialogInput> inputs = List.of(
                text(AuthAction.INPUT_EMAIL, "dialog.input-email", 254));

        List<ActionButton> buttons = List.of(
                button("dialog.button-send-code", "dialog.tooltip-send-code", AuthAction.SEND_CODE),
                button("dialog.button-cancel", "dialog.tooltip-cancel", AuthAction.CANCEL));

        return build(messages.plain("dialog.register-title", "step", 1), body, inputs, buttons);
    }

    /** 注册第 2 步：填验证码 + 设置密码 */
    public Dialog registerCode(String email, int expireMinutes, String errorLine, String infoLine) {
        List<DialogBody> body = new ArrayList<>();
        body.add(body("dialog.register-body-step2", "email", email, "minutes", expireMinutes));
        appendFeedback(body, errorLine, infoLine);

        List<DialogInput> inputs = List.of(
                text(AuthAction.INPUT_CODE, "dialog.input-code", 12),
                text(AuthAction.INPUT_PASSWORD, "dialog.input-password", config.login().maxPasswordLength()),
                text(AuthAction.INPUT_PASSWORD_CONFIRM, "dialog.input-password-confirm",
                        config.login().maxPasswordLength()));

        List<ActionButton> buttons = List.of(
                button("dialog.button-submit-register", "dialog.tooltip-submit-register", AuthAction.REGISTER_SUBMIT),
                button("dialog.button-resend-code", "dialog.tooltip-resend-code", AuthAction.REGISTER_RESEND),
                button("dialog.button-cancel", "dialog.tooltip-cancel", AuthAction.CANCEL));

        return build(messages.plain("dialog.register-title-step2"), body, inputs, buttons);
    }

    /** 关闭邮箱验证时的一步注册：填邮箱 + 直接设密码（邮箱只做记录，不发码） */
    public Dialog registerDirect(String errorLine, String infoLine) {
        List<DialogBody> body = new ArrayList<>();
        body.add(body("dialog.register-body-step1"));
        appendAllowedDomains(body);
        appendFeedback(body, errorLine, infoLine);

        List<DialogInput> inputs = List.of(
                text(AuthAction.INPUT_EMAIL, "dialog.input-email", 254),
                text(AuthAction.INPUT_PASSWORD, "dialog.input-password", config.login().maxPasswordLength()),
                text(AuthAction.INPUT_PASSWORD_CONFIRM, "dialog.input-password-confirm",
                        config.login().maxPasswordLength()));

        List<ActionButton> buttons = List.of(
                button("dialog.button-submit-register", "dialog.tooltip-submit-register", AuthAction.REGISTER_DIRECT),
                button("dialog.button-cancel", "dialog.tooltip-cancel", AuthAction.CANCEL));

        return build(messages.plain("dialog.register-title-step2"), body, inputs, buttons);
    }

    // ------------------------------------------------------------ 登录流程

    public Dialog login(String errorLine, String infoLine) {
        List<DialogBody> body = new ArrayList<>();
        body.add(body("dialog.login-body",
                "maxAttempts", config.login().maxFailedAttempts(),
                "lockout", config.login().lockoutMinutes()));
        appendFeedback(body, errorLine, infoLine);

        List<DialogInput> inputs = List.of(
                text(AuthAction.INPUT_PASSWORD, "dialog.input-password", config.login().maxPasswordLength()));

        List<ActionButton> buttons = List.of(
                button("dialog.button-submit-login", "dialog.tooltip-submit-login", AuthAction.LOGIN_SUBMIT),
                button("dialog.button-forgot", "dialog.tooltip-forgot", AuthAction.LOGIN_FORGOT),
                button("dialog.button-cancel", "dialog.tooltip-cancel", AuthAction.CANCEL));

        return build(messages.plain("dialog.login-title"), body, inputs, buttons);
    }

    // -------------------------------------------------------- 找回密码流程

    public Dialog resetEmail(String errorLine, String infoLine) {
        List<DialogBody> body = new ArrayList<>();
        body.add(body("dialog.reset-body-step1"));
        appendFeedback(body, errorLine, infoLine);

        List<DialogInput> inputs = List.of(
                text(AuthAction.INPUT_EMAIL, "dialog.input-email", 254));

        List<ActionButton> buttons = List.of(
                button("dialog.button-send-code", "dialog.tooltip-send-code", AuthAction.RESET_SEND),
                button("dialog.button-back-to-login", "dialog.tooltip-back-to-login", AuthAction.BACK),
                button("dialog.button-cancel", "dialog.tooltip-cancel", AuthAction.CANCEL));

        return build(messages.plain("dialog.reset-title", "step", 1), body, inputs, buttons);
    }

    public Dialog resetCode(String email, int expireMinutes, String errorLine, String infoLine) {
        List<DialogBody> body = new ArrayList<>();
        body.add(body("dialog.reset-body-step2", "email", email, "minutes", expireMinutes));
        appendFeedback(body, errorLine, infoLine);

        List<DialogInput> inputs = List.of(
                text(AuthAction.INPUT_CODE, "dialog.input-code", 12),
                text(AuthAction.INPUT_PASSWORD, "dialog.input-new-password", config.login().maxPasswordLength()),
                text(AuthAction.INPUT_PASSWORD_CONFIRM, "dialog.input-new-password-confirm",
                        config.login().maxPasswordLength()));

        List<ActionButton> buttons = List.of(
                button("dialog.button-submit-reset", "dialog.tooltip-submit-reset", AuthAction.RESET_SUBMIT),
                button("dialog.button-resend-code", "dialog.tooltip-resend-code", AuthAction.RESET_RESEND),
                button("dialog.button-cancel", "dialog.tooltip-cancel", AuthAction.CANCEL));

        return build(messages.plain("dialog.reset-title", "step", 2), body, inputs, buttons);
    }

    // -------------------------------------------------- 管理员重置码改密

    /**
     * 管理员签发重置码之后，玩家在预进服界面直接改密。
     *
     * <p>和「找回密码」的区别：这里的凭据不是发到邮箱的验证码，而是管理员
     * 当面/私聊交给玩家的一次性重置码，所以整条链路里不存在明文密码。
     */
    public Dialog forceReset(String playerName, int expireMinutes, String errorLine, String infoLine) {
        List<DialogBody> body = new ArrayList<>();
        body.add(body("dialog.force-reset-body", "player", playerName, "minutes", expireMinutes));
        appendFeedback(body, errorLine, infoLine);

        List<DialogInput> inputs = List.of(
                text(AuthAction.INPUT_RESET_CODE, "dialog.input-reset-code", 16),
                text(AuthAction.INPUT_PASSWORD, "dialog.input-new-password", config.login().maxPasswordLength()),
                text(AuthAction.INPUT_PASSWORD_CONFIRM, "dialog.input-new-password-confirm",
                        config.login().maxPasswordLength()));

        List<ActionButton> buttons = List.of(
                button("dialog.button-submit-force-reset", "dialog.tooltip-submit-force-reset",
                        AuthAction.FORCE_RESET),
                button("dialog.button-cancel", "dialog.tooltip-cancel", AuthAction.CANCEL));

        return build(messages.plain("dialog.force-reset-title"), body, inputs, buttons);
    }

    // ------------------------------------------------------------ 设备绑定

    /**
     * 登录 / 注册成功之后，问一句要不要把这台设备绑上。
     *
     * <p>刻意<b>不放输入框</b>：这台设备是什么、能不能绑，全都由客户端在后台对挑战
     * 签名来决定，对话框只负责收集「绑 / 不绑」这个意愿。少一个输入框就少一次
     * 「键名不合法导致弹框瞬间踢人」的机会。
     *
     * @param deviceName 客户端自报的设备名；没装模组时会是 null
     * @param bound      当前账号已经绑了几台
     * @param maxDevices 单账号上限
     */
    public Dialog bindPrompt(String deviceName, int bound, int maxDevices, String errorLine) {
        List<DialogBody> body = new ArrayList<>();
        body.add(body("dialog.device-bind-body",
                "device", deviceName == null || deviceName.isBlank()
                        ? messages.raw("dialog.device-unknown-name") : deviceName,
                "bound", bound,
                "max", maxDevices));
        appendFeedback(body, errorLine, null);

        List<ActionButton> buttons = List.of(
                button("dialog.button-device-bind", "dialog.tooltip-device-bind", AuthAction.DEVICE_BIND),
                button("dialog.button-device-skip", "dialog.tooltip-device-skip", AuthAction.DEVICE_SKIP));

        return build(messages.plain("dialog.device-bind-title"), body, List.of(), buttons);
    }

    // ---------------------------------------------------------------- 构建
    private Dialog build(Component title, List<DialogBody> body, List<DialogInput> inputs,
                         List<ActionButton> buttons) {
        boolean canEscape = config.preJoin().allowCloseWithEscape();
        return Dialog.create(factory -> {
            var entry = factory.empty();
            entry.base(DialogBase.builder(title)
                    .canCloseWithEscape(canEscape)
                    .pause(false)
                    .afterAction(DialogBase.DialogAfterAction.WAIT_FOR_RESPONSE)
                    .body(body)
                    .inputs(inputs)
                    .build());
            entry.type(DialogType.multiAction(buttons).columns(1).build());
        });
    }

    /** 把多行消息转成一条 body（保留换行） */
    private DialogBody body(String key, Object... placeholders) {
        String raw = messages.raw(key, placeholders);
        String[] lines = raw.split("\\R");
        Component text = Component.empty();
        for (int i = 0; i < lines.length; i++) {
            if (i > 0) {
                text = text.append(Component.newline());
            }
            text = text.append(Text.of(lines[i]));
        }
        return DialogBody.plainMessage(text, BODY_WIDTH);
    }

    /** 红字错误 / 绿字提示挂在正文末尾 */
    private void appendFeedback(List<DialogBody> body, String errorLine, String infoLine) {
        if (errorLine != null && !errorLine.isBlank()) {
            body.add(DialogBody.plainMessage(Text.of(errorLine), BODY_WIDTH));
        }
        if (infoLine != null && !infoLine.isBlank()) {
            body.add(DialogBody.plainMessage(Text.of(infoLine), BODY_WIDTH));
        }
    }

    /**
     * 白名单非空时，把允许的邮箱域名直接印在注册框里。
     *
     * <p>玩家用临时邮箱注册失败时最烦的是「不知道到底哪些能用」，
     * 与其等他填完再报错，不如一开始就写清楚。
     */
    private void appendAllowedDomains(List<DialogBody> body) {
        if (config.register().whitelistDomains().isEmpty()) {
            return;
        }
        body.add(body("dialog.register-allowed-domains", "domains", allowedDomainsText()));
    }

    private DialogInput text(String key, String labelKey, int maxLength) {
        return DialogInput.text(key, messages.plain(labelKey))
                .width(INPUT_WIDTH)
                .maxLength(Math.max(1, maxLength))
                .build();
    }

    private ActionButton button(String labelKey, String tooltipKey, AuthAction action) {
        return ActionButton.builder(messages.plain(labelKey))
                .tooltip(messages.plain(tooltipKey))
                .width(BUTTON_WIDTH)
                .action(DialogAction.customClick(action.key(), null))
                .build();
    }

    // ------------------------------------------------------- 消息短访问器

    public Messages messages() {
        return messages;
    }

    /** 取一条消息原文，供业务层拼错误提示用 */
    public String line(String key, Object... placeholders) {
        return messages.raw(key, placeholders);
    }

    /** 是否配置了邮箱域名白名单（非空 = 只允许名单内域名注册） */
    public boolean hasAllowedDomains() {
        return !config.register().whitelistDomains().isEmpty();
    }

    /**
     * 把白名单域名拼成一行给玩家看的文本。
     *
     * <p>域名太多时截断，避免把对话框撑爆；配置里写了几百个域名本来也不现实。
     */
    public String allowedDomainsText() {
        List<String> domains = config.register().whitelistDomains();
        int limit = 12;
        if (domains.size() <= limit) {
            return String.join(" / ", domains);
        }
        return String.join(" / ", domains.subList(0, limit)) + " 等 " + domains.size() + " 个域名";
    }
}
