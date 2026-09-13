package com.kunxun.auth.dialog;

import net.kyori.adventure.key.Key;

/**
 * 对话框按钮的动作标识。
 *
 * <p>每个按钮绑定一个 {@code kunxunauth:} 命名空间下的 Key，玩家点击后
 * Paper 会抛出 {@code PlayerCustomClickEvent}，插件据此判断点了哪个按钮。
 * 只认自己命名空间的 Key，避免和其它插件的对话框互相干扰。
 */
public enum AuthAction {

    /** 注册第 1 步：发送验证码 */
    SEND_CODE("register-send"),
    /** 注册第 2 步：校验验证码 + 创建账号 */
    REGISTER_SUBMIT("register-submit"),
    /** 注册第 2 步：重新发送验证码 */
    REGISTER_RESEND("register-resend"),
    /** 关闭邮箱验证时的一步注册 */
    REGISTER_DIRECT("register-direct"),
    /** 登录：提交密码 */
    LOGIN_SUBMIT("login-submit"),
    /** 登录：进入找回密码 */
    LOGIN_FORGOT("login-forgot"),
    /** 找回密码第 1 步：发送验证码 */
    RESET_SEND("reset-send"),
    /** 找回密码第 2 步：重置密码 */
    RESET_SUBMIT("reset-submit"),
    /** 找回密码第 2 步：重新发送验证码 */
    RESET_RESEND("reset-resend"),
    /** 管理员签发重置码后：用重置码换新密码 */
    FORCE_RESET("force-reset"),
    /** 登录/注册成功后的设备询问：把这台设备绑到账号下 */
    DEVICE_BIND("device-bind"),
    /** 登录/注册成功后的设备询问：这次先不绑 */
    DEVICE_SKIP("device-skip"),
    /**
     * 设备免密校验等待框上的唯一按钮。
     *
     * <p>它不对应任何判定，存在的意义是让那个框有一个可点的按钮（对话框的按钮列表
     * 不能为空，否则客户端解析不过）。点它只会让客户端进入「等待服务器」状态，
     * 而服务器紧接着就会发下一个框或放行。
     */
    DEVICE_WAIT("device-wait"),
    /** 放弃并断开连接 */
    CANCEL("cancel"),
    /** 返回上一步 */
    BACK("back");

    public static final String NAMESPACE = "kunxunauth";

    /** 输入框的键名，服务端从 DialogResponseView 里按这些键取回内容 */
    public static final String INPUT_EMAIL = "email";
    public static final String INPUT_CODE = "code";
    public static final String INPUT_PASSWORD = "password";
    // 注意：输入框键名会被 Paper 用 StringTemplate.isValidVariableName() 校验，
    // 只允许「字母 / 数字 / 下划线」，因此这里不能用连字符。
    public static final String INPUT_PASSWORD_CONFIRM = "password_confirm";
    /** 管理员当面/私聊交给玩家的一次性重置码（区别于邮件验证码） */
    public static final String INPUT_RESET_CODE = "reset_code";

    private final Key key;

    AuthAction(String value) {
        this.key = Key.key(NAMESPACE, value);
    }

    public Key key() {
        return key;
    }

    public String id() {
        return key.value();
    }

    /** 反查；不是本插件的 Key 返回 null */
    public static AuthAction from(Key key) {
        if (key == null || !NAMESPACE.equals(key.namespace())) {
            return null;
        }
        return byId(key.value());
    }

    /** 按动作标识反查 */
    public static AuthAction byId(String id) {
        if (id == null) {
            return null;
        }
        for (AuthAction action : values()) {
            if (action.key.value().equals(id)) {
                return action;
            }
        }
        return null;
    }
}
