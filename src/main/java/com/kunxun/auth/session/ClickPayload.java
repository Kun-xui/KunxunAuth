package com.kunxun.auth.session;

import java.util.Map;

/**
 * 一次对话框按钮点击的回传内容。
 *
 * <p>数据通过 {@code DialogAction.customClick} 的私有通道回到服务端，
 * 不进聊天框也不进日志，所以可以安全地携带密码。
 *
 * @param action 动作标识，例如 {@code "submit"} / {@code "send-code"} / {@code "cancel"}
 * @param inputs 输入框内容，键为 {@code email} / {@code code} / {@code password} / {@code password_confirm}
 */
public record ClickPayload(String action, Map<String, String> inputs) {

    public String input(String key) {
        if (inputs == null) {
            return "";
        }
        String value = inputs.get(key);
        return value == null ? "" : value.trim();
    }

    public String raw(String key) {
        if (inputs == null) {
            return "";
        }
        String value = inputs.get(key);
        return value == null ? "" : value;
    }
}
