package com.kunxun.auth.diagnostics;

import com.kunxun.auth.config.Messages;
import com.kunxun.auth.util.Text;

import java.util.List;
import java.util.logging.Logger;

/**
 * 首次开服引导：发信邮箱还没配好时，把「该填什么、去哪填、怎么开 SMTP」讲清楚。
 *
 * <p>面向的是<b>从没搭过 MC 服务器、也不知道什么叫 SMTP 授权码</b>的人。
 * 插件原来的行为是：邮件不可用时静默降级成「注册不验证邮箱」，
 * 只在日志里留一行「邮件不可用」—— 新手既不知道发生了什么，也不知道下一步该做什么，
 * 常见结局是把插件删掉。所以这里在启动时打一份带链接的教程，并且在登录界面上
 * 也给玩家/管理员一句明确的话（见 {@code dialog.mail-not-configured}）。
 *
 * <p>文本全部放在 {@code messages.yml} 的 {@code setup.lines} 里，改文案不用改代码。
 */
public final class SetupGuide {

    private final Messages messages;
    private final Logger logger;

    public SetupGuide(Messages messages, Logger logger) {
        this.messages = messages;
        this.logger = logger;
    }

    /** 引导正文（带颜色码，玩家在游戏里看到的是彩色） */
    public List<String> lines() {
        return messages.rawLines("setup.lines");
    }

    /**
     * 需要时在控制台打印引导。
     *
     * @param mailEnabled   配置里 mail.enable 是不是开着的
     * @param mailAvailable 现在真的能发信吗
     */
    public void logIfNeeded(boolean mailEnabled, boolean mailAvailable) {
        if (mailAvailable) {
            return;
        }
        if (!mailEnabled) {
            logger.info("[KunxunAuth] 邮件功能已在 config.yml 里关闭（mail.enable=false），"
                    + "玩家注册不会验证邮箱。需要邮箱验证时把它改回 true 并填上发信账号。"
                    + "（在游戏里看完整引导：/kunxunauth setup）");
            return;
        }
        // 用 warning 级别，避免被埋在启动日志里；整块一次打出来，不要每行一个前缀
        StringBuilder block = new StringBuilder(512);
        block.append('\n').append(header()).append('\n');
        for (String line : lines()) {
            block.append(Text.strip(line)).append('\n');
        }
        block.append(footer());
        logger.warning(block.toString());
    }

    /** 单独取头部（给控制台与命令共用） */
    public String header() {
        return Text.strip(messages.raw("setup.header"));
    }

    public String footer() {
        return Text.strip(messages.raw("setup.footer"));
    }
}
