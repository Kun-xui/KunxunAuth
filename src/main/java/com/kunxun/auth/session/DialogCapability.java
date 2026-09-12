package com.kunxun.auth.session;

import org.bukkit.Bukkit;
import org.bukkit.plugin.Plugin;

import java.lang.reflect.Method;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 判断当前连接对应的客户端能否渲染 Paper 原生对话框。
 *
 * <p>对话框是 Minecraft 1.21.6（协议号 771）才有的能力。装了 ViaVersion 时，
 * 老版本客户端也能连进来，但它们看不到对话框——如果仍然对它们用对话框流程，
 * 玩家会永远卡在「正在加入世界…」界面。所以必须按客户端版本分流。
 *
 * <p>ViaVersion 是可选依赖，这里用反射调用它的 API，避免把 ViaVersion 变成硬依赖。
 */
public final class DialogCapability {

    private final Logger logger;
    private final boolean viaPresent;
    private final boolean assumeCapableWithoutVia;
    private final int minProtocol;

    private Method getPlayerVersion;

    public DialogCapability(Logger logger, boolean assumeCapableWithoutVia, int minProtocol) {
        this.logger = logger;
        this.assumeCapableWithoutVia = assumeCapableWithoutVia;
        this.minProtocol = minProtocol;

        Plugin via = Bukkit.getPluginManager().getPlugin("ViaVersion");
        this.viaPresent = via != null && via.isEnabled();
        if (this.viaPresent) {
            this.getPlayerVersion = resolveMethod();
            if (this.getPlayerVersion == null) {
                logger.warning("[KunxunAuth] 检测到 ViaVersion，但无法读取玩家协议版本，"
                        + "将按 assume-dialog-capable-without-viaversion 的设定处理。");
            }
        }
    }

    private Method resolveMethod() {
        String[] candidates = {
                "com.viaversion.viaversion.api.ViaAPI",
                "com.viaversion.viaversion.api.Via"
        };
        for (String name : candidates) {
            try {
                Class<?> type = Class.forName(name);
                return type.getMethod("getPlayerVersion", UUID.class);
            } catch (ReflectiveOperationException ignored) {
                // 试下一个
            }
        }
        return null;
    }

    /**
     * 该玩家的客户端是否支持原生对话框。
     */
    public boolean isDialogCapable(UUID playerId) {
        if (!viaPresent || getPlayerVersion == null) {
            return assumeCapableWithoutVia;
        }
        try {
            Object api = Class.forName("com.viaversion.viaversion.api.Via")
                    .getMethod("getAPI").invoke(null);
            Object version = getPlayerVersion.invoke(api, playerId);
            if (version instanceof Integer protocol) {
                return protocol >= minProtocol;
            }
        } catch (Throwable t) {
            logger.log(Level.FINE, "[KunxunAuth] 读取 ViaVersion 协议版本失败: " + t.getMessage(), t);
        }
        return assumeCapableWithoutVia;
    }

    public boolean viaPresent() {
        return viaPresent;
    }

    public int minProtocol() {
        return minProtocol;
    }

    /** 启动时打印一次分流策略，方便排查 */
    public void logSummary() {
        if (!viaPresent) {
            logger.info("[KunxunAuth] 未检测到 ViaVersion —— 默认认为所有客户端都支持原生对话框"
                    + "（assume-dialog-capable-without-viaversion=" + assumeCapableWithoutVia + "）");
        } else {
            logger.info("[KunxunAuth] 已检测到 ViaVersion —— 客户端协议号 >= " + minProtocol
                    + " 走对话框流程，低于该版本走聊天降级流程");
        }
    }
}
