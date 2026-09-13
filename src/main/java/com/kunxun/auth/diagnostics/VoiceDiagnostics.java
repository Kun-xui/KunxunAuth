package com.kunxun.auth.diagnostics;

import org.bukkit.Bukkit;
import org.bukkit.plugin.Plugin;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 语音聊天的端口 / 版本诊断。
 *
 * <p><b>为什么不把语音功能并进来。</b> Simple Voice Chat 是「客户端模组 + 服务端插件」两半的，
 * 服务端那半跑的是一个独立的 UDP 语音服务器：自己的握手与密钥协商、自己的音频帧格式、
 * 分组/距离/旁观者一堆逻辑。把它塞进登录插件等于从零重写一个模组，而且客户端那半
 * 永远得让玩家单独安装 —— 省不下任何东西，却要跟着它的协议版本一直维护。
 *
 * <p><b>那能帮上什么。</b> 用它的服务器最常踩的坑不是「功能不够」，而是「端口不对」：
 * 语音走 UDP，默认和 MC 用同一个端口号；nat/端口映射环境下，路由器往往只把 TCP 转发了，
 * 于是「能进服、但语音连不上」。这一层是完全可以从配置里读出来并提前警告的，
 * 所以这里做诊断：把实际端口链路念一遍，把要在路由器上转发哪个端口说清楚。
 *
 * <p>诊断只读文件、不碰任何协议，也不影响语音是否可用。
 */
public final class VoiceDiagnostics {

    /** Simple Voice Chat 的插件名 */
    private static final String PLUGIN_NAME = "voicechat";

    /** 一次诊断的结果 */
    public record Report(boolean pluginLoaded, String pluginVersion, String disabledJar,
                         String mcPort, String voicePort, String voiceHost, boolean voiceConfigFound,
                         List<String> lines) {

        /** 服务端的语音插件是不是正在运行（决定要不要给玩家发按键提示） */
        public boolean active() {
            return pluginLoaded;
        }
    }

    private final Plugin plugin;
    private final Logger logger;
    private volatile Report report;

    public VoiceDiagnostics(Plugin plugin, Logger logger) {
        this.plugin = plugin;
        this.logger = logger;
    }

    /** 上次诊断结果；没跑过就先跑一次 */
    public Report report() {
        Report current = report;
        if (current == null) {
            current = inspect();
            report = current;
        }
        return current;
    }

    /** 服务端语音是否可用 */
    public boolean active() {
        return report().active();
    }

    /** 在控制台打一份诊断（整块输出，别被启动日志埋掉） */
    public void log() {
        Report current = inspect();
        this.report = current;
        StringBuilder block = new StringBuilder(512);
        block.append('\n').append("── 语音聊天诊断（只读配置，不参与语音协议）────────────────").append('\n');
        for (String line : current.lines()) {
            block.append(line).append('\n');
        }
        block.append("──────────────────────────────────────────────────────");
        logger.info(block.toString());
    }

    // ------------------------------------------------------------------ 采集

    private Report inspect() {
        Plugin voice = Bukkit.getPluginManager().getPlugin(PLUGIN_NAME);
        boolean loaded = voice != null && voice.isEnabled();
        // 用 getPluginMeta() 而不是已过时的 getDescription()（Paper 26.2 上后者会编译告警）
        String version = voice == null ? "-" : String.valueOf(voice.getPluginMeta().getVersion());

        File pluginsDir = plugin.getDataFolder().getParentFile();
        String disabledJar = findDisabledJar(pluginsDir);

        File voiceConfig = new File(pluginsDir, PLUGIN_NAME + File.separator + "voicechat-server.properties");
        Properties voiceProps = read(voiceConfig);
        String voicePort = value(voiceProps, "port", "");
        String voiceHost = value(voiceProps, "voice_host", "");

        File serverProps = pluginsDir.getParentFile() == null
                ? null : new File(pluginsDir.getParentFile(), "server.properties");
        String mcPort = value(read(serverProps), "server-port", "25565");

        List<String> lines = new ArrayList<>();
        lines.add("  · 服务端插件：" + state(loaded, version, voice, disabledJar));
        lines.add("  · 端口：MC " + mcPort + "/TCP · 语音 " + describeVoicePort(voicePort)
                + "/UDP（语音端口读自 plugins/" + PLUGIN_NAME + "/voicechat-server.properties 的 port）");
        lines.add("  · 对外通告：" + describeVoiceHost(voiceHost));
        lines.add("  · 路由器/防火墙需要把对外那个端口的 " + "TCP 和 UDP 都" + " 转发到这台机器的 "
                + mcPort + "：只转 TCP 的典型表现是「能进服，但语音一直连不上」。");
        lines.add("  · 客户端模组版本必须与服务端插件一致，否则玩家进服会被提示版本不兼容。");
        return new Report(loaded, version, disabledJar, mcPort, voicePort, voiceHost,
                !voiceProps.isEmpty(), lines);
    }

    /** 插件状态那一行（区分「没装」「装了但被改名禁用」「已经加载」三种）*/
    private static String state(boolean loaded, String version, Plugin voice, String disabledJar) {
        if (loaded) {
            return "已加载（Simple Voice Chat " + version + "）";
        }
        if (disabledJar != null) {
            return "未加载 —— 发现 " + disabledJar
                    + "，把文件名末尾的 .disabled 去掉再重启服务器就能启用";
        }
        if (voice != null) {
            return "已安装但没启用";
        }
        return "未安装 —— plugins/ 下没有 Simple Voice Chat 插件，玩家用不了语音";
    }

    private static String describeVoicePort(String port) {
        if (port == null || port.isEmpty()) {
            return "未知";
        }
        if ("-1".equals(port)) {
            // SVC 用 -1 表示「跟 MC 用同一个端口」
            return "同 MC 端口";
        }
        return port;
    }

    private static String describeVoiceHost(String host) {
        if (host == null || host.isEmpty()) {
            return "未设置（voice_host 为空）—— 客户端会用「它连服务器的那个地址」，"
                    + "在 nat/端口映射环境下语音通常连不上；建议填「公网地址:对外端口」";
        }
        return host + "（voice_host，客户端会连这个地址）";
    }

    /** plugins/ 下有没有被改名禁用的语音插件 jar */
    private static String findDisabledJar(File pluginsDir) {
        if (pluginsDir == null || !pluginsDir.isDirectory()) {
            return null;
        }
        File[] files = pluginsDir.listFiles((dir, name) -> {
            String lower = name.toLowerCase(Locale.ROOT);
            return lower.startsWith("voicechat") && lower.endsWith(".disabled");
        });
        if (files == null || files.length == 0) {
            return null;
        }
        return files[0].getName();
    }

    private static Properties read(File file) {
        Properties properties = new Properties();
        if (file == null || !file.isFile()) {
            return properties;
        }
        // 用 UTF-8 reader 而不是 InputStream：Properties.load(InputStream) 按 ISO-8859-1 解，
        // 万一以后配置里出现非 ASCII 的值就会被解坏
        try (java.io.Reader reader = Files.newBufferedReader(file.toPath(), StandardCharsets.UTF_8)) {
            properties.load(reader);
        } catch (IOException e) {
            // 读不到就当没有：诊断失败不该影响插件启动
            return properties;
        }
        return properties;
    }

    private static String value(Properties properties, String key, String fallback) {
        String value = properties.getProperty(key);
        return value == null || value.isBlank() ? fallback : value.trim();
    }
}
