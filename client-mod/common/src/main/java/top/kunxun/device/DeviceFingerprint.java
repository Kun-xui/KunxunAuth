package top.kunxun.device;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 这台机器的硬件指纹。
 *
 * <p>把 CPU 序列号 / 主板序列号与型号 / 系统盘序列号 / 机器唯一 ID 这些「换机器就变、
 * 但同一台机器上装了什么都读得到」的字段拼起来做 SHA-256，取 Base64url 前 32 位。
 *
 * <p><b>它被用来做什么。</b> 设备私钥在落盘时用「指纹派生出来的密钥」做 AES-256-GCM
 * 加密（见 {@link DeviceKeyStore}）。于是把 {@code kunxun-device-*.properties}
 * 整份拷到另一台机器上，文件解不开、私钥拿不到、免密用不了 —— 这就是「密钥跟设备绑定」
 * 的实现方式。
 *
 * <p><b>它做不到什么（必须说清楚）。</b> 这些字段都是公开信息，本机上任何一个程序都能
 * 读出来，所以它防的是「把文件复制走」，防不住「在同一台机器上运行一个伪造指纹的程序」。
 * 换句话说：它把密钥文件从「bearer token（谁拿到谁能用）」降级成了
 * 「只在这台机器上有意义的密文」，而不是一枚硬件级别的保险箱（那需要 TPM）。
 * 服务端那边收到同一个摘要，只用来回答「还是不是同一台机器」并留证据，绝不作为放行依据。
 *
 * <p>采集过程要起子进程（Windows 上读 CIM / 注册表），所以结果静态缓存一次，
 * 整个游戏生命周期只算一遍。
 */
public final class DeviceFingerprint {

    private static final Logger LOGGER = Logger.getLogger("KunxunAuth-Device");

    /** 摘要长度：SHA-256 的 Base64url 取前 32 位，够用且方便贴在管理输出里看 */
    private static final int SUMMARY_LENGTH = 32;

    /** 子进程读取上限：拿不到硬件信息时也要能玩游戏，不能卡在启动上 */
    private static final long COMMAND_TIMEOUT_MILLIS = 4000L;

    private static final class Cached {
        static final Result VALUE = collect();
    }

    /**
     * 指纹结果。
     *
     * @param summary 摘要（Base64url 前 32 位），参与 KDF 与上报协议
     * @param weak    true = 一个硬件字段都没读到，摘要只由主机名/系统/架构拼出来，
     *                换台机器、甚至同一台机器改名都会变。此时绑定关系显著变弱
     * @param detail  给日志看的采集详情（不含任何玩家的网络信息）
     */
    public record Result(String summary, boolean weak, String detail) {
    }

    private DeviceFingerprint() {
    }

    /** 当前机器的指纹（进程内缓存） */
    public static Result current() {
        return Cached.VALUE;
    }

    /** 摘要快捷方式 */
    public static String summary() {
        return current().summary();
    }

    /**
     * 采集 + 计算。
     *
     * <p>顺序是「平台专用字段 → 通用兜底字段」。只要拿到了任何一个硬件级字段，
     * 就不算弱指纹。
     */
    private static Result collect() {
        List<String> parts = new ArrayList<>();
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        boolean hardware = false;
        try {
            if (os.contains("win")) {
                hardware = appendWindows(parts);
            } else if (os.contains("mac") || os.contains("darwin")) {
                hardware = appendMac(parts);
            } else {
                hardware = appendLinux(parts);
            }
        } catch (Throwable t) {
            // 采集失败不能影响游戏：退到通用字段，只是指纹变弱
            LOGGER.log(Level.FINE, "[KunxunAuth] 硬件字段采集失败，改用通用字段", t);
        }
        if (!hardware) {
            parts.add("host=" + hostname());
        }
        parts.add("os=" + os);
        parts.add("arch=" + System.getProperty("os.arch", ""));

        String joined = String.join("|", parts);
        String summary = shorten(sha256Base64(joined));
        if (!hardware) {
            LOGGER.warning("[KunxunAuth] 读不到 CPU / 主板 / 磁盘等硬件标识，"
                    + "设备密钥将只能跟主机名绑定（换机器名就会失效）。"
                    + "如需稳定的免密登录，请确认系统允许读取硬件信息。");
        }
        LOGGER.fine("[KunxunAuth] 设备指纹=" + summary + " · " + String.join(" ", parts));
        return new Result(summary, !hardware, joined);
    }

    // ------------------------------------------------------------------ Windows

    /**
     * Windows：一次 PowerShell 把要的字段全打出来。
     *
     * <p>用一个进程而不是五六个，是因为每次起进程都要几百毫秒；这里总共只允许
     * {@link #COMMAND_TIMEOUT_MILLIS}，起五次必然超时。
     */
    private static boolean appendWindows(List<String> parts) {
        String script = String.join("; ",
                "$ErrorActionPreference='SilentlyContinue'",
                "'cpu=' + ((Get-CimInstance Win32_Processor | Select-Object -First 1).ProcessorId)",
                "'board=' + ((Get-CimInstance Win32_BaseBoard | Select-Object -First 1).SerialNumber)",
                "'model=' + ((Get-CimInstance Win32_BaseBoard | Select-Object -First 1).Product)",
                "'bios=' + ((Get-CimInstance Win32_BIOS | Select-Object -First 1).SerialNumber)",
                "'disk=' + ((Get-CimInstance Win32_DiskDrive | Where-Object { $_.Index -eq 0 }"
                        + " | Select-Object -First 1).SerialNumber)",
                "'guid=' + ((Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography').MachineGuid)");

        List<String> lines = run("powershell.exe", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-Command", script);
        if (lines.isEmpty()) {
            // 老系统上 PowerShell 被策略挡住时退到 wmic（新系统里可能已经移除）
            lines = run("wmic", "cpu", "get", "ProcessorId", "/value");
        }
        return absorb(parts, lines, "cpu", "board", "model", "bios", "disk", "guid");
    }

    // -------------------------------------------------------------------- macOS

    /** macOS：IOPlatformUUID 是这台机器最稳的标识，够用 */
    private static boolean appendMac(List<String> parts) {
        List<String> lines = run("ioreg", "-rd1", "-c", "IOPlatformExpertDevice");
        String uuid = null;
        for (String line : lines) {
            int index = line.indexOf("IOPlatformUUID");
            if (index >= 0) {
                int quote = line.indexOf('"', line.indexOf('=', index));
                if (quote >= 0) {
                    int end = line.indexOf('"', quote + 1);
                    if (end > quote) {
                        uuid = line.substring(quote + 1, end);
                    }
                }
            }
        }
        if (uuid != null && !uuid.isBlank()) {
            parts.add("platform=" + uuid.trim());
            return true;
        }
        return false;
    }

    // -------------------------------------------------------------------- Linux

    /**
     * Linux：优先读 sysfs / machine-id，这些文件普通用户可读，不需要 root，
     * 也不需要为了一个指纹去装 dmidecode。
     */
    private static boolean appendLinux(List<String> parts) {
        boolean found = false;
        found |= appendFile(parts, "machine", "/etc/machine-id");
        found |= appendFile(parts, "board", "/sys/class/dmi/id/board_serial");
        found |= appendFile(parts, "model", "/sys/class/dmi/id/board_name");
        found |= appendFile(parts, "platform", "/sys/class/dmi/id/product_uuid");
        return found;
    }

    private static boolean appendFile(List<String> parts, String key, String path) {
        try {
            Path file = Path.of(path);
            if (!Files.isReadable(file)) {
                return false;
            }
            String value = Files.readString(file, StandardCharsets.UTF_8).trim();
            if (value.isEmpty()) {
                return false;
            }
            parts.add(key + "=" + value);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    // -------------------------------------------------------------------- 工具

    /**
     * 把 {@code key=value} 形式的输出收进 parts。
     *
     * <p>过滤掉的都是「看起来有值、其实每个型号都一样」的垃圾：空串、
     * {@code To Be Filled By O.E.M.}、{@code None}、{@code Default string}、
     * 全零。这些值留在指纹里等于没留，还会让两台不同机器算出同一个摘要。
     *
     * @return 是否至少收到一个可用字段
     */
    private static boolean absorb(List<String> parts, List<String> lines, String... keys) {
        boolean found = false;
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            int eq = trimmed.indexOf('=');
            String raw;
            if (eq > 0) {
                String key = trimmed.substring(0, eq).trim().toLowerCase(Locale.ROOT);
                boolean wanted = false;
                for (String candidate : keys) {
                    if (candidate.equals(key)) {
                        wanted = true;
                        break;
                    }
                }
                if (!wanted) {
                    continue;
                }
                raw = trimmed.substring(eq + 1);
                String value = cleanValue(raw);
                if (value == null) {
                    continue;
                }
                parts.add(key + "=" + value);
                found = true;
            } else if (trimmed.contains("|")) {
                // wmic 的表格式兜底：ProcessorId 之类会以「值|」的形式出现
                String value = cleanValue(trimmed);
                if (value != null && keys.length > 0) {
                    parts.add(keys[0] + "=" + value);
                    found = true;
                }
            }
        }
        return found;
    }

    /** 剔除占位值和长度异常的值；不可用时返回 null */
    private static String cleanValue(String raw) {
        String value = raw.trim();
        if (value.isEmpty() || value.length() < 4 || value.length() > 120) {
            return null;
        }
        String lower = value.toLowerCase(Locale.ROOT);
        if (lower.startsWith("to be filled")
                || lower.equals("none")
                || lower.equals("null")
                || lower.equals("default string")
                || lower.equals("o.e.m.")
                || lower.equals("system serial number")
                || lower.equals("0")
                || lower.matches("0+")) {
            return null;
        }
        return value;
    }

    /**
     * 跑一个外部命令并把输出读回来。
     *
     * <p>超时直接 {@code destroyForcibly}：读硬件信息的命令偶尔会因为 WMI 卡住，
     * 而玩家在等着进游戏，不能把它当作不可中断的操作。
     */
    private static List<String> run(String... command) {
        List<String> lines = new ArrayList<>();
        Process process = null;
        try {
            ProcessBuilder builder = new ProcessBuilder(command);
            builder.redirectErrorStream(true);
            process = builder.start();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    lines.add(line);
                }
            }
            if (!process.waitFor(COMMAND_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)) {
                process.destroyForcibly();
                lines.clear();
            }
        } catch (IOException e) {
            // 命令不存在（例如被精简过的系统）：当作没读到
            return List.of();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return List.of();
        } finally {
            if (process != null && process.isAlive()) {
                process.destroyForcibly();
            }
        }
        return lines;
    }

    private static String hostname() {
        try {
            String name = java.net.InetAddress.getLocalHost().getHostName();
            return name == null ? "" : name;
        } catch (Exception e) {
            return "";
        }
    }

    private static String sha256Base64(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            // JDK 必然带 SHA-256，走到这里说明运行环境被阉割过
            throw new IllegalStateException("当前运行环境不支持 SHA-256", e);
        }
    }

    private static String shorten(String value) {
        return value.length() <= SUMMARY_LENGTH ? value : value.substring(0, SUMMARY_LENGTH);
    }
}
