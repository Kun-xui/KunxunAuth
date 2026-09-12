package com.kunxun.auth.config;

import com.kunxun.auth.util.Text;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.JoinConfiguration;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * messages.yml 的访问入口。
 *
 * <p>所有取到的字符串都会先做占位符替换，再转成 Adventure 的 {@link Component}。
 */
public final class Messages {

    private final FileConfiguration config;
    private final String prefix;

    private Messages(FileConfiguration config) {
        this.config = config;
        this.prefix = config.getString("prefix", "");
    }

    /**
     * 载入消息文件。若插件目录下不存在则从 jar 内释放一份。
     */
    public static Messages load(JavaPlugin plugin, String language) {
        String fileName = "messages.yml";
        File file = new File(plugin.getDataFolder(), fileName);
        if (!file.exists()) {
            plugin.saveResource(fileName, false);
        }
        YamlConfiguration configuration = YamlConfiguration.loadConfiguration(file);

        // jar 内建默认值做兜底，用户文件缺键时不会显示空
        try (InputStream in = plugin.getResource(fileName)) {
            if (in != null) {
                configuration.setDefaults(YamlConfiguration.loadConfiguration(
                        new InputStreamReader(in, StandardCharsets.UTF_8)));
            }
        } catch (Exception ignored) {
            // 读不到就用用户文件本身
        }
        configuration.options().copyDefaults(true);
        return new Messages(configuration);
    }

    public String prefix() {
        return prefix;
    }

    /** 取原始字符串（不转 Component），带占位符替换 */
    public String raw(String key, Object... placeholders) {
        String value = config.getString(key);
        if (value == null) {
            return "";
        }
        return Text.fill(value, placeholders);
    }

    /** 取带前缀的 Component */
    public Component get(String key, Object... placeholders) {
        return Text.of(prefix + raw(key, placeholders));
    }

    /** 取不带前缀的 Component */
    public Component plain(String key, Object... placeholders) {
        return Text.of(raw(key, placeholders));
    }

    /** 取多行消息，每行一个 Component */
    public List<Component> lines(String key, Object... placeholders) {
        List<String> raw = config.getStringList(key);
        List<Component> result = new ArrayList<>(raw.size());
        for (String line : raw) {
            result.add(Text.of(Text.fill(line, placeholders)));
        }
        return result;
    }

    /** 取多行消息拼成单个换行 Component */
    public Component block(String key, Object... placeholders) {
        return Component.join(JoinConfiguration.newlines(), lines(key, placeholders));
    }

    public int intValue(String key, int fallback) {
        return config.getInt(key, fallback);
    }

    public boolean has(String key) {
        return config.contains(key);
    }
}
