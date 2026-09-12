package com.kunxun.auth.util;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;

import java.util.List;

/**
 * 文本工具：把配置里的 & 颜色代码 / &#RRGGBB 十六进制转成 Adventure Component。
 */
public final class Text {

    private static final LegacyComponentSerializer AMPERSAND = LegacyComponentSerializer.builder()
            .character('&')
            .hexColors()
            .useUnusualXRepeatedCharacterHexFormat()
            .build();

    private static final LegacyComponentSerializer SECTION = LegacyComponentSerializer.legacySection();

    private Text() {
    }

    /** & 颜色代码 → Component */
    public static Component of(String legacy) {
        if (legacy == null || legacy.isEmpty()) {
            return Component.empty();
        }
        return AMPERSAND.deserialize(legacy);
    }

    /** Component → § 颜色代码字符串（写日志用） */
    public static String legacy(Component component) {
        return component == null ? "" : SECTION.serialize(component);
    }

    /** 去掉颜色代码，得到纯文本 */
    public static String strip(String legacy) {
        if (legacy == null) {
            return "";
        }
        return legacy(AMPERSAND.deserialize(legacy));
    }

    /**
     * 占位符替换。按 (key, value, key, value ...) 传入。
     */
    public static String fill(String template, Object... pairs) {
        if (template == null) {
            return "";
        }
        String out = template;
        for (int i = 0; i + 1 < pairs.length; i += 2) {
            out = out.replace("{" + pairs[i] + "}", String.valueOf(pairs[i + 1]));
        }
        return out;
    }

    /** 多行消息（YAML 列表）拼接成一行一段的正文 */
    public static List<String> lines(String legacyMultiline) {
        return List.of(legacyMultiline.split("\\R"));
    }
}
