package com.kunxun.auth.util;

import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 通用滑动窗口限流器（内存实现）。
 *
 * <p>用于「同一 IP 每小时最多注册几个账号」「同一 IP 每小时最多发几次验证码」
 * 「同一 IP 并发连接数」这类粗粒度限制。重启即清零——这些限制本身也不需要持久化。
 */
public final class RateLimiter {

    private static final class Window {
        private long start;
        private final AtomicInteger count = new AtomicInteger();

        Window(long start) {
            this.start = start;
        }
    }

    private final Map<String, Window> windows = new ConcurrentHashMap<>();

    /**
     * 尝试消费一次配额。
     *
     * @param key          限流维度，例如 {@code "register:1.2.3.4"}
     * @param limit        窗口内允许的次数，{@code <= 0} 表示不限
     * @param windowMillis 窗口长度（毫秒）
     * @return true = 允许，false = 已超限
     */
    public boolean allow(String key, int limit, long windowMillis) {
        if (limit <= 0) {
            return true;
        }
        long now = System.currentTimeMillis();
        Window window = windows.compute(key, (ignored, existing) -> {
            if (existing == null || now - existing.start >= windowMillis) {
                return new Window(now);
            }
            return existing;
        });
        return window.count.incrementAndGet() <= limit;
    }

    /** 当前窗口内已消费的次数 */
    public int count(String key, long windowMillis) {
        Window window = windows.get(key);
        if (window == null) {
            return 0;
        }
        if (System.currentTimeMillis() - window.start >= windowMillis) {
            windows.remove(key, window);
            return 0;
        }
        return window.count.get();
    }

    /** 归还一次配额（例如注册流程中途失败时） */
    public void refund(String key) {
        Window window = windows.get(key);
        if (window != null) {
            window.count.updateAndGet(value -> Math.max(0, value - 1));
        }
    }

    /** 清掉某个前缀下的所有窗口，例如玩家解封后重置 */
    public void clearPrefix(String prefix) {
        String normalized = prefix.toLowerCase(Locale.ROOT);
        windows.keySet().removeIf(key -> key.toLowerCase(Locale.ROOT).startsWith(normalized));
    }

    public void clear() {
        windows.clear();
    }

    /** 定期清理过期窗口，避免长期运行内存缓慢增长 */
    public void sweep(long windowMillis) {
        long now = System.currentTimeMillis();
        windows.entrySet().removeIf(entry -> now - entry.getValue().start >= windowMillis);
    }
}
