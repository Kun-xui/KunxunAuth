package com.kunxun.auth.mail;

import com.kunxun.auth.config.AuthConfig;
import com.kunxun.auth.util.Text;
import jakarta.mail.Authenticator;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;

import java.io.File;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Date;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * SMTP 发信服务。
 *
 * <p>用 Jakarta Mail（Angus Mail 实现，QQ 邮箱 587 端口走 STARTTLS）。
 * 发信放在独立线程池里执行，避免验证码邮件把服务器主线程卡住；
 * 调用方拿到的是 {@link CompletableFuture}，可以自由设置等待上限。
 */
public final class MailService implements AutoCloseable {

    private static final String FALLBACK_TEMPLATE = """
            <!DOCTYPE html>
            <html lang="zh-CN"><head><meta charset="utf-8"></head>
            <body style="font-family:sans-serif;background:#f4f5f7;padding:24px">
              <div style="max-width:520px;margin:0 auto;background:#fff;border-radius:12px;padding:28px">
                <h2 style="margin:0 0 12px;color:#1f6feb">{server} 登录验证码</h2>
                <p style="color:#444;line-height:1.7">你好 {player}，你的验证码是：</p>
                <p style="font-size:30px;letter-spacing:8px;font-weight:700;color:#1f6feb">{code}</p>
                <p style="color:#888;font-size:13px">验证码 {minutes} 分钟内有效，请勿转发给他人。</p>
              </div>
            </body></html>
            """;

    private final AuthConfig.MailSettings settings;
    private final Logger logger;
    private final Session session;
    private final ExecutorService executor;
    private final String template;
    private final boolean available;

    public MailService(AuthConfig.MailSettings settings, File dataFolder, Logger logger) {
        this.settings = settings;
        this.logger = logger;
        this.template = loadTemplate(dataFolder);
        this.available = settings.enable()
                && !settings.account().isBlank()
                && !settings.password().isBlank();

        ThreadFactory factory = new ThreadFactory() {
            private final AtomicInteger counter = new AtomicInteger();

            @Override
            public Thread newThread(Runnable runnable) {
                Thread thread = new Thread(runnable, "KunxunAuth-Mail-" + counter.incrementAndGet());
                thread.setDaemon(true);
                return thread;
            }
        };
        this.executor = Executors.newFixedThreadPool(2, factory);
        this.session = available ? buildSession(settings) : null;
        if (!available && settings.enable()) {
            logger.warning("[KunxunAuth] 邮件服务未启用：mail.account / mail.password 为空，"
                    + "注册流程将退化为「直接设置密码」模式。");
        }
    }

    public boolean available() {
        return available;
    }

    private static Session buildSession(AuthConfig.MailSettings settings) {
        Properties props = new Properties();
        props.put("mail.transport.protocol", "smtp");
        props.put("mail.smtp.host", settings.host());
        props.put("mail.smtp.port", String.valueOf(settings.port()));
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.ssl.enable", String.valueOf(settings.ssl()));
        if (settings.starttls()) {
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.starttls.required", "true");
        }
        // 部分邮件服务商的证书链在 JRE 里不全，显式信任目标主机可避免握手失败
        props.put("mail.smtp.ssl.trust", settings.host());
        props.put("mail.smtp.connectiontimeout", String.valueOf(settings.connectionTimeoutMs()));
        props.put("mail.smtp.timeout", String.valueOf(settings.connectionTimeoutMs()));
        props.put("mail.smtp.writetimeout", String.valueOf(settings.connectionTimeoutMs()));

        return Session.getInstance(props, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(settings.account(), settings.password());
            }
        });
    }

    private static String loadTemplate(File dataFolder) {
        File file = new File(dataFolder, "email-template.html");
        if (file.isFile()) {
            try {
                String content = Files.readString(file.toPath(), StandardCharsets.UTF_8);
                if (!content.isBlank()) {
                    return content;
                }
            } catch (Exception e) {
                // 读失败就用内建模板
            }
        }
        try (InputStream in = MailService.class.getResourceAsStream("/email-template.html")) {
            if (in != null) {
                String content = new String(in.readAllBytes(), StandardCharsets.UTF_8);
                if (!content.isBlank()) {
                    return content;
                }
            }
        } catch (Exception ignored) {
            // 落到硬编码兜底
        }
        return FALLBACK_TEMPLATE;
    }

    /**
     * 异步发送验证码邮件。
     *
     * @return true = 已成功投递到 SMTP 服务器
     */
    public CompletableFuture<Boolean> sendVerificationCode(String email, String player, String code,
                                                           int expireMinutes) {
        if (!available) {
            return CompletableFuture.completedFuture(false);
        }
        return CompletableFuture.supplyAsync(() -> {
            try {
                send(email, player, code, expireMinutes);
                return true;
            } catch (Exception e) {
                logger.log(Level.WARNING, "[KunxunAuth] 验证码邮件发送失败 → " + email + " : " + e.getMessage(), e);
                return false;
            }
        }, executor);
    }

    private void send(String email, String player, String code, int expireMinutes) throws MessagingException {
        String html = Text.fill(template,
                "player", player,
                "code", code,
                "minutes", expireMinutes,
                "server", settings.serverName());

        MimeMessage message = new MimeMessage(session);
        message.setFrom(fromAddress());
        message.setRecipient(Message.RecipientType.TO, new InternetAddress(email));
        message.setSubject(settings.subject(), StandardCharsets.UTF_8.name());
        message.setSentDate(new Date());
        message.setHeader("X-Mailer", "KunxunAuth");

        MimeBodyPart plainPart = new MimeBodyPart();
        plainPart.setText("你好 " + player + "，你的验证码是 " + code + "，"
                + expireMinutes + " 分钟内有效。若不是你本人操作请忽略本邮件。", StandardCharsets.UTF_8.name());

        MimeBodyPart htmlPart = new MimeBodyPart();
        htmlPart.setContent(html, "text/html; charset=UTF-8");

        MimeMultipart multipart = new MimeMultipart("alternative");
        multipart.addBodyPart(plainPart);
        multipart.addBodyPart(htmlPart);
        message.setContent(multipart);

        Transport.send(message);
    }

    /** 构造发件人地址（含中文显示名） */
    private InternetAddress fromAddress() throws MessagingException {
        try {
            return new InternetAddress(settings.account(), settings.senderName(),
                    StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            // UTF-8 一定存在，这里只是把受检异常转成 MessagingException
            throw new MessagingException("发件人显示名编码失败: " + e.getMessage(), e);
        }
    }

    @Override
    public void close() {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(3, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            executor.shutdownNow();
        }
    }
}
