package com.kunxun.auth.util;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 * 密码哈希（PBKDF2-HMAC-SHA256）。
 *
 * <p>存储格式：{@code pbkdf2-sha256$<迭代次数>$<盐 base64>$<哈希 base64>}
 *
 * <p>每个密码独立随机盐，因此同一个密码两次注册得到的哈希不同。
 * 校验时用常量时间比较，避免计时侧信道。
 */
public final class PasswordHasher {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String ID = "pbkdf2-sha256";
    private static final String SEPARATOR = "$";
    private static final int SALT_BYTES = 16;
    private static final int KEY_BITS = 256;

    private final int iterations;
    private final SecureRandom random = new SecureRandom();

    public PasswordHasher(int iterations) {
        this.iterations = Math.max(10000, iterations);
    }

    public int iterations() {
        return iterations;
    }

    /** 生成哈希串 */
    public String hash(String password) {
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        byte[] key = derive(password, salt, iterations);
        Base64.Encoder encoder = Base64.getEncoder();
        return ID + SEPARATOR + iterations + SEPARATOR
                + encoder.encodeToString(salt) + SEPARATOR + encoder.encodeToString(key);
    }

    /** 校验密码。格式非法或算法不可用一律返回 false */
    public boolean verify(String password, String stored) {
        if (password == null || stored == null || stored.isEmpty()) {
            return false;
        }
        String[] parts = stored.split("\\" + SEPARATOR);
        if (parts.length != 4 || !ID.equals(parts[0])) {
            return false;
        }
        int storedIterations;
        byte[] salt;
        byte[] expected;
        try {
            storedIterations = Integer.parseInt(parts[1]);
            salt = Base64.getDecoder().decode(parts[2]);
            expected = Base64.getDecoder().decode(parts[3]);
        } catch (IllegalArgumentException e) {
            return false;
        }
        if (storedIterations <= 0 || salt.length == 0 || expected.length == 0) {
            return false;
        }
        byte[] actual = derive(password, salt, storedIterations, expected.length * 8);
        return MessageDigest.isEqual(expected, actual);
    }

    /** 迭代次数低于当前配置时，登录成功后应顺手重新哈希 */
    public boolean needsRehash(String stored) {
        if (stored == null || stored.isEmpty()) {
            return true;
        }
        String[] parts = stored.split("\\" + SEPARATOR);
        if (parts.length != 4 || !ID.equals(parts[0])) {
            return true;
        }
        try {
            return Integer.parseInt(parts[1]) < iterations;
        } catch (NumberFormatException e) {
            return true;
        }
    }

    private byte[] derive(String password, byte[] salt, int rounds) {
        return derive(password, salt, rounds, KEY_BITS);
    }

    private byte[] derive(String password, byte[] salt, int rounds, int keyBits) {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, rounds, keyBits);
        try {
            return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("密码哈希算法不可用: " + ALGORITHM, e);
        } finally {
            spec.clearPassword();
        }
    }
}
