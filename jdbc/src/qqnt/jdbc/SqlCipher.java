package qqnt.jdbc;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Linux QQ NT 客户端所使用的 SQLCipher 页加解密。
 *
 * <p>这是在客户端自身的二进制文件与一个运行中的进程之上做出的净室重实现；
 * 完整的推导过程见仓库 README。概要：
 *
 * <ul>
 *   <li>容器头：1024 字节明文头，其后紧跟数据库，数据库的前 16 字节是
 *       SQLCipher 的 salt；</li>
 *   <li>密钥派生：PBKDF2-HMAC-SHA512，4000 次迭代，256 位密钥；</li>
 *   <li>HMAC 密钥：PBKDF2-HMAC-SHA512(encKey, salt XOR 0x3a, 2 次迭代)；</li>
 *   <li>页：{@code content | IV(16) | HMAC | padding}，第 1 页的前 16 字节
 *       保留 salt，此处的明文即为 SQLite magic。</li>
 * </ul>
 */
public final class SqlCipher {

    public static final int HEADER_SIZE = 1024;
    public static final int PAGE_SIZE = 4096;
    public static final int SALT_SIZE = 16;
    public static final int IV_SIZE = 16;
    public static final int KDF_ITERATIONS = 4000;
    public static final int KEY_SIZE = 32;
    public static final byte HMAC_SALT_MASK = 0x3A;
    public static final byte[] SQLITE_MAGIC =
            "SQLite format 3\0".getBytes(StandardCharsets.US_ASCII);

    private SqlCipher() {
    }

    /** 页认证算法；QQ 对大多数文件使用 SHA1，对 guild1.db 使用 SHA512。 */
    public enum Hmac {
        SHA1("HmacSHA1", 20),
        SHA512("HmacSHA512", 64),
        SHA256("HmacSHA256", 32);

        public final String jce;
        public final int size;

        Hmac(String jce, int size) {
            this.jce = jce;
            this.size = size;
        }

        /** IV 加摘要，向上取整到下一个 AES 块。 */
        public int reserve() {
            return ((IV_SIZE + size + 15) / 16) * 16;
        }

        public static Hmac of(String name) {
            if (name == null || name.isEmpty() || name.equalsIgnoreCase("auto")) {
                return null;
            }
            switch (name.toLowerCase().replace("-", "")) {
                case "sha1": return SHA1;
                case "sha256": return SHA256;
                case "sha512": return SHA512;
                default: throw new IllegalArgumentException("unknown hmac: " + name);
            }
        }
    }

    public static byte[] deriveEncKey(byte[] password, byte[] salt) {
        return pbkdf2("HmacSHA512", password, salt, KDF_ITERATIONS, KEY_SIZE);
    }

    public static byte[] deriveHmacKey(byte[] encKey, byte[] salt) {
        byte[] masked = new byte[salt.length];
        for (int i = 0; i < salt.length; i++) {
            masked[i] = (byte) (salt[i] ^ HMAC_SALT_MASK);
        }
        return pbkdf2("HmacSHA512", encKey, masked, 2, KEY_SIZE);
    }

    /** 字节精确的 PBKDF2（JCE 的 PBEKeySpec 会破坏非 ASCII 口令）。 */
    public static byte[] pbkdf2(String macAlgorithm, byte[] password, byte[] salt,
                                int iterations, int keyLength) {
        try {
            Mac mac = Mac.getInstance(macAlgorithm);
            mac.init(new SecretKeySpec(password, macAlgorithm));
            int hLen = mac.getMacLength();
            int blocks = (keyLength + hLen - 1) / hLen;
            byte[] out = new byte[blocks * hLen];
            byte[] block = new byte[hLen];
            byte[] u = new byte[hLen];
            for (int i = 1; i <= blocks; i++) {
                mac.update(salt);
                mac.update((byte) (i >>> 24));
                mac.update((byte) (i >>> 16));
                mac.update((byte) (i >>> 8));
                mac.update((byte) i);
                mac.doFinal(u, 0);
                System.arraycopy(u, 0, block, 0, hLen);
                for (int c = 1; c < iterations; c++) {
                    u = mac.doFinal(u);
                    for (int k = 0; k < hLen; k++) {
                        block[k] ^= u[k];
                    }
                }
                System.arraycopy(block, 0, out, (i - 1) * hLen, hLen);
            }
            return Arrays.copyOf(out, keyLength);
        } catch (Exception e) {
            throw new IllegalStateException("PBKDF2 failed", e);
        }
    }

    private static byte[] hmacInput(byte[] page, int pgno, Hmac hmac) {
        int reserve = hmac.reserve();
        int contentEnd = PAGE_SIZE - reserve;
        int skip = pgno == 1 ? SALT_SIZE : 0;
        int contentLength = contentEnd - skip;
        byte[] data = new byte[contentLength + IV_SIZE + 4];
        System.arraycopy(page, skip, data, 0, contentLength);
        System.arraycopy(page, contentEnd, data, contentLength, IV_SIZE);
        int p = contentLength + IV_SIZE;
        data[p] = (byte) pgno;
        data[p + 1] = (byte) (pgno >>> 8);
        data[p + 2] = (byte) (pgno >>> 16);
        data[p + 3] = (byte) (pgno >>> 24);
        return data;
    }

    public static boolean verifyPage(byte[] page, int pgno, byte[] hmacKey, Hmac hmac) {
        if (page.length < PAGE_SIZE - hmac.reserve() + IV_SIZE + hmac.size) {
            return false;
        }
        try {
            Mac mac = Mac.getInstance(hmac.jce);
            mac.init(new SecretKeySpec(hmacKey, hmac.jce));
            byte[] digest = mac.doFinal(hmacInput(page, pgno, hmac));
            int reserve = hmac.reserve();
            int hmacOffset = PAGE_SIZE - reserve + IV_SIZE;
            for (int i = 0; i < hmac.size; i++) {
                if (digest[i] != page[hmacOffset + i]) {
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 将一页解密到 {@code out}（一个 {@link #PAGE_SIZE} 字节的数组）。
     *
     * <p>保留区会被填充为零：SQLite 从不使用它，那里的原始字节是
     * SQLCipher 的 IV/HMAC 簿记数据。
     */
    public static void decryptPage(byte[] page, int pgno, byte[] encKey, Hmac hmac, byte[] out) {
        int reserve = hmac.reserve();
        int contentEnd = PAGE_SIZE - reserve;
        int skip = pgno == 1 ? SALT_SIZE : 0;
        int contentLength = contentEnd - skip;
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encKey, "AES"),
                    new IvParameterSpec(page, contentEnd, IV_SIZE));
            cipher.doFinal(page, skip, contentLength, out, skip);
            if (pgno == 1) {
                System.arraycopy(SQLITE_MAGIC, 0, out, 0, SQLITE_MAGIC.length);
            }
            for (int i = contentEnd; i < PAGE_SIZE; i++) {
                out[i] = 0;
            }
        } catch (Exception e) {
            throw new IllegalStateException("page " + pgno + " decryption failed", e);
        }
    }

    /** 尝试所有可能的 HMAC 算法，返回其中能够验证通过的那一个。 */
    public static Hmac detectHmac(byte[] page1, byte[] page2, byte[] salt, byte[] password) {
        byte[] encKey = deriveEncKey(password, salt);
        byte[] hmacKey = deriveHmacKey(encKey, salt);
        for (Hmac candidate : new Hmac[]{Hmac.SHA1, Hmac.SHA512, Hmac.SHA256}) {
            if (verifyPage(page1, 1, hmacKey, candidate)
                    && (page2 == null || verifyPage(page2, 2, hmacKey, candidate))) {
                return candidate;
            }
        }
        return null;
    }

    public static boolean looksEncrypted(byte[] head) {
        // 加密的 QQ 数据库以诱饵 magic 开头；而普通的 SQLite
        // 文件以 "SQLite format 3\0" 开头。
        return head.length >= HEADER_SIZE
                && !Arrays.equals(Arrays.copyOf(head, 16), SQLITE_MAGIC);
    }
}
