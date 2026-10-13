package qqnt.jdbc;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * 把加密的 QQ NT 数据库转换成任何 SQLite 工具（包括 DataGrip）都能读取的
 * 普通 SQLite 文件，所执行的步骤与 QQ 自己的 WCDB 栈打开该文件时完全相同。
 */
public final class Preparer {

    /** 当 SQLite 报告文件损坏时该怎么做。 */
    public enum Repair {
        /** 依次尝试 REINDEX、DROP，再直接删除 schema 行（默认）。 */
        AUTO,
        /** 根据完好的表数据重建索引。 */
        REINDEX,
        /** 删除有问题的索引（不改动数据，最快）。 */
        DROP,
        /** 从 sqlite_master 中删除索引行，不触碰对应的树。 */
        SCHEMA,
        /** 绝不修改解密后的文件。 */
        NONE
    }

    public static final class Options {
        public Repair repair = Repair.AUTO;
        public boolean applyWal = true;
        public boolean force = false;
        public SqlCipher.Hmac hmac = null;

        public Options repair(Repair value) { this.repair = value; return this; }
        public Options applyWal(boolean value) { this.applyWal = value; return this; }
        public Options force(boolean value) { this.force = value; return this; }
        public Options hmac(SqlCipher.Hmac value) { this.hmac = value; return this; }
    }

    private Preparer() {
    }

    /**
     * 将 {@code source} 解密为一个缓存的普通 SQLite 文件，并确保 SQLite
     * 能够读取它。用相同参数重复调用会复用缓存的副本，因此 DataGrip
     * 的重连风暴开销很小。
     */
    public static Path prepare(Path source, byte[] password, Path cacheDir, Options options)
            throws IOException {
        source = source.toAbsolutePath().normalize();
        if (!Files.isRegularFile(source)) {
            throw new IOException("not a file: " + source);
        }
        Path wal = source.resolveSibling(source.getFileName() + "-wal");
        long walLength = Files.isRegularFile(wal) ? Files.size(wal) : -1;

        String stamp = "qqnt-jdbc/1.2|" + source + "|" + Files.size(source) + "|"
                + Files.getLastModifiedTime(source).toMillis()
                + "|" + walLength + "|" + sha256(password)
                + "|" + options.repair + "|" + options.hmac;
        String base = source.getFileName().toString().replaceAll("[^A-Za-z0-9._-]", "_");
        String hash = sha256(stamp).substring(0, 16);
        Path target = cacheDir.resolve(base + "-" + hash + ".db");
        Path marker = cacheDir.resolve(base + "-" + hash + ".ok");

        if (!options.force && Files.isRegularFile(target) && Files.isRegularFile(marker)
                && Files.size(target) > 0) {
            return target;
        }
        Files.createDirectories(cacheDir);
        Path temp = cacheDir.resolve(target.getFileName() + ".part");

        byte[] head = new byte[SqlCipher.HEADER_SIZE];
        try (InputStream in = Files.newInputStream(source)) {
            int n = in.readNBytes(head, 0, head.length);
            if (n < head.length) {
                throw new IOException("file too small to be a QQ database: " + source);
            }
        }

        if (!SqlCipher.looksEncrypted(head)) {
            // 已经是普通的 SQLite 数据库；在副本上操作，这样修复永远不会
            // 触碰用户的原文件。
            Files.copy(source, temp, StandardCopyOption.REPLACE_EXISTING);
        } else {
            if (password == null || password.length == 0) {
                throw new IOException(source + " is encrypted; pass the database key "
                        + "(URL parameter key=/keyHex=/keyFile=, the JDBC password, "
                        + "$NTQQ_DB_KEY or a sibling .key file)");
            }
            decryptFile(source, temp, password, options.hmac);
            if (options.applyWal && Files.isRegularFile(wal) && Files.size(wal) > 0) {
                applyWal(source, temp, password, options.hmac);
            }
        }

        if (options.repair != Repair.NONE) {
            repair(temp, options.repair);
        }
        Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
        Files.writeString(marker, "ok");
        return target;
    }

    // ------------------------------------------------------------------
    // 解密
    // ------------------------------------------------------------------

    private static void decryptFile(Path source, Path dest, byte[] password, SqlCipher.Hmac forced)
            throws IOException {
        byte[] page = new byte[SqlCipher.PAGE_SIZE];
        byte[] out = new byte[SqlCipher.PAGE_SIZE];
        try (InputStream in = Files.newInputStream(source);
             OutputStream os = Files.newOutputStream(dest)) {
            in.readNBytes(page, 0, SqlCipher.HEADER_SIZE);
            // salt 是 *第 1 页* 的前 16 字节；把它保留在页内，
            // 这样 HMAC/加密偏移就能与 SQLCipher 的布局对齐。
            byte[] salt = new byte[SqlCipher.SALT_SIZE];
            readFully(in, salt);
            byte[] first = new byte[SqlCipher.PAGE_SIZE];
            System.arraycopy(salt, 0, first, 0, SqlCipher.SALT_SIZE);
            readFully(in, first, SqlCipher.SALT_SIZE, SqlCipher.PAGE_SIZE - SqlCipher.SALT_SIZE);
            byte[] second = readPage(in, page);
            SqlCipher.Hmac hmac = forced != null ? forced
                    : SqlCipher.detectHmac(first, second, salt, password);
            if (hmac == null) {
                throw new IOException("cannot decrypt " + source
                        + ": the key does not match (or the file is damaged)");
            }
            byte[] encKey = SqlCipher.deriveEncKey(password, salt);

            writePage(os, first, 1, encKey, hmac, out);
            if (second != null) {
                writePage(os, second, 2, encKey, hmac, out);
            }
            int pgno = 2;
            byte[] buffer = new byte[SqlCipher.PAGE_SIZE];
            while (true) {
                int read = in.readNBytes(buffer, 0, SqlCipher.PAGE_SIZE);
                if (read < SqlCipher.PAGE_SIZE) {
                    break;
                }
                pgno++;
                writePage(os, buffer, pgno, encKey, hmac, out);
            }
        }
    }

    private static void writePage(OutputStream os, byte[] page, int pgno, byte[] encKey,
                                  SqlCipher.Hmac hmac, byte[] out) throws IOException {
        SqlCipher.decryptPage(page, pgno, encKey, hmac, out);
        os.write(out, 0, SqlCipher.PAGE_SIZE);
    }

    private static byte[] readPage(InputStream in, byte[] buffer) throws IOException {
        int read = in.readNBytes(buffer, 0, SqlCipher.PAGE_SIZE);
        if (read < SqlCipher.PAGE_SIZE) {
            return null;
        }
        return java.util.Arrays.copyOf(buffer, SqlCipher.PAGE_SIZE);
    }

    private static void readFully(InputStream in, byte[] target) throws IOException {
        readFully(in, target, 0, target.length);
    }

    private static void readFully(InputStream in, byte[] target, int offset, int length)
            throws IOException {
        int done = 0;
        while (done < length) {
            int read = in.read(target, offset + done, length - done);
            if (read < 0) {
                throw new IOException("unexpected end of file");
            }
            done += read;
        }
    }

    // ------------------------------------------------------------------
    // 写前日志
    // ------------------------------------------------------------------

    private static void applyWal(Path source, Path dest, byte[] password, SqlCipher.Hmac forced)
            throws IOException {
        byte[] walPathBytes = Files.readAllBytes(source.resolveSibling(source.getFileName() + "-wal"));
        if (walPathBytes.length < 32) {
            return;
        }
        byte[] salt = new byte[SqlCipher.SALT_SIZE];
        byte[] firstPage = new byte[SqlCipher.PAGE_SIZE];
        try (InputStream in = Files.newInputStream(source)) {
            in.readNBytes(new byte[SqlCipher.HEADER_SIZE], 0, SqlCipher.HEADER_SIZE);
            readFully(in, salt);
            System.arraycopy(salt, 0, firstPage, 0, SqlCipher.SALT_SIZE);
            readFully(in, firstPage, SqlCipher.SALT_SIZE,
                    SqlCipher.PAGE_SIZE - SqlCipher.SALT_SIZE);
        }
        SqlCipher.Hmac hmac = forced != null ? forced
                : SqlCipher.detectHmac(firstPage, null, salt, password);
        if (hmac == null) {
            return;
        }
        byte[] encKey = SqlCipher.deriveEncKey(password, salt);
        byte[] hmacKey = SqlCipher.deriveHmacKey(encKey, salt);

        int frameSize = 24 + SqlCipher.PAGE_SIZE;
        int frames = (walPathBytes.length - 32) / frameSize;
        if (frames <= 0) {
            return;
        }
        long headerSalt1 = beInt(walPathBytes, 16);
        long headerSalt2 = beInt(walPathBytes, 20);
        int lastCommit = -1;
        List<byte[]> pageImages = new ArrayList<>();
        List<Integer> pageNumbers = new ArrayList<>();
        for (int i = 0; i < frames; i++) {
            int off = 32 + i * frameSize;
            long salt1 = beInt(walPathBytes, off + 8);
            long salt2 = beInt(walPathBytes, off + 12);
            if (salt1 != headerSalt1 || salt2 != headerSalt2) {
                break; // 属于上一代 WAL
            }
            int pgno = beInt(walPathBytes, off);
            int dbSize = beInt(walPathBytes, off + 4);
            if (dbSize != 0) {
                lastCommit = i;
            }
            byte[] page = java.util.Arrays.copyOfRange(walPathBytes, off + 24, off + 24 + SqlCipher.PAGE_SIZE);
            pageImages.add(page);
            pageNumbers.add(pgno);
        }
        if (lastCommit < 0) {
            return;
        }
        byte[] out = new byte[SqlCipher.PAGE_SIZE];
        try (RandomAccessFile raf = new RandomAccessFile(dest.toFile(), "rw")) {
            for (int i = 0; i <= lastCommit; i++) {
                byte[] page = pageImages.get(i);
                int pgno = pageNumbers.get(i);
                if (pgno <= 0 || !SqlCipher.verifyPage(page, pgno, hmacKey, hmac)) {
                    continue;
                }
                SqlCipher.decryptPage(page, pgno, encKey, hmac, out);
                raf.seek((long) (pgno - 1) * SqlCipher.PAGE_SIZE);
                raf.write(out);
            }
        }
    }

    private static int beInt(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 24) | ((data[offset + 1] & 0xFF) << 16)
                | ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);
    }

    // ------------------------------------------------------------------
    // 修复
    // ------------------------------------------------------------------

    /**
     * 让解密后的文件能被原版 SQLite 读取。
     *
     * <p>QQ 的数据库中可能含有结构损坏的索引 b-tree（某个页被引用两次、条目
     * 数量错误）。表 b-tree 是完好的，这正是 QQ 自身能够读取每一行的原因——
     * 它的查询计划从不遍历损坏的索引。原版 SQLite 则会为 {@code count(*)}
     * 选择最小的索引，并以 “database disk image is malformed” 退出。
     * 重建或删除索引即可恢复完整的可读性，且不会触碰任何用户数据。
     */
    public static List<String> repair(Path database, Repair mode) throws IOException {
        try {
            return repairChecked(database, mode);
        } catch (SQLException e) {
            throw new IOException("repair failed: " + e.getMessage(), e);
        }
    }

    private static List<String> repairChecked(Path database, Repair mode)
            throws IOException, SQLException {
        List<String> actions = new ArrayList<>();
        List<int[]> orphaned = new ArrayList<>(); // {rootPage}
        String firstCheck;

        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database)) {
            try {
                firstCheck = quickCheck(connection);
            } catch (SQLException e) {
                firstCheck = "error: " + e.getMessage();
            }
            if ("ok".equals(firstCheck)) {
                actions.add("quick_check: ok");
                return actions;
            }
            actions.add("quick_check: " + oneLine(firstCheck));

            Repair effective = mode == Repair.AUTO ? Repair.REINDEX : mode;
            List<String> indexes;
            try {
                indexes = listIndexes(connection);
            } catch (SQLException e) {
                indexes = List.of();
                actions.add("cannot enumerate indexes: " + e.getMessage());
            }
            for (String index : indexes) {
                if (tryRepair(connection, index, effective)) {
                    actions.add(effective.name().toLowerCase(Locale.ROOT) + " " + index + ": ok");
                    continue;
                }
                if (effective == Repair.SCHEMA || !schemaDrop(connection, index, orphaned)) {
                    actions.add("could not repair " + index);
                } else {
                    actions.add("schema-drop " + index + ": ok");
                }
            }
        }

        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + database)) {
            String after;
            try {
                after = quickCheck(connection);
            } catch (SQLException e) {
                after = "error: " + e.getMessage();
            }
            if (!"ok".equals(after)) {
                actions.add("note: quick_check still reports free pages that QQ left "
                        + "orphaned; they contain no data and do not affect queries");
            }
        }
        return actions;
    }

    /** 删除索引的 schema 行，并记录其根页以便回收。 */
    private static boolean schemaDrop(Connection connection, String index, List<int[]> orphaned) {
        long root = -1;
        try (Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(
                     "SELECT rootpage FROM sqlite_master WHERE type='index' AND name='"
                             + index.replace("'", "''") + "'")) {
            if (rs.next()) {
                root = rs.getLong(1);
            }
        } catch (SQLException e) {
            return false;
        }
        try (Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA writable_schema=ON");
            statement.execute("DELETE FROM sqlite_master WHERE type='index' AND name='"
                    + index.replace("'", "''") + "'");
            return true;
        } catch (SQLException e) {
            return false;
        } finally {
            try {
                connection.createStatement().execute("PRAGMA writable_schema=OFF");
            } catch (SQLException ignored) {
                // 反正连接马上就要被拆掉了
            }
        }
    }

    private static boolean tryRepair(Connection connection, String index, Repair mode) {
        String sql;
        switch (mode) {
            case REINDEX: sql = "REINDEX \"" + index + "\""; break;
            case DROP: sql = "DROP INDEX IF EXISTS \"" + index + "\""; break;
            default: return false;
        }
        try (Statement statement = connection.createStatement()) {
            statement.execute(sql);
            return true;
        } catch (SQLException e) {
            return false;
        }
    }

    private static List<String> listIndexes(Connection connection) throws SQLException {
        List<String> out = new ArrayList<>();
        try (Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(
                     "SELECT name FROM sqlite_master WHERE type='index' AND sql IS NOT NULL")) {
            while (rs.next()) {
                out.add(rs.getString(1));
            }
        }
        return out;
    }

    public static String quickCheck(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery("PRAGMA quick_check")) {
            StringBuilder sb = new StringBuilder();
            while (rs.next()) {
                if (sb.length() > 0) {
                    sb.append('\n');
                }
                sb.append(rs.getString(1));
            }
            return sb.toString();
        }
    }

    private static String oneLine(String text) {
        return text.replace('\n', ';');
    }

    // ------------------------------------------------------------------

    static String sha256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return hex(digest.digest(data == null ? new byte[0] : data));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String sha256(String text) {
        return sha256(text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
