package qqnt.jdbc;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.Locale;
import java.util.Properties;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * QQ NT 数据库的 JDBC 驱动。
 *
 * <p>连接方式
 *
 * <pre>jdbc:qqnt:/home/me/.config/QQ/nt_qq_&lt;profile&gt;/nt_db/nt_msg.db?key=&lt;passphrase&gt;</pre>
 *
 * 该驱动完全按照 QQ 自身 WCDB 栈的方式解密 SQLCipher 容器（包括
 * {@code -wal} 文件），修复 QQ 留下的结构不一致的索引 b-tree，然后把
 * 明文数据库交给内置的 SQLite 引擎。因此 DataGrip 看到的是一个普通的、
 * 完全可读的 SQLite schema，且每一行都完好无损。
 *
 * <p>支持的 URL 参数：
 * <table>
 *   <tr><td>{@code key}</td><td>口令（原始文本）</td></tr>
 *   <tr><td>{@code keyHex}</td><td>以十六进制表示的口令</td></tr>
 *   <tr><td>{@code keyFile}</td><td>包含 {@code "passphrase"} 的 JSON 文件</td></tr>
 *   <tr><td>{@code cache}</td><td>解密副本的存放目录</td></tr>
 *   <tr><td>{@code repair}</td><td>{@code auto}（默认）、{@code reindex}、
 *       {@code drop}、{@code schema}、{@code none}</td></tr>
 *   <tr><td>{@code wal}</td><td>{@code true}（默认）/ {@code false}</td></tr>
 *   <tr><td>{@code hmac}</td><td>{@code auto}（默认）、{@code sha1}、{@code sha512}</td></tr>
 *   <tr><td>{@code force}</td><td>{@code true} 表示即使已有缓存也重新解密</td></tr>
 * </table>
 *
 * <p>密钥也可以通过 JDBC 的 {@code password} 属性提供，这样 DataGrip
 * 便能把它保存在自己的凭据库中。
 */
public class Driver implements java.sql.Driver {

    public static final String URL_PREFIX = "jdbc:qqnt:";
    /** 同样接受该前缀，以便打开普通（已解密）的数据库。 */
    public static final String SQLITE_PREFIX = "jdbc:sqlite:";
    private static final Pattern JSON_PASSPHRASE =
            Pattern.compile("\"passphrase\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");

    static {
        try {
            DriverManager.registerDriver(new Driver());
        } catch (SQLException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @Override
    public Connection connect(String url, Properties info) throws SQLException {
        if (!acceptsURL(url)) {
            return null;
        }
        if (url.regionMatches(true, 0, SQLITE_PREFIX, 0, SQLITE_PREFIX.length())) {
            return connectPlain(url, info);
        }
        try {
            Path source = sourcePath(url);
            byte[] key = resolveKey(url, info, source);
            Preparer.Options options = options(url);
            Path cache = cacheDir(url);
            Path plain = key == null
                    ? source
                    : Preparer.prepare(source, key, cache, options);
            Connection connection = DriverManager.getConnection("jdbc:sqlite:" + plain);
            return connection;
        } catch (IOException e) {
            throw new SQLException(e.getMessage(), e);
        }
    }

    /**
     * 处理普通的 {@code jdbc:sqlite:} URL。
     *
     * <p>没有 {@code repair=} 参数时，URL 会原样交给内置的 SQLite 引擎。
     * 带有该参数时（例如 {@code ?repair=schema}），文件会先被复制到缓存中
     * 并完成修复，这正是让索引 b-tree 仍损坏的解密后 QQ 数据库变得完全
     * 可读的原因。
     */
    private Connection connectPlain(String url, Properties info) throws SQLException {
        String repair = query(url).getProperty("repair");
        if (repair == null || repair.isEmpty() || repair.equalsIgnoreCase("none")) {
            return new org.sqlite.JDBC().connect(url, info);
        }
        try {
            String rest = url.substring(SQLITE_PREFIX.length());
            int q = rest.indexOf('?');
            Path source = Paths.get(decode(q >= 0 ? rest.substring(0, q) : rest));
            Preparer.Options options = options(url);
            options.repair = Preparer.Repair.valueOf(repair.toUpperCase(Locale.ROOT));
            Path plain = Preparer.prepare(source, null, cacheDir(url), options);
            return new org.sqlite.JDBC().connect("jdbc:sqlite:" + plain, info);
        } catch (IOException e) {
            throw new SQLException(e.getMessage(), e);
        }
    }

    // ------------------------------------------------------------------

    private static Path sourcePath(String url) throws SQLException {
        String rest = url.substring(URL_PREFIX.length());
        int q = rest.indexOf('?');
        String path = q >= 0 ? rest.substring(0, q) : rest;
        path = decode(path);
        if (path.isEmpty()) {
            throw new SQLException("no database path in URL: " + url);
        }
        Path p = Paths.get(path);
        if (Files.isDirectory(p)) {
            // 传入的是 profile 目录：默认使用其中的主数据库。
            Path candidate = p.resolve("nt_msg.db");
            p = Files.isRegularFile(candidate) ? candidate : p;
        }
        return p;
    }

    /**
     * 百分号解码，其中 {@code +} 按字面量处理。
     *
     * <p>{@link java.net.URLDecoder} 实现的是 HTML 表单解码，其中
     * {@code +} 表示空格——这会静默破坏诸如
     * {@code 114514+1919810?x} 这样的口令。
     */
    static String decode(String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream(bytes.length);
        for (int i = 0; i < bytes.length; i++) {
            int c = bytes[i] & 0xFF;
            if (c == '%' && i + 2 < bytes.length) {
                int hi = Character.digit((char) bytes[i + 1], 16);
                int lo = Character.digit((char) bytes[i + 2], 16);
                if (hi >= 0 && lo >= 0) {
                    out.write((hi << 4) | lo);
                    i += 2;
                    continue;
                }
            }
            out.write(c);
        }
        return out.toString(StandardCharsets.UTF_8);
    }

    private static Properties query(String url) {
        Properties properties = new Properties();
        int q = url.indexOf('?');
        if (q < 0) {
            return properties;
        }
        for (String pair : url.substring(q + 1).split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int eq = pair.indexOf('=');
            String name = eq < 0 ? pair : pair.substring(0, eq);
            String value = eq < 0 ? "" : pair.substring(eq + 1);
            properties.setProperty(
                    decode(name).toLowerCase(Locale.ROOT),
                    decode(value));
        }
        return properties;
    }

    private static byte[] resolveKey(String url, Properties info, Path source) throws SQLException {
        Properties q = query(url);
        String hex = q.getProperty("keyhex", info == null ? null : info.getProperty("keyHex"));
        if (hex != null && !hex.isEmpty()) {
            return fromHex(hex);
        }
        String text = q.getProperty("key");
        if (text == null && info != null) {
            text = info.getProperty("key");
        }
        if (text == null && info != null) {
            text = info.getProperty("password");
        }
        if (text == null || text.isEmpty()) {
            String keyFile = q.getProperty("keyfile");
            if (keyFile != null && !keyFile.isEmpty()) {
                text = readKeyFile(Paths.get(keyFile), source);
            }
        }
        if (text == null || text.isEmpty()) {
            text = System.getenv("NTQQ_DB_KEY");
        }
        if (text == null || text.isEmpty()) {
            Path sibling = source.resolveSibling(source.getFileName() + ".key");
            if (Files.isRegularFile(sibling)) {
                try {
                    text = Files.readString(sibling).trim();
                } catch (IOException e) {
                    throw new SQLException("cannot read " + sibling + ": " + e.getMessage(), e);
                }
            }
        }
        return text == null || text.isEmpty() ? null : text.getBytes(StandardCharsets.UTF_8);
    }

    private static String readKeyFile(Path file, Path source) throws SQLException {
        try {
            String content = Files.readString(file);
            String profile = null;
            Path parent = source.getParent();
            if (parent != null && parent.getParent() != null) {
                profile = parent.getParent().getFileName().toString();
            }
            if (profile != null) {
                Matcher m = Pattern.compile(
                        "\"" + Pattern.quote(profile) + "\"\\s*:\\s*\\{[^}]*?\"passphrase\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"",
                        Pattern.DOTALL).matcher(content);
                if (m.find()) {
                    return unescape(m.group(1));
                }
            }
            Matcher m = JSON_PASSPHRASE.matcher(content);
            if (m.find()) {
                return unescape(m.group(1));
            }
            String trimmed = content.trim();
            return trimmed.isEmpty() ? null : trimmed;
        } catch (IOException e) {
            throw new SQLException("cannot read key file " + file + ": " + e.getMessage(), e);
        }
    }

    private static String unescape(String value) {
        return value.replace("\\\"", "\"").replace("\\\\", "\\").replace("\\n", "\n");
    }

    private static byte[] fromHex(String hex) throws SQLException {
        String clean = hex.trim().replace("x'", "").replace("'", "").replace(" ", "");
        if (clean.length() % 2 != 0) {
            throw new SQLException("hex key must have an even number of digits");
        }
        byte[] out = new byte[clean.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(clean.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    private static Preparer.Options options(String url) throws SQLException {
        Properties q = query(url);
        Preparer.Options options = new Preparer.Options();
        String repair = q.getProperty("repair");
        if (repair != null && !repair.isEmpty()) {
            try {
                options.repair = Preparer.Repair.valueOf(repair.toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException e) {
                throw new SQLException("unknown repair mode: " + repair);
            }
        }
        options.applyWal = !"false".equalsIgnoreCase(q.getProperty("wal"));
        options.force = "true".equalsIgnoreCase(q.getProperty("force"));
        try {
            options.hmac = SqlCipher.Hmac.of(q.getProperty("hmac"));
        } catch (IllegalArgumentException e) {
            throw new SQLException(e.getMessage());
        }
        return options;
    }

    private static Path cacheDir(String url) {
        String value = query(url).getProperty("cache");
        if (value != null && !value.isEmpty()) {
            return Paths.get(value);
        }
        String home = System.getProperty("user.home", ".");
        return Paths.get(home, ".cache", "qqnt-jdbc");
    }

    // ------------------------------------------------------------------

    @Override
    public boolean acceptsURL(String url) {
        if (url == null) {
            return false;
        }
        return url.regionMatches(true, 0, URL_PREFIX, 0, URL_PREFIX.length())
                || url.regionMatches(true, 0, SQLITE_PREFIX, 0, SQLITE_PREFIX.length());
    }

    @Override
    public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) {
        return new DriverPropertyInfo[]{
                new DriverPropertyInfo("key", info == null ? null : info.getProperty("key")),
                new DriverPropertyInfo("cache", null),
                new DriverPropertyInfo("repair", "auto"),
                new DriverPropertyInfo("wal", "true"),
                new DriverPropertyInfo("hmac", "auto"),
        };
    }

    @Override
    public int getMajorVersion() {
        return 1;
    }

    @Override
    public int getMinorVersion() {
        return 0;
    }

    @Override
    public boolean jdbcCompliant() {
        return false;
    }

    @Override
    public Logger getParentLogger() throws SQLFeatureNotSupportedException {
        throw new SQLFeatureNotSupportedException();
    }
}
