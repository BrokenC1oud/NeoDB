package qqnt.jdbc;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;
import java.util.Locale;

/**
 * 小型命令行前端：使用与 JDBC 驱动相同的代码来解密、查看和修复
 * QQ NT 数据库。
 */
public final class Tool {

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            usage();
            return;
        }
        String command = args[0].toLowerCase(Locale.ROOT);
        switch (command) {
            case "decrypt": decrypt(args); break;
            case "info": info(args); break;
            case "check": check(args); break;
            case "repair": repair(args); break;
            default: usage();
        }
    }

    private static void usage() {
        System.out.println("""
                QQ NT database tool

                  decrypt <source-db> [output-db]   decrypt + WAL + repair
                  info    <source-db>               tables and row counts
                  check   <plain-db>                PRAGMA quick_check
                  repair  <plain-db> [auto|reindex|drop|schema]

                The key is read from $NTQQ_DB_KEY (or -Dqqnt.key=...).
                """);
    }

    private static byte[] key() {
        String value = System.getProperty("qqnt.key", System.getenv("NTQQ_DB_KEY"));
        return value == null || value.isEmpty() ? null : value.getBytes(StandardCharsets.UTF_8);
    }

    private static void decrypt(String[] args) throws IOException {
        if (args.length < 2) {
            usage();
            return;
        }
        Path source = Paths.get(args[1]);
        Path cache = args.length >= 3
                ? Paths.get(args[2]).getParent()
                : Paths.get(System.getProperty("user.home"), ".cache", "qqnt-jdbc");
        Path prepared = Preparer.prepare(source, key(), cache,
                new Preparer.Options().force(true));
        List<String> actions = Preparer.repair(prepared, Preparer.Repair.AUTO);
        System.out.println("plain database: " + prepared);
        actions.forEach(a -> System.out.println("  " + a));
    }

    private static void info(String[] args) throws Exception {
        if (args.length < 2) {
            usage();
            return;
        }
        Path source = Paths.get(args[1]);
        Path cache = Paths.get(System.getProperty("user.home"), ".cache", "qqnt-jdbc");
        Path prepared = Preparer.prepare(source, key(), cache, new Preparer.Options());
        System.out.println("plain database: " + prepared);
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + prepared);
             Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(
                     "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")) {
            int tables = 0;
            int rows = 0;
            while (rs.next()) {
                String table = rs.getString(1);
                tables++;
                int count = -1;
                try (Statement inner = connection.createStatement();
                     ResultSet cr = inner.executeQuery(
                             "SELECT count(*) FROM \"" + table + "\" NOT INDEXED")) {
                    count = cr.getInt(1);
                    rows += count;
                } catch (Exception e) {
                    count = -1;
                }
                System.out.printf("  %-34s %s%n", table, count < 0 ? "(scan failed)" : count);
            }
            System.out.println("tables=" + tables + " rows=" + rows);
        }
    }

    private static void check(String[] args) throws Exception {
        if (args.length < 2) {
            usage();
            return;
        }
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + args[1])) {
            System.out.println(Preparer.quickCheck(connection));
        }
    }

    private static void repair(String[] args) throws Exception {
        if (args.length < 2) {
            usage();
            return;
        }
        Preparer.Repair mode = args.length >= 3
                ? Preparer.Repair.valueOf(args[2].toUpperCase(Locale.ROOT))
                : Preparer.Repair.AUTO;
        Preparer.repair(Paths.get(args[1]), mode).forEach(System.out::println);
    }
}
