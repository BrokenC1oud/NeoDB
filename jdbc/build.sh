#!/usr/bin/env bash
# Build qqnt-jdbc.jar without Maven: javac + jar, bundling the SQLite engine.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

XERIAL_VERSION="${XERIAL_VERSION:-3.51.1.0}"
# Class-file target.  JetBrains IDEs run on their bundled JBR (DataGrip
# 2026.2 ships JBR 25, older IDEs ship 21/17), so compile for a release they
# all accept instead of for the JDK that happens to be installed.
JAVA_RELEASE="${JAVA_RELEASE:-17}"
XERIAL_URL="https://repo1.maven.org/maven2/org/xerial/sqlite-jdbc/${XERIAL_VERSION}/sqlite-jdbc-${XERIAL_VERSION}.jar"
LIB_DIR="$here/lib"
BUILD="$here/build"
DIST="$here/dist"

if ! command -v javac >/dev/null; then
  echo "error: javac is required" >&2
  exit 1
fi

mkdir -p "$LIB_DIR" "$BUILD" "$DIST"
XERIAL_JAR="$LIB_DIR/sqlite-jdbc-${XERIAL_VERSION}.jar"
if [ ! -f "$XERIAL_JAR" ]; then
  echo "downloading sqlite-jdbc ${XERIAL_VERSION} ..."
  curl -fsSL -o "$XERIAL_JAR" "$XERIAL_URL"
fi

echo "compiling (--release $JAVA_RELEASE) ..."
rm -rf "$BUILD/classes"
mkdir -p "$BUILD/classes"
javac -nowarn --release "$JAVA_RELEASE" -d "$BUILD/classes" -cp "$XERIAL_JAR" $(find src -name '*.java')

echo "packaging (bundling the SQLite engine) ..."
rm -rf "$BUILD/fat"
mkdir -p "$BUILD/fat"
(cd "$BUILD/fat" && jar xf "$XERIAL_JAR")
rm -rf "$BUILD/fat/META-INF/MANIFEST.MF" "$BUILD/fat/META-INF/maven" "$BUILD/fat/META-INF/versions"
cp -r "$BUILD/classes/." "$BUILD/fat/"

mkdir -p "$BUILD/fat/META-INF/services"
cat > "$BUILD/fat/META-INF/services/java.sql.Driver" <<'EOF'
qqnt.jdbc.Driver
org.sqlite.JDBC
EOF

cat > "$BUILD/MANIFEST.MF" <<EOF
Manifest-Version: 1.0
Main-Class: qqnt.jdbc.Tool
Implementation-Title: QQ NT JDBC driver
Implementation-Version: 1.0
EOF

(cd "$BUILD/fat" && jar cfm "$DIST/qqnt-jdbc.jar" "$BUILD/MANIFEST.MF" .)
echo "built $DIST/qqnt-jdbc.jar"
ls -la "$DIST/qqnt-jdbc.jar"
