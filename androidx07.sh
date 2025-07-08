#!/bin/bash

# ─── COLORS ────────────────────────────────────────────────
R="\e[91m"; G="\e[92m"; Y="\e[93m"; B="\e[94m"; W="\e[0m"

# ─── CHECK ─────────────────────────────────────────────────
APK="$1"
if [ -z "$APK" ]; then
    echo -e "${R}[!] Usage: $0 <apk_file.apk>${W}"
    exit 1
fi

# ─── SETUP ────────────────────────────────────────────────
NAME=$(basename "$APK" .apk)
WORKDIR="analysis_$NAME"
mkdir -p "$WORKDIR"

# ─── DISPLAY TOOL NAME ────────────────────────────────────
echo -e "${Y}$(figlet -f slant 'ANDROIDX07')${W}"

echo -e "${B}[+] Starting APK Vulnerability Analysis...${W}"

# ─── STEP 1: STRINGS + URLs ───────────────────────────────
strings "$APK" > "$WORKDIR/strings.txt"
grep -Eo 'http[s]?://[a-zA-Z0-9./?=_%:-]*' "$WORKDIR/strings.txt" | sort -u > "$WORKDIR/urls.txt"
grep -Ei "firebaseio|firebase" "$WORKDIR/strings.txt" > "$WORKDIR/firebase.txt"
grep -Eoi 'apikey|token|secret|bearer|accesskey|auth' "$WORKDIR/strings.txt" | sort -u > "$WORKDIR/secrets.txt"

# ─── STEP 2: APKTOOL & JADX ───────────────────────────────
apktool d "$APK" -o "$WORKDIR/apktool_src" -f > /dev/null 2>&1
jadx -d "$WORKDIR/jadx_src" "$APK" > /dev/null 2>&1

# ─── STEP 3: Manifest Analysis ────────────────────────────
grep -i 'exported="true"' "$WORKDIR/apktool_src/AndroidManifest.xml" > "$WORKDIR/exported_components.txt"
grep -i "uses-permission" "$WORKDIR/apktool_src/AndroidManifest.xml" | grep -Ei "INTERNET|READ_SMS|CALL_PHONE|SYSTEM_ALERT_WINDOW" > "$WORKDIR/permissions.txt"
grep -i "scheme" "$WORKDIR/apktool_src/AndroidManifest.xml" > "$WORKDIR/deeplinks.txt"

# ─── STEP 4: Native Libs ───────────────────────────────────
find "$WORKDIR/apktool_src/lib" -name "*.so" > "$WORKDIR/native_libs.txt" 2>/dev/null

# ─── STEP 5: Internal IPs ──────────────────────────────────
grep -Eo '192\.168\.[0-9]+\.[0-9]+|10\.[0-9]+\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]+\.[0-9]+' "$WORKDIR/strings.txt" > "$WORKDIR/internal_ips.txt"

# ─── STEP 6: QUARK-ENGINE ANALYSIS ─────────────────────────
echo -e "${Y}[*] Running Quark-Engine Static Analysis...${W}"
quark -a "$APK" -o "$WORKDIR/quark_report.json" --silent > /dev/null 2>&1
cat "$WORKDIR/quark_report.json" | jq '.' > "$WORKDIR/quark_report_pretty.json"

# ─── STEP 7: ANDROGUARD SIGNATURE SCAN ─────────────────────
echo -e "${Y}[*] Running Androguard Signature Scan...${W}"
androguard analyze -i "$APK" -s << EOF > "$WORKDIR/androguard_output.txt"
from androguard.misc import AnalyzeAPK
a,d,dx = AnalyzeAPK("$APK")
print("Package:", a.get_package())
print("Main Activity:", a.get_main_activity())
for perm in a.get_permissions():
    print("Permission:", perm)
EOF

# ─── STEP 8: GENERATE HTML REPORT ───────────────────────────
echo -e "${Y}[*] Generating HTML Report...${W}"
REPORT_HTML="$WORKDIR/report.html"
cat <<EOF > $REPORT_HTML
<html><head><title>APK Vulnerability Report - $NAME</title></head><body>
<h1>APK Vulnerability Report: $NAME</h1>

<h2>1. Extracted URLs</h2><pre>$(cat "$WORKDIR/urls.txt")</pre>
<h2>2. Firebase URLs</h2><pre>$(cat "$WORKDIR/firebase.txt")</pre>
<h2>3. Hardcoded Secrets</h2><pre>$(cat "$WORKDIR/secrets.txt")</pre>
<h2>4. Exported Components</h2><pre>$(cat "$WORKDIR/exported_components.txt")</pre>
<h2>5. Dangerous Permissions</h2><pre>$(cat "$WORKDIR/permissions.txt")</pre>
<h2>6. Deep Links</h2><pre>$(cat "$WORKDIR/deeplinks.txt")</pre>
<h2>7. Native Libraries</h2><pre>$(cat "$WORKDIR/native_libs.txt")</pre>
<h2>8. Internal IPs</h2><pre>$(cat "$WORKDIR/internal_ips.txt")</pre>
<h2>9. Quark Static Analysis Summary</h2><pre>$(cat "$WORKDIR/quark_report_pretty.json" | jq -r '.app_analysis[].summary // "No Threats Detected"')</pre>
<h2>10. Androguard Signature Output</h2><pre>$(cat "$WORKDIR/androguard_output.txt")</pre>

<p><b>Report generated on:</b> $(date)</p>
</body></html>
EOF

# ─── STEP 9: Convert to PDF ─────────────────────────────────
echo -e "${Y}[*] Generating PDF Report...${W}"
wkhtmltopdf "$REPORT_HTML" "$WORKDIR/report.pdf" > /dev/null 2>&1

# ─── DONE ───────────────────────────────────────────────────
echo -e "\n${G}[✓] ALL DONE!${W} PDF saved at: ${Y}$WORKDIR/report.pdf${W}\n"