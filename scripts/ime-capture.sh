#!/usr/bin/env bash
# iMe ad-traffic capture: SNI + flow log from the phone, attributed by
# "only iMe was in the foreground" — no per-flow UID needed.
#
#   ./scripts/ime-capture.sh 192.168.1.209:5555 180
#
# Требует: adb в PATH, rupas 0.3.1 установлен, VPN-разрешение выдано.
# Мешает пользователю минимально: VPN включён только на время окна.
set -u
ADB=adb
DEV="${1:-192.168.1.209:5555}"
SECS="${2:-180}"
OUT="ime-capture-$(date +%Y%m%d-%H%M%S).log"

$ADB connect "$DEV" >/dev/null 2>&1
$ADB -s "$DEV" wait-for-device || { echo "нет устройства $DEV"; exit 1; }

# uid пакета iMe — чтобы потом отфильтровать по нему в netstats
PKG=$($ADB -s "$DEV" shell pm list packages | grep -i 'ime\.' | head -1 | sed 's/package://' | tr -d '\r')
echo "package=$PKG"

$ADB -s "$DEV" logcat -c
$ADB -s "$DEV" shell am start -n ru.rupas.android/.MainActivity >/dev/null
sleep 2
# Кнопка питания на главном экране rupas (1440x3120 -> центр карточки).
$ADB -s "$DEV" shell input tap 720 1067
sleep 6
RUNNING=$($ADB -s "$DEV" logcat -d -s RupasVpn:V | grep -c "TUN fd=" || true)
echo "vpn_started=$RUNNING"

echo ">>> окно $SECS c: откройте iMe и листайте каналы с рекламой, больше ничего не открывайте"
sleep "$SECS"

{
  echo "# device=$DEV package=$PKG $(date -Iseconds)"
  $ADB -s "$DEV" logcat -d -s RupasVpn:V
  echo "# --- netstats (per-uid bytes) ---"
  $ADB -s "$DEV" shell dumpsys netstats detail 2>/dev/null | grep -i "$PKG" || true
} > "$OUT"

# обратно в выключенное состояние
$ADB -s "$DEV" shell am start -n ru.rupas.android/.MainActivity >/dev/null
sleep 1
$ADB -s "$DEV" shell input tap 720 1067

echo "captured: $OUT"
grep -oE 'sni="[^"]+"' "$OUT" | sort | uniq -c | sort -rn | head -40
