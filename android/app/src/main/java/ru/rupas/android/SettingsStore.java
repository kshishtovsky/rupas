package ru.rupas.android;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * W3: хранение настроек туннельного эндпоинта в EncryptedSharedPreferences.
 * Секреты (uuid, publicKey/short_id) НЕ попадают в обычные prefs и в логи.
 * JSON-контракт с Go-стороной (ключи ровно такие):
 * {"uuid":"…","server":"host","port":443,"sni":"…","public_key":"…","short_id":"…","fallback":true}
 *
 * Per-app routing (docs/PERAPP_ROUTING.md §5): правила хранятся в prefs как
 * {@code app_rules: [{package, action}]} — package, а не UID (UID меняется при
 * переустановке). В core JSON уходит уже резолвнутый uid: {@code app_rules: [{uid, action}]},
 * см. {@link #toJson()} и RupasVpnService.establishAndStartCore().
 */
public final class SettingsStore {

    /** Действия per-app правил (ровно эти строки понимает ядро). */
    public static final String APP_DIRECT = "direct";
    public static final String APP_TUNNEL = "tunnel";
    public static final String APP_BLOCK = "block";

    /** Снимок настроек; изменяемый только в UI-потоке SettingsActivity. */
    public static final class Settings {
        public String uuid = "";
        public String server = "";
        public int port;
        public String sni = "";
        public String publicKey = "";
        public String shortId = "";
        public boolean fallback = true;
        /** Фильтр рекламы (0.4.0): реклама по умолчанию блокируется, трекеры — нет. */
        public boolean blockAds = true;
        public boolean blockTrackers = false;
        /** Share links in dial order, newline-separated (universal config). */
        public String links = "";
        /**
         * Per-app правила: package → action (direct|tunnel|block).
         * Пустая карта == поведения до per-app routing (ничего не исключаем).
         */
        public final Map<String, String> appRules = new LinkedHashMap<>();
        /**
         * Резолвнутые UID-правила для ядра: uid → action (только tunnel|block).
         * Заполняется сервисом при старте VPN; в prefs НЕ сохраняется.
         */
        public final Map<Integer, String> coreAppRules = new LinkedHashMap<>();

        /** true, если снимок получен из {@link SettingsStore#load()}. */
        boolean savedSnapshot;

        /** Настройки считаются заданными, если есть uuid, server и валидный порт. */
        public boolean isConfigured() {
            if (links != null && !links.isEmpty()) {
                return true;
            }
            return !uuid.isEmpty() && !server.isEmpty() && port > 0 && port <= 65535;
        }

        /** JSON ровно по контракту W3 (org.json доступен на Android из коробки). */
        public String toJson() throws JSONException {
            JSONObject o = new JSONObject();
            o.put("uuid", uuid);
            o.put("server", server);
            o.put("port", port);
            o.put("sni", sni);
            o.put("public_key", publicKey);
            o.put("short_id", shortId);
            o.put("fallback", fallback);
            JSONObject adblock = new JSONObject();
            adblock.put("ads", blockAds);
            adblock.put("trackers", blockTrackers);
            o.put("adblock", adblock);
            if (links != null && !links.isEmpty()) {
                JSONArray arr = new JSONArray();
                for (String l : links.split("\n")) {
                    String t = l.trim();
                    if (!t.isEmpty()) {
                        arr.put(t);
                    }
                }
                if (arr.length() > 0) {
                    o.put("links", arr);
                }
            }
            // §6: ядро получает uid, не package. Пусто → ключа нет (omitempty).
            if (coreAppRules != null && !coreAppRules.isEmpty()) {
                JSONArray arr = new JSONArray();
                for (Map.Entry<Integer, String> e : coreAppRules.entrySet()) {
                    String action = normalizeAction(e.getValue());
                    if (action == null || APP_DIRECT.equals(action)) {
                        continue; // direct живёт в Builder, не в UID-карте
                    }
                    JSONObject r = new JSONObject();
                    r.put("uid", e.getKey().intValue());
                    r.put("action", action);
                    arr.put(r);
                }
                if (arr.length() > 0) {
                    o.put("app_rules", arr);
                }
            }
            return o.toString();
        }
    }

    private static final String FILE = "rupas_secure_settings";
    private static final String K_UUID = "uuid";
    private static final String K_SERVER = "server";
    private static final String K_PORT = "port";
    private static final String K_SNI = "sni";
    private static final String K_PUBLIC_KEY = "publicKey";
    private static final String K_SHORT_ID = "shortId";
    private static final String K_FALLBACK = "fallback";
    private static final String K_BLOCK_ADS = "blockAds";
    private static final String K_BLOCK_TRACKERS = "blockTrackers";
    private static final String K_LINKS = "links";
    private static final String K_APP_RULES = "appRules";
    // Тема — НЕ секрет, но живёт в том же хранилище: один MasterKey на процесс.
    private static final String K_THEME = "themeMode";

    /**
     * Тема оформления: -1 = как в системе (AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM),
     * 0 = светлая, 1 = тёмная. Значение — ровно константа AppCompatDelegate,
     * чтобы MainActivity не переводила его туда-обратно.
     */
    public static int loadThemeMode(Context ctx) {
        try {
            return open(ctx.getApplicationContext()).getInt(K_THEME, -1);
        } catch (Exception e) {
            return -1; // хранилище недоступно — ведём себя как система
        }
    }

    public static void saveThemeMode(Context ctx, int mode) {
        try {
            open(ctx.getApplicationContext()).edit().putInt(K_THEME, mode).apply();
        } catch (Exception ignored) {
            // тема — украшение: не суметь её запомнить не повод падать
        }
    }

    // EncryptedSharedPreferences + MasterKey открывают Android Keystore,
    // поэтому инстанс кешируется на процесс: раньше каждый load() заново
    // создавал MasterKey (дорогая операция, заметный расход батареи).
    private static volatile SharedPreferences cachedPrefs;

    private final SharedPreferences prefs;

    public SettingsStore(Context ctx) throws Exception {
        prefs = open(ctx.getApplicationContext());
    }

    private static SharedPreferences open(Context ctx) throws Exception {
        SharedPreferences p = cachedPrefs;
        if (p != null) {
            return p;
        }
        synchronized (SettingsStore.class) {
            if (cachedPrefs == null) {
                MasterKey masterKey = new MasterKey.Builder(ctx)
                        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                        .build();
                cachedPrefs = EncryptedSharedPreferences.create(
                        ctx,
                        FILE,
                        masterKey,
                        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM);
            }
            return cachedPrefs;
        }
    }

    public Settings load() {
        Settings s = new Settings();
        s.uuid = prefs.getString(K_UUID, "");
        s.server = prefs.getString(K_SERVER, "");
        s.port = prefs.getInt(K_PORT, 0);
        s.sni = prefs.getString(K_SNI, "");
        s.publicKey = prefs.getString(K_PUBLIC_KEY, "");
        s.shortId = prefs.getString(K_SHORT_ID, "");
        s.fallback = prefs.getBoolean(K_FALLBACK, true);
        s.blockAds = prefs.getBoolean(K_BLOCK_ADS, true);
        s.blockTrackers = prefs.getBoolean(K_BLOCK_TRACKERS, false);
        s.links = prefs.getString(K_LINKS, "");
        parseAppRules(prefs.getString(K_APP_RULES, ""), s.appRules);
        s.savedSnapshot = true;
        return s;
    }

    /**
     * Сохраняет снимок. Per-app правила пишутся, только если снимок пришёл из
     * {@link #load()} (то есть UI их видел) — иначе экран, который заполняет лишь
     * endpoint из {@code new Settings()}, не должен стирать выбор приложений.
     */
    public void save(Settings s) {
        SharedPreferences.Editor e = prefs.edit()
                .putString(K_UUID, s.uuid == null ? "" : s.uuid.trim())
                .putString(K_SERVER, s.server == null ? "" : s.server.trim())
                .putInt(K_PORT, s.port)
                .putString(K_SNI, s.sni == null ? "" : s.sni.trim())
                .putString(K_PUBLIC_KEY, s.publicKey == null ? "" : s.publicKey.trim())
                .putString(K_SHORT_ID, s.shortId == null ? "" : s.shortId.trim())
                .putBoolean(K_FALLBACK, s.fallback)
                .putBoolean(K_BLOCK_ADS, s.blockAds)
                .putBoolean(K_BLOCK_TRACKERS, s.blockTrackers)
                .putString(K_LINKS, s.links == null ? "" : s.links.trim());
        if (s.savedSnapshot || (s.appRules != null && !s.appRules.isEmpty())) {
            e.putString(K_APP_RULES, appRulesToJson(s.appRules).toString());
        }
        e.apply();
    }

    /** Отдельное сохранение per-app правил (экран «Приложения»). */
    public void saveAppRules(Map<String, String> rules) {
        prefs.edit().putString(K_APP_RULES, appRulesToJson(rules).toString()).apply();
    }

    /** package → action в JSON для prefs: [{package, action}]. Невалидное отбрасывается. */
    static JSONArray appRulesToJson(Map<String, String> rules) {
        JSONArray arr = new JSONArray();
        if (rules == null) {
            return arr;
        }
        for (Map.Entry<String, String> e : rules.entrySet()) {
            String pkg = e.getKey() == null ? "" : e.getKey().trim();
            String action = normalizeAction(e.getValue());
            if (pkg.isEmpty() || action == null) {
                continue;
            }
            try {
                JSONObject o = new JSONObject();
                o.put("package", pkg);
                o.put("action", action);
                arr.put(o);
            } catch (JSONException ignored) {
                // put(String, Object) не бросает на валидных ключах; защита от будущих правок.
            }
        }
        return arr;
    }

    /** Разбор сохранённого массива; битый JSON == пустой набор (как до per-app). */
    static void parseAppRules(String raw, Map<String, String> out) {
        if (raw == null || raw.isEmpty()) {
            return;
        }
        try {
            JSONArray arr = new JSONArray(raw);
            for (int i = 0; i < arr.length(); i++) {
                JSONObject o = arr.optJSONObject(i);
                if (o == null) {
                    continue;
                }
                String pkg = o.optString("package", "").trim();
                String action = normalizeAction(o.optString("action", ""));
                if (!pkg.isEmpty() && action != null) {
                    out.put(pkg, action);
                }
            }
        } catch (JSONException ignored) {
            // мусор в prefs не должен валить старт VPN
        }
    }

    /** Приводит действие к нижнему регистру; null для неизвестного. */
    static String normalizeAction(String raw) {
        if (raw == null) {
            return null;
        }
        String a = raw.trim().toLowerCase(java.util.Locale.US);
        if (APP_DIRECT.equals(a) || APP_TUNNEL.equals(a) || APP_BLOCK.equals(a)) {
            return a;
        }
        return null;
    }
}
