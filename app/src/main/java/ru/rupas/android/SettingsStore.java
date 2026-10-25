package ru.rupas.android;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * W3: хранение настроек туннельного эндпоинта в EncryptedSharedPreferences.
 * Секреты (uuid, publicKey/short_id) НЕ попадают в обычные prefs и в логи.
 * JSON-контракт с Go-стороной (ключи ровно такие):
 * {"uuid":"…","server":"host","port":443,"sni":"…","public_key":"…","short_id":"…","fallback":true}
 */
public final class SettingsStore {

    /** Снимок настроек; изменяемый только в UI-потоке SettingsActivity. */
    public static final class Settings {
        public String uuid = "";
        public String server = "";
        public int port;
        public String sni = "";
        public String publicKey = "";
        public String shortId = "";
        public boolean fallback = true;

        /** Настройки считаются заданными, если есть uuid, server и валидный порт. */
        public boolean isConfigured() {
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

    private final SharedPreferences prefs;

    public SettingsStore(Context ctx) throws Exception {
        MasterKey masterKey = new MasterKey.Builder(ctx)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build();
        prefs = EncryptedSharedPreferences.create(
                ctx,
                FILE,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM);
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
        return s;
    }

    public void save(Settings s) {
        prefs.edit()
                .putString(K_UUID, s.uuid == null ? "" : s.uuid.trim())
                .putString(K_SERVER, s.server == null ? "" : s.server.trim())
                .putInt(K_PORT, s.port)
                .putString(K_SNI, s.sni == null ? "" : s.sni.trim())
                .putString(K_PUBLIC_KEY, s.publicKey == null ? "" : s.publicKey.trim())
                .putString(K_SHORT_ID, s.shortId == null ? "" : s.shortId.trim())
                .putBoolean(K_FALLBACK, s.fallback)
                .apply();
    }
}
