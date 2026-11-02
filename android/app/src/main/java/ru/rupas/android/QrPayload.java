package ru.rupas.android;

import android.content.Context;
import android.util.Base64;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * Обмен конфигом через QR: тот же payload, что у десктопного GUI
 * (internal/guictrl/qr.go), — {@code RUPAS1:<base64url(gzip(json))>}.
 *
 * Раскладку знают обе стороны: десктоп читает и пишет этот JSON, поэтому QR,
 * снятый телефоном, применяется на ПК и наоборот. YAML здесь не используется
 * намеренно — на Android нет YAML-парсера, и второй разбор разошёлся бы с
 * Go-стороной при первой же правке схемы.
 *
 * Что уезжает: каналы (share-ссылки в порядке перебора), правила маршрутизации,
 * per-app правила, фильтр рекламы. Чего телефон не знает — desync/geoip/
 * исключения — он не присылает, и десктоп свои значения сохраняет.
 */
final class QrPayload {

    private static final String TAG = "rupas.qr";
    private static final String PREFIX = "RUPAS1:";
    private static final int VERSION = 1;
    /** Потолок распаковки: чужой QR не должен съесть память (gzip-бомба). */
    private static final int MAX_INFLATED = 4 << 20;
    /** 40-L в байтовом режиме — больше в один QR не влезает. */
    private static final int MAX_QR_TEXT = 2900;

    private QrPayload() {
    }

    /** Итог импорта/экспорта — строка для тоста и диалога. */
    static final class Result {
        final String text;
        final String summary;
        final boolean tooBig;

        Result(String text, String summary, boolean tooBig) {
            this.text = text;
            this.summary = summary;
            this.tooBig = tooBig;
        }
    }

    // ------------------------------------------------------------------ export

    /** Собирает payload из текущего состояния приложения. */
    static Result export(Context ctx) throws Exception {
        SettingsStore.Settings s = new SettingsStore(ctx).load();
        JSONObject doc = new JSONObject();
        doc.put("v", VERSION);
        doc.put("links", new JSONArray(splitLinks(s.links)));
        JSONObject ad = new JSONObject();
        ad.put("ads", s.blockAds);
        ad.put("trackers", s.blockTrackers);
        doc.put("adblock", ad);
        JSONArray apps = appsJson(AppRule.load(ctx));
        if (apps.length() > 0) {
            doc.put("apps", apps);
        }
        JSONArray rules = rulesJson();
        if (rules.length() > 0) {
            doc.put("rules", rules);
        }
        String text = encode(doc.toString());
        String summary = rules.length() + " правил · " + splitLinks(s.links).size() + " канал(ов)"
                + (apps.length() > 0 ? " · " + apps.length() + " приложений" : "")
                + " · " + String.format(java.util.Locale.ROOT, "%.1f КБ",
                doc.toString().getBytes(StandardCharsets.UTF_8).length / 1024.0);
        return new Result(text, summary, text.length() > MAX_QR_TEXT);
    }

    private static List<String> splitLinks(String blob) {
        List<String> out = new ArrayList<>();
        if (blob == null) {
            return out;
        }
        for (String line : blob.split("\n")) {
            String t = line.trim();
            if (!t.isEmpty()) {
                out.add(t);
            }
        }
        return out;
    }

    /** Правила ядра как есть: их раскладку уже понимает десктоп. */
    private static JSONArray rulesJson() {
        try {
            String raw = CoreRouting.rulesJson();
            return raw == null || raw.trim().isEmpty() ? new JSONArray() : new JSONArray(raw);
        } catch (Throwable t) {
            Log.w(TAG, "rulesJson: " + t);
            return new JSONArray();
        }
    }

    private static JSONArray appsJson(List<AppRule> rules) throws JSONException {
        JSONArray arr = new JSONArray();
        for (AppRule r : rules) {
            if (r == null || r.pkg == null || r.pkg.isEmpty() || r.action == null || r.action.isEmpty()) {
                continue; // «наследует» не несёт информации
            }
            JSONObject o = new JSONObject();
            o.put("pkg", r.pkg);
            o.put("action", r.action);
            arr.put(o);
        }
        return arr;
    }

    // ------------------------------------------------------------------ import

    /**
     * Применяет payload: настройки → профили каналов → per-app правила →
     * правила ядра. Каждый шаг идёт тем же путём, что обычное «Сохранить»,
     * поэтому сервис увидит ровно то же, что после ручной правки.
     */
    static Result apply(Context ctx, String text) throws Exception {
        JSONObject doc = new JSONObject(new String(decode(text), StandardCharsets.UTF_8));
        int v = doc.optInt("v", 0);
        if (v != VERSION) {
            throw new IllegalArgumentException("конфиг версии " + v + ", приложение понимает только " + VERSION);
        }

        SettingsStore store = new SettingsStore(ctx);
        SettingsStore.Settings s = store.load();

        JSONArray links = doc.optJSONArray("links");
        if (links != null) {
            List<String> lines = new ArrayList<>();
            for (int i = 0; i < links.length(); i++) {
                String l = links.optString(i, "").trim();
                if (!l.isEmpty()) {
                    lines.add(l);
                }
            }
            if (!lines.isEmpty()) {
                // links — производная от profiles (SettingsStore.save), поэтому
                // правим источник истины, а не строку.
                s.links = String.join("\n", lines);
                s.profiles.clear();
                int n = 0;
                for (String l : lines) {
                    s.profiles.add(new SettingsStore.Profile("p" + (++n), l, "", true));
                }
            }
        }
        JSONObject ad = doc.optJSONObject("adblock");
        if (ad != null) {
            s.blockAds = ad.optBoolean("ads", s.blockAds);
            s.blockTrackers = ad.optBoolean("trackers", s.blockTrackers);
        }

        JSONArray rules = doc.optJSONArray("rules");
        JSONArray appRules = doc.optJSONArray("apps");
        // Пишем настройки последними из блока, который мог упасть: сначала
        // убеждаемся, что правила разбираются, потом трогаем хранилище.
        JSONArray cleaned = cleanRules(rules);

        store.save(s);
        if (appRules != null) {
            AppRule.save(ctx, parseApps(appRules));
        }
        if (rules != null) {
            CoreRouting.setRulesJson(cleaned.toString());
        }

        String summary = cleaned.length() + " правил · " + splitLinks(s.links).size() + " канал(ов)"
                + (appRules != null && appRules.length() > 0 ? " · " + appRules.length() + " приложений" : "");
        return new Result(text, summary, false);
    }

    /**
     * Убирает правило-маркер без матчера (действие по умолчанию приходит
     * последним) и правила по имени процесса: на Android такого матчера нет,
     * и без фильтра они превратились бы в «действие по умолчанию».
     */
    private static JSONArray cleanRules(JSONArray rules) throws JSONException {
        JSONArray out = new JSONArray();
        if (rules == null) {
            return out;
        }
        for (int i = 0; i < rules.length(); i++) {
            JSONObject o = rules.optJSONObject(i);
            if (o == null || o.has("app")) {
                continue;
            }
            boolean matcher = false;
            for (String k : new String[]{"cidr", "sni", "ports", "geoip"}) {
                String val = o.optString(k, "").trim();
                if (!val.isEmpty()) {
                    matcher = true;
                    break;
                }
            }
            if (!matcher) {
                continue; // маркер default
            }
            out.put(o);
        }
        return out;
    }

    private static List<AppRule> parseApps(JSONArray arr) {
        List<AppRule> out = new ArrayList<>();
        for (int i = 0; i < arr.length(); i++) {
            JSONObject o = arr.optJSONObject(i);
            if (o == null) {
                continue;
            }
            AppRule r = new AppRule(o.optString("pkg", ""), o.optString("action", ""));
            if (r.isValid()) {
                out.add(r);
            }
        }
        return out;
    }

    // ----------------------------------------------------------------- codec

    static String encode(String json) throws Exception {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(buf)) {
            gz.write(json.getBytes(StandardCharsets.UTF_8));
        }
        return PREFIX + Base64.encodeToString(buf.toByteArray(),
                Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
    }

    static byte[] decode(String text) throws Exception {
        String s = text == null ? "" : text.replaceAll("[\\s]", "");
        if (s.startsWith(PREFIX)) {
            s = s.substring(PREFIX.length());
        } else if (s.startsWith("RUPAS1")) {
            s = s.substring("RUPAS1".length());
        }
        if (s.isEmpty()) {
            throw new IllegalArgumentException("пустой QR");
        }
        byte[] raw;
        try {
            raw = Base64.decode(s, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
        } catch (IllegalArgumentException e) {
            raw = Base64.decode(s, Base64.DEFAULT);
        }
        if (raw.length < 2 || (raw[0] & 0xff) != 0x1f || (raw[1] & 0xff) != 0x8b) {
            throw new IllegalArgumentException("это не конфиг Rupas");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPInputStream gz = new GZIPInputStream(new ByteArrayInputStream(raw))) {
            byte[] chunk = new byte[8192];
            int n;
            while ((n = gz.read(chunk)) > 0) {
                out.write(chunk, 0, n);
                if (out.size() > MAX_INFLATED) {
                    throw new IllegalArgumentException("конфиг больше " + (MAX_INFLATED >> 10) + " КБ");
                }
            }
        }
        return out.toByteArray();
    }
}
