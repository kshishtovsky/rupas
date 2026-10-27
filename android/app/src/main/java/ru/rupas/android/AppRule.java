package ru.rupas.android;

import android.content.Context;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Правило маршрутизации по приложению (docs/PERAPP_ROUTING.md §5).
 *
 * Хранение — {@link SettingsStore.Settings#appRules}: package → action,
 * action = {@code direct | tunnel | block} строчными (Go-контракт §6). Ключ — package,
 * а не UID: UID меняется при переустановке приложения. Своего prefs-ключа у UI нет:
 * тот же массив читает RupasVpnService при establish(), поэтому запись идёт только
 * через {@link SettingsStore#saveAppRules(Map)}.
 *
 * Пустое действие = правила нет («наследует»): действует общая политика.
 * TUNNEL/BLOCK работают с API 29+ (§7.1): матрица действий — §1.
 */
final class AppRule {

    static final String ACT_DIRECT = SettingsStore.APP_DIRECT;
    static final String ACT_TUNNEL = SettingsStore.APP_TUNNEL;
    static final String ACT_BLOCK = SettingsStore.APP_BLOCK;

    /** Минимальный API, на котором ядро видит UID потока (§1, §7.1). */
    static final int ADVANCED_MIN_API = 29;

    final String pkg;
    String action;

    AppRule(String pkg, String action) {
        this.pkg = pkg == null ? "" : pkg.trim();
        this.action = normalize(action);
    }

    boolean isValid() {
        return !pkg.isEmpty();
    }

    /** «Наследует»: правила нет, действует общая политика. */
    boolean inherited() {
        return action.isEmpty();
    }

    /** Действие в форме чипа (§5.3 ROUTING_UI); "" — правила нет. */
    String chipAction() {
        if (ACT_DIRECT.equals(action)) {
            return RoutingRule.ACT_DIRECT;
        }
        if (ACT_TUNNEL.equals(action)) {
            return RoutingRule.ACT_TUNNEL;
        }
        if (ACT_BLOCK.equals(action)) {
            return RoutingRule.ACT_BLOCK;
        }
        return "";
    }

    AppRule copy() {
        return new AppRule(pkg, action);
    }

    boolean sameAs(AppRule other) {
        return other != null && pkg.equals(other.pkg) && action.equals(other.action);
    }

    JSONObject toJson() throws JSONException {
        JSONObject o = new JSONObject();
        o.put("package", pkg);
        o.put("action", action);
        return o;
    }

    // ---------------------------------------------------------------- normalize

    /** Терпимо: DIRECT/direct, неизвестное значение — «наследует». */
    static String normalize(String action) {
        String a = action == null ? "" : action.trim().toLowerCase(Locale.ROOT);
        if (ACT_DIRECT.equals(a) || ACT_TUNNEL.equals(a) || ACT_BLOCK.equals(a)) {
            return a;
        }
        return "";
    }

    /** Обратный маппинг из чипа ROUTING_UI (DIRECT/TUNNEL/BLOCK) в значение настроек. */
    static String fromChipAction(String chipAction) {
        String a = chipAction == null ? "" : chipAction.trim().toUpperCase(Locale.ROOT);
        if (RoutingRule.ACT_TUNNEL.equals(a)) {
            return ACT_TUNNEL;
        }
        if (RoutingRule.ACT_BLOCK.equals(a)) {
            return ACT_BLOCK;
        }
        if (RoutingRule.ACT_DIRECT.equals(a)) {
            return ACT_DIRECT;
        }
        return "";
    }

    /** TUNNEL/BLOCK ядро применит только с Android 10 (§7.1). */
    static boolean needsApi29(String action) {
        return ACT_TUNNEL.equals(action) || ACT_BLOCK.equals(action);
    }

    // ------------------------------------------------------------------ storage

    /** Сохранённые правила; Keystore недоступен — пустое состояние, а не падение экрана. */
    static List<AppRule> load(Context ctx) {
        try {
            return fromMap(new SettingsStore(ctx).load().appRules);
        } catch (Throwable t) {
            LogBuffer.add("[routing] app_rules не прочитаны: " + t);
            return new ArrayList<>();
        }
    }

    /** Запись тем же путём, что читает сервис; бросает наружу — UI обязан сказать об ошибке. */
    static void save(Context ctx, Collection<AppRule> rules) throws Exception {
        new SettingsStore(ctx).saveAppRules(toMap(rules));
    }

    /** JSON в формате хранилища — источник истины для dirty-сравнения. */
    static String toJson(Collection<AppRule> rules) {
        return SettingsStore.appRulesToJson(toMap(rules)).toString();
    }

    /** Разбор JSON из Bundle (поворот экрана): тот же парсер, что у хранилища. */
    static List<AppRule> parse(String raw) {
        Map<String, String> map = new LinkedHashMap<>();
        SettingsStore.parseAppRules(raw, map);
        return fromMap(map);
    }

    static Map<String, String> toMap(Collection<AppRule> rules) {
        Map<String, String> map = new LinkedHashMap<>();
        if (rules != null) {
            for (AppRule r : rules) {
                if (r == null || !r.isValid() || r.inherited()) {
                    continue;
                }
                map.put(r.pkg, r.action);
            }
        }
        return map;
    }

    /** package → action из карты экрана выбора (пустое = «наследует»). */
    static List<AppRule> fromMap(Map<String, String> map) {
        List<AppRule> out = new ArrayList<>();
        if (map == null) {
            return out;
        }
        for (Map.Entry<String, String> e : map.entrySet()) {
            AppRule r = new AppRule(e.getKey(), e.getValue());
            if (r.isValid() && !r.inherited()) {
                out.add(r);
            }
        }
        return out;
    }

    /** Снимок «как было» для dirty-сравнения. */
    static List<AppRule> copyAll(Collection<AppRule> rules) {
        List<AppRule> out = new ArrayList<>();
        if (rules != null) {
            for (AppRule r : rules) {
                if (r != null) {
                    out.add(r.copy());
                }
            }
        }
        return out;
    }
}
