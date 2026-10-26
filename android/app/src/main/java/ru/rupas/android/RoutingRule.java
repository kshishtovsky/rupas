package ru.rupas.android;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Одно правило маршрутизации. Форма — ровно как в движке (docs/ROUTING_UI.md §10):
 * {cidr, sni, ports, geoip, proto, action}, заполнен максимум один матчер;
 * правило без матчера — это default.
 *
 * Здесь же клиентская валидация (пусто / CIDR / порт-диапазон / пересечение),
 * чтобы до ядра не доезжал невалидный конфиг (§1: «0 невалидных конфигов до reload»).
 */
final class RoutingRule {

    static final String KIND_CIDR = "cidr";
    static final String KIND_GEOIP = "geoip";
    static final String KIND_SNI = "sni";
    static final String KIND_PORTS = "ports";

    static final String ACT_DIRECT = "DIRECT";
    static final String ACT_TUNNEL = "TUNNEL";
    static final String ACT_DESYNC = "DESYNC";
    static final String ACT_BLOCK = "BLOCK";

    static final int STAGE_IP = 0;
    static final int STAGE_DOMAINS = 1;
    static final int STAGE_PORTS = 2;
    static final int STAGE_NONE = -1;

    String kind = "";
    String value = "";
    String proto = "";
    String action = ACT_DIRECT;

    RoutingRule() {
    }

    RoutingRule(String kind, String value, String proto, String action) {
        this.kind = kind == null ? "" : kind;
        this.value = value == null ? "" : value.trim();
        this.proto = normalizeProto(proto);
        this.action = normalizeAction(action);
    }

    boolean isDefault() {
        return kind == null || kind.isEmpty();
    }

    int stage() {
        if (isDefault()) {
            return STAGE_NONE;
        }
        switch (kind) {
            case KIND_CIDR:
            case KIND_GEOIP:
                return STAGE_IP;
            case KIND_SNI:
                return STAGE_DOMAINS;
            case KIND_PORTS:
                return STAGE_PORTS;
            default:
                return STAGE_NONE;
        }
    }

    RoutingRule copy() {
        return new RoutingRule(kind, value, proto, action);
    }

    boolean sameAs(RoutingRule other) {
        return other != null
                && kind.equals(other.kind)
                && value.equals(other.value)
                && proto.equals(other.proto)
                && action.equals(other.action);
    }

    /** Матчер как данные (§5.2): `geoip: ru`, `91.105.192.0/23`, `*.x`, `50000-65535`. */
    String matcher() {
        if (isDefault()) {
            return "";
        }
        if (KIND_GEOIP.equals(kind)) {
            return "geoip: " + value.toLowerCase(Locale.ROOT);
        }
        if (KIND_PORTS.equals(kind) && !proto.isEmpty()) {
            return value + " / " + proto;
        }
        return value;
    }

    /** Вторая строка — человеческая подпись, а не повтор матчера (§5.2). */
    String caption(Context ctx) {
        if (isDefault()) {
            return ctx.getString(R.string.routing_default_name);
        }
        switch (kind) {
            case KIND_CIDR: {
                long n = addressCount(value);
                if (n == Long.MAX_VALUE) {
                    return ctx.getString(R.string.routing_caption_cidr_pow, hostBits(value));
                }
                if (n <= 0) {
                    return value;
                }
                return ctx.getResources().getQuantityString(
                        R.plurals.addresses_count, pluralQuantity(n), formatCount(n));
            }
            case KIND_GEOIP:
                return ctx.getString(R.string.routing_caption_geoip, value.toUpperCase(Locale.ROOT));
            case KIND_SNI:
                return ctx.getString(value.startsWith("*.")
                        ? R.string.routing_caption_sni_wild
                        : R.string.routing_caption_sni_exact);
            case KIND_PORTS: {
                String human = humanPorts(value);
                String base = (value.indexOf(',') < 0 && value.indexOf('-') < 0)
                        ? ctx.getString(R.string.routing_caption_port, human)
                        : ctx.getString(R.string.routing_caption_ports, human);
                return proto.isEmpty()
                        ? base
                        : ctx.getString(R.string.routing_caption_with_proto, base, proto);
            }
            default:
                return "";
        }
    }

    JSONObject toJson() throws JSONException {
        JSONObject o = new JSONObject();
        if (!isDefault()) {
            o.put(kind, value);
        }
        if (!proto.isEmpty()) {
            o.put("proto", proto);
        }
        o.put("action", action);
        return o;
    }

    // ---------------------------------------------------------------- parsing

    /** Разобранный ответ ядра: правила по порядку + закреплённый default. */
    static final class Parsed {
        final List<RoutingRule> rules = new ArrayList<>();
        RoutingRule def = defaultRule();

        static RoutingRule defaultRule() {
            RoutingRule r = new RoutingRule();
            r.kind = "";
            r.value = "";
            r.proto = "";
            r.action = ACT_TUNNEL;
            return r;
        }
    }

    static RoutingRule fromJson(JSONObject o) {
        RoutingRule r = new RoutingRule();
        r.kind = "";
        r.value = "";
        String v;
        if ((v = opt(o, "cidr")) != null) {
            r.kind = KIND_CIDR;
            r.value = v;
        } else if ((v = opt(o, "geoip")) != null) {
            r.kind = KIND_GEOIP;
            r.value = v;
        } else if ((v = opt(o, "sni")) != null) {
            r.kind = KIND_SNI;
            r.value = v;
        } else if ((v = opt(o, "ports")) != null) {
            r.kind = KIND_PORTS;
            r.value = v;
        }
        r.proto = normalizeProto(o.optString("proto", ""));
        r.action = normalizeAction(o.optString("action", ""));
        return r;
    }

    private static String opt(JSONObject o, String key) {
        if (!o.has(key) || o.isNull(key)) {
            return null;
        }
        String v = o.optString(key, "").trim();
        return v.isEmpty() ? null : v;
    }

    /**
     * Терпимый разбор RulesJSON(): массив правил (default = правило без матчера)
     * либо объект {"rules":[…],"default":…}. Неизвестная форма = пустой список.
     */
    static Parsed parseRules(String raw) throws JSONException {
        Parsed p = new Parsed();
        String t = raw == null ? "" : raw.trim();
        if (t.isEmpty()) {
            return p;
        }
        JSONArray arr = null;
        if (t.startsWith("{")) {
            JSONObject root = new JSONObject(t);
            arr = root.optJSONArray("rules");
            if (arr == null) {
                arr = root.optJSONArray("items");
            }
            Object d = root.opt("default");
            if (d instanceof String) {
                p.def.action = normalizeAction((String) d);
            } else if (d instanceof JSONObject) {
                p.def = fromJson((JSONObject) d);
            }
            if (arr == null) {
                RoutingRule single = fromJson(root);
                if (single.isDefault()) {
                    p.def.action = single.action;
                } else {
                    p.rules.add(single);
                }
                return p;
            }
        } else if (t.startsWith("[")) {
            arr = new JSONArray(t);
        } else {
            return p;
        }
        for (int i = 0; i < arr.length(); i++) {
            JSONObject o = arr.optJSONObject(i);
            if (o == null) {
                continue;
            }
            RoutingRule r = fromJson(o);
            if (r.isDefault()) {
                p.def.action = r.action;
            } else {
                p.rules.add(r);
            }
        }
        return p;
    }

    /** Порядок массива = порядок стадий; default уходит последним правилом без матчера. */
    static String rulesJson(List<RoutingRule> rules, RoutingRule def) {
        JSONArray arr = new JSONArray();
        for (RoutingRule r : rules) {
            if (r == null || r.isDefault()) {
                continue;
            }
            try {
                arr.put(r.toJson());
            } catch (JSONException ignored) {
                // поле-строка не может не сериализоваться; правило не теряем молча
            }
        }
        try {
            JSONObject d = new JSONObject();
            d.put("action", def == null ? ACT_TUNNEL : def.action);
            arr.put(d);
        } catch (JSONException ignored) {
        }
        return arr.toString();
    }

    // ------------------------------------------------------------- validation

    static String normalizeProto(String proto) {
        String p = proto == null ? "" : proto.trim().toLowerCase(Locale.ROOT);
        if ("tcp".equals(p) || "udp".equals(p)) {
            return p;
        }
        return "";
    }

    static String normalizeAction(String action) {
        String a = action == null ? "" : action.trim().toUpperCase(Locale.ROOT);
        if (ACT_DIRECT.equals(a) || ACT_TUNNEL.equals(a) || ACT_DESYNC.equals(a) || ACT_BLOCK.equals(a)) {
            return a;
        }
        return ACT_DIRECT;
    }

    /** @return 0 когда значение валидно, иначе строковый ресурс с причиной. */
    static int validateValue(String kind, String value) {
        String v = value == null ? "" : value.trim();
        if (v.isEmpty()) {
            return R.string.editor_err_empty;
        }
        switch (kind) {
            case KIND_CIDR:
                return cidrValid(v) ? 0 : R.string.editor_err_cidr;
            case KIND_GEOIP:
                return v.matches("[A-Za-z]{2}") ? 0 : R.string.editor_err_country;
            case KIND_SNI:
                return domainValid(v) ? 0 : R.string.editor_err_domain;
            case KIND_PORTS:
                return portsErrorRes(v);
            default:
                return R.string.editor_err_empty;
        }
    }

    static boolean cidrValid(String s) {
        int slash = s.indexOf('/');
        if (slash <= 0 || slash == s.length() - 1) {
            return false;
        }
        String addr = s.substring(0, slash);
        String prefix = s.substring(slash + 1);
        if (!prefix.matches("\\d{1,3}")) {
            return false;
        }
        int bits = Integer.parseInt(prefix);
        if (addr.indexOf(':') >= 0) {
            if (!addr.matches("[0-9a-fA-F:.]+") || bits > 128) {
                return false;
            }
            try {
                return InetAddress.getByName(addr) instanceof Inet6Address;
            } catch (Exception e) {
                return false;
            }
        }
        if (!addr.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
            return false;
        }
        for (String part : addr.split("\\.")) {
            if (Integer.parseInt(part) > 255) {
                return false;
            }
        }
        return bits <= 32;
    }

    static boolean domainValid(String s) {
        if (s.contains(" ") || s.contains("/") || s.contains(":")) {
            return false;
        }
        String host = s.startsWith("*.") ? s.substring(2) : s;
        if (host.isEmpty() || host.startsWith("*") || host.startsWith(".") || host.endsWith(".")) {
            return false;
        }
        return host.contains(".");
    }

    static int portsErrorRes(String value) {
        String[] parts = value.trim().split("[,\\s]+");
        boolean any = false;
        for (String part : parts) {
            if (part.isEmpty()) {
                continue;
            }
            any = true;
            String lo = part;
            String hi = part;
            int dash = part.indexOf('-');
            if (dash > 0) {
                lo = part.substring(0, dash);
                hi = part.substring(dash + 1);
            }
            int l = parsePort(lo);
            int h = parsePort(hi);
            if (l < 0 || h < 0) {
                return R.string.editor_err_port;
            }
            if (l > h) {
                return R.string.editor_err_range;
            }
        }
        return any ? 0 : R.string.editor_err_empty;
    }

    private static int parsePort(String s) {
        try {
            int p = Integer.parseInt(s.trim());
            return (p >= 1 && p <= 65535) ? p : -1;
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /** Диапазоны портов правила; пустой список, если значение не разбирается. */
    static List<int[]> portSpans(String value) {
        List<int[]> out = new ArrayList<>();
        if (value == null) {
            return out;
        }
        for (String part : value.trim().split("[,\\s]+")) {
            if (part.isEmpty()) {
                continue;
            }
            String lo = part;
            String hi = part;
            int dash = part.indexOf('-');
            if (dash > 0) {
                lo = part.substring(0, dash);
                hi = part.substring(dash + 1);
            }
            int l = parsePort(lo);
            int h = parsePort(hi);
            if (l < 0 || h < 0 || l > h) {
                return new ArrayList<>();
            }
            out.add(new int[]{l, h});
        }
        return out;
    }

    /**
     * Пересечение портов = ошибка компиляции (§2). Движок раскладывает порты по
     * трём независимым наборам (any / tcp / udp, config.checkPortOverlaps), поэтому
     * конфликт возможен только внутри одного протокола: `443` и `443/udp` — разные
     * наборы и сохраняются вместе.
     */
    static RoutingRule findPortConflict(List<RoutingRule> rules, int skipIndex,
                                        String ports, String proto) {
        if (rules == null || ports == null) {
            return null;
        }
        for (int i = 0; i < rules.size(); i++) {
            if (i == skipIndex) {
                continue;
            }
            RoutingRule r = rules.get(i);
            if (r == null || !KIND_PORTS.equals(r.kind)) {
                continue;
            }
            if (!protoCompatible(r.proto, normalizeProto(proto))) {
                continue;
            }
            if (overlapSpan(r.value, ports) != null) {
                return r;
            }
        }
        return null;
    }

    private static boolean protoCompatible(String a, String b) {
        String left = a == null ? "" : a;
        String right = b == null ? "" : b;
        return left.equals(right);
    }

    /** Первое пересечение двух наборов диапазонов как «50000-60000», либо null. */
    static String overlapSpan(String existing, String candidate) {
        List<int[]> a = portSpans(existing);
        List<int[]> b = portSpans(candidate);
        for (int[] x : a) {
            for (int[] y : b) {
                int lo = Math.max(x[0], y[0]);
                int hi = Math.min(x[1], y[1]);
                if (lo <= hi) {
                    return lo == hi ? String.valueOf(lo) : lo + "-" + hi;
                }
            }
        }
        return null;
    }

    static long addressCount(String cidr) {
        if (cidr == null) {
            return 0;
        }
        int slash = cidr.indexOf('/');
        if (slash <= 0) {
            return 1;
        }
        String addr = cidr.substring(0, slash);
        int bits;
        try {
            bits = Integer.parseInt(cidr.substring(slash + 1));
        } catch (NumberFormatException e) {
            return 0;
        }
        int width = addr.indexOf(':') >= 0 ? 128 : 32;
        int hostBits = width - bits;
        if (hostBits < 0) {
            return 0;
        }
        if (hostBits >= 63) {
            return Long.MAX_VALUE;
        }
        return 1L << hostBits;
    }

    /** Ширина хостовой части префикса — для честного «2^n адресов» (IPv6 /48 и т.п.). */
    static int hostBits(String cidr) {
        int slash = cidr == null ? -1 : cidr.indexOf('/');
        if (slash <= 0) {
            return 0;
        }
        int bits;
        try {
            bits = Integer.parseInt(cidr.substring(slash + 1));
        } catch (NumberFormatException e) {
            return 0;
        }
        int width = cidr.indexOf(':') >= 0 ? 128 : 32;
        return Math.max(0, width - bits);
    }

    static String formatCount(long n) {
        String digits = String.valueOf(n);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < digits.length(); i++) {
            if (i > 0 && (digits.length() - i) % 3 == 0) {
                sb.append('\u00A0');
            }
            sb.append(digits.charAt(i));
        }
        return sb.toString();
    }

    /** Количество для русских плюралов: правило смотрит на n%100 и n%10. */
    private static int pluralQuantity(long n) {
        int q = (int) (n % 1000);
        return q == 0 ? 1000 : q;
    }

    private static String humanPorts(String value) {
        return value.replaceAll("\\s*,\\s*", ", ").replace('-', '\u2013');
    }

    /** Первая строка ошибки движка — дословно, без переписывания (§9). */
    static String firstLine(String text) {
        if (text == null) {
            return "";
        }
        String t = text.trim();
        int nl = t.indexOf('\n');
        String line = nl >= 0 ? t.substring(0, nl) : t;
        return line.trim();
    }
}
