package ru.rupas.android;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Universal share-link intake for the W3 core (parity with the Go side).
 * The core's SetSettings accepts a "links" array of standard share links
 * in dial order: the first is the primary carrier, the rest are fallbacks.
 * Supported schemes: vless://, hysteria2://, hy2://, trojan://.
 *
 * Java validates the shape loosely; the authoritative parse lives in Go
 * (internal/transport/android/sharelink.go) and its errors surface in the
 * VPN log. Flat legacy fields (uuid/server/port/...) are filled from the
 * FIRST link for display and backward compatibility.
 */
public final class ParseLink {

    private static final Pattern SCHEME_HOST_PORT = Pattern.compile(
            "^(vless|hysteria2|hy2|trojan)://([^@\\s/]+)@(\\[[^\\]]+\\]|[^:/\\s]+):(\\d{1,5})([/?#].*)?$");

    private ParseLink() {}

    /** A flat view of the first link (legacy display fields). */
    public static final class Flat {
        public String uuid = "";
        public String server = "";
        public int port;
        public String sni = "";
        public String publicKey = "";
        public String shortId = "";
        /** Non-fatal import notice (unsupported transport etc.), null when clean. */
        public String warning;
    }

    /**
     * Splits a pasted block into validated share links. Links may be
     * separated by newlines, commas or spaces. Accepts a single link too.
     *
     * @throws IllegalArgumentException when nothing valid is found
     */
    public static List<String> splitInput(String raw) {
        if (raw == null || raw.trim().isEmpty()) {
            throw new IllegalArgumentException("empty input");
        }
        List<String> out = new ArrayList<>();
        for (String token : raw.trim().split("[\\s,]+")) {
            if (token.isEmpty()) continue;
            if (!token.contains("://")) continue;
            Matcher m = SCHEME_HOST_PORT.matcher(token);
            if (!m.matches()) {
                throw new IllegalArgumentException("bad link: " + abbreviate(token));
            }
            int port = Integer.parseInt(m.group(4));
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("bad port in: " + abbreviate(token));
            }
            out.add(token);
        }
        if (out.isEmpty()) {
            throw new IllegalArgumentException("no share links found (want vless://, hysteria2:// or trojan://)");
        }
        return out;
    }

    /**
     * Fills the legacy flat view from the first link (any scheme): vless
     * links go through the full ParseVless parser; hysteria2/trojan fill
     * password/host/port (password lands in the uuid display field, the
     * authoritative value travels inside the link itself).
     */
    public static Flat flattenLegacy(String link) {
        Flat f = new Flat();
        if (link.startsWith("vless://")) {
            ParseVless.Result r = ParseVless.parse(link);
            f.uuid = r.uuid;
            f.server = r.server;
            f.port = r.port;
            f.sni = r.sni;
            f.publicKey = r.publicKey;
            f.shortId = r.shortId;
            f.warning = r.warning;
            return f;
        }
        Matcher m = SCHEME_HOST_PORT.matcher(link);
        if (!m.matches()) {
            throw new IllegalArgumentException("bad link: " + abbreviate(link));
        }
        f.uuid = m.group(2); // password
        f.server = m.group(3).replace("[", "").replace("]", "");
        f.port = Integer.parseInt(m.group(4));
        // sni query param, when present.
        int q = link.indexOf('?');
        if (q >= 0) {
            for (String kv : link.substring(q + 1).split("&")) {
                if (kv.startsWith("sni=")) {
                    f.sni = urlDecode(kv.substring(4));
                }
            }
        }
        return f;
    }

    private static String urlDecode(String v) {
        try {
            return java.net.URLDecoder.decode(v, "UTF-8");
        } catch (Exception e) {
            return v;
        }
    }

    /**
     * Человекочитаемая подпись канала для UI приоритетов: ярлык после '#'
     * (например "rupas-reality"), иначе "хост:порт"; префикс — схема
     * (hy2 разворачивается в hysteria2).
     */
    public static String describe(String link) {
        String scheme = scheme(link);
        String label = fragment(link);
        if (label.isEmpty()) {
            label = hostPort(link);
        }
        if (scheme.isEmpty()) {
            return label.isEmpty() ? link : label;
        }
        return label.isEmpty() ? scheme : scheme + " · " + label;
    }

    /** Метка профиля: ярлык из '#' (декодированный), иначе хост:порт, иначе схема. */
    public static String label(String link) {
        if (link == null || link.trim().isEmpty()) {
            return "";
        }
        String label = fragment(link);
        if (label.isEmpty()) {
            label = hostPort(link);
        }
        if (label.isEmpty()) {
            label = scheme(link);
        }
        return label;
    }

    /**
     * Вторая строка карточки профиля: тип · хост:порт · SNI.
     * Тип — reality для vless с security=reality/pbk, иначе схема (hy2 → hysteria2).
     */
    public static String subtitle(String link) {
        if (link == null || link.trim().isEmpty()) {
            return "";
        }
        String type = scheme(link);
        if ("vless".equals(type)
                && (link.contains("security=reality") || link.contains("pbk="))) {
            type = "reality";
        }
        String host = hostPort(link);
        String sni = param(link, "sni");
        StringBuilder sb = new StringBuilder(type);
        if (!host.isEmpty()) {
            if (sb.length() > 0) sb.append(" · ");
            sb.append(host);
        }
        if (!sni.isEmpty()) {
            if (sb.length() > 0) sb.append(" · ");
            sb.append(sni);
        }
        return sb.toString();
    }

    /** Схема ссылки, hy2 развёрнута в hysteria2; "" если ссылка битая. */
    private static String scheme(String link) {
        int se = link == null ? -1 : link.indexOf("://");
        if (se <= 0) {
            return "";
        }
        String s = link.substring(0, se);
        return s.equals("hy2") ? "hysteria2" : s;
    }

    /** Ярлык после '#' (декодированный), "" если фрагмента нет. */
    private static String fragment(String link) {
        int h = link == null ? -1 : link.indexOf('#');
        if (h < 0 || h + 1 >= link.length()) {
            return "";
        }
        return urlDecode(link.substring(h + 1).trim());
    }

    /** "хост:порт" из authority, "" если ссылка не разбирается. */
    private static String hostPort(String link) {
        Matcher m = link == null ? null : SCHEME_HOST_PORT.matcher(link.trim());
        if (m == null || !m.matches()) {
            return "";
        }
        return m.group(3).replace("[", "").replace("]", "") + ":" + m.group(4);
    }

    /** Значение query-параметра (до '#'); "" если его нет. */
    private static String param(String link, String key) {
        int q = link == null ? -1 : link.indexOf('?');
        if (q < 0) {
            return "";
        }
        int end = link.indexOf('#');
        String query = end > q ? link.substring(q + 1, end) : link.substring(q + 1);
        for (String kv : query.split("&")) {
            if (kv.startsWith(key + "=")) {
                String v = kv.substring(key.length() + 1);
                if (!v.isEmpty()) {
                    return urlDecode(v);
                }
            }
        }
        return "";
    }

    private static String abbreviate(String s) {
        return s.length() <= 48 ? s : s.substring(0, 48) + "...";
    }
}
