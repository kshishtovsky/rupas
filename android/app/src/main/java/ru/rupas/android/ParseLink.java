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
        String scheme = "";
        int se = link.indexOf("://");
        if (se > 0) {
            scheme = link.substring(0, se);
        }
        if (scheme.equals("hy2")) {
            scheme = "hysteria2";
        }
        String label = "";
        int h = link.indexOf('#');
        if (h >= 0) {
            label = link.substring(h + 1).trim();
        }
        if (label.isEmpty()) {
            Matcher m = SCHEME_HOST_PORT.matcher(link);
            if (m.matches()) {
                label = m.group(3) + ":" + m.group(4);
            }
        }
        if (scheme.isEmpty()) {
            return label.isEmpty() ? link : label;
        }
        return label.isEmpty() ? scheme : scheme + " · " + label;
    }

    private static String abbreviate(String s) {
        return s.length() <= 48 ? s : s.substring(0, 48) + "...";
    }
}
