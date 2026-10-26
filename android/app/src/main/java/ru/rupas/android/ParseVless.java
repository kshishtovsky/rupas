package ru.rupas.android;

/**
 * W3: парсер ссылок vless://uuid@host:port?params#label
 * Параметры reality: pbk=publicKey, sid=shortId, sni=SNI, fp игнорируем.
 * type: только tcp/xhttp; что-то другое — предупреждение (не ошибка).
 */
public final class ParseVless {

    public static final class Result {
        public final String uuid;
        public final String server;
        public final int port;
        public final String sni;
        public final String publicKey;
        public final String shortId;
        public final boolean fallback;
        /** Ненулевое предупреждение (например, неподдерживаемый transport). */
        public final String warning;

        Result(String uuid, String server, int port, String sni,
               String publicKey, String shortId, boolean fallback, String warning) {
            this.uuid = uuid;
            this.server = server;
            this.port = port;
            this.sni = sni;
            this.publicKey = publicKey;
            this.shortId = shortId;
            this.fallback = fallback;
            this.warning = warning;
        }
    }

    private ParseVless() {}

    /**
     * @throws IllegalArgumentException если ссылка не vless:// или не разбирается
     */
    public static Result parse(String link) {
        if (link == null) {
            throw new IllegalArgumentException("пустая ссылка");
        }
        String s = link.trim();
        if (!s.startsWith("vless://")) {
            throw new IllegalArgumentException("это не vless://-ссылка");
        }
        s = s.substring("vless://".length());

        // отрезаем #label
        int hash = s.indexOf('#');
        if (hash >= 0) {
            s = s.substring(0, hash);
        }

        // query-параметры
        String query = "";
        int q = s.indexOf('?');
        if (q >= 0) {
            query = s.substring(q + 1);
            s = s.substring(0, q);
        }

        // authority: uuid@host:port
        int at = s.lastIndexOf('@');
        if (at < 0) {
            throw new IllegalArgumentException("нет uuid@host:port");
        }
        String uuid = s.substring(0, at);
        String hostPort = s.substring(at + 1);
        if (uuid.isEmpty() || hostPort.isEmpty()) {
            throw new IllegalArgumentException("пустой uuid или host");
        }

        String host;
        int port;
        if (hostPort.startsWith("[")) { // IPv6-литерал [::1]:443
            int close = hostPort.indexOf(']');
            if (close < 0) {
                throw new IllegalArgumentException("незакрытая IPv6-скобка в host");
            }
            host = hostPort.substring(1, close);
            String rest = hostPort.substring(close + 1);
            if (!rest.startsWith(":")) {
                throw new IllegalArgumentException("нет порта после IPv6-хоста");
            }
            port = parsePort(rest.substring(1));
        } else {
            int colon = hostPort.lastIndexOf(':');
            if (colon < 0) {
                throw new IllegalArgumentException("нет порта");
            }
            host = hostPort.substring(0, colon);
            port = parsePort(hostPort.substring(colon + 1));
        }

        String sni = "";
        String publicKey = "";
        String shortId = "";
        String type = "";
        for (String kv : query.split("&")) {
            if (kv.isEmpty()) {
                continue;
            }
            int eq = kv.indexOf('=');
            String key = eq < 0 ? kv : kv.substring(0, eq);
            String val = eq < 0 ? "" : urlDecode(kv.substring(eq + 1));
            switch (key) {
                case "sni":
                    sni = val;
                    break;
                case "pbk":
                    publicKey = val;
                    break;
                case "sid":
                    shortId = val;
                    break;
                case "type":
                    type = val;
                    break;
                default:
                    // fp, security, flow, serviceName и пр. — игнорируем
            }
        }

        String warning = null;
        if (!type.isEmpty() && !"tcp".equals(type) && !"xhttp".equals(type)) {
            warning = "transport type=" + type + " не поддерживается (ожидались tcp/xhttp) — проверьте сервер";
        }
        return new Result(uuid, host, port, sni, publicKey, shortId, true, warning);
    }

    private static int parsePort(String p) {
        try {
            int port = Integer.parseInt(p);
            if (port <= 0 || port > 65535) {
                throw new IllegalArgumentException("порт вне диапазона: " + p);
            }
            return port;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("неверный порт: " + p);
        }
    }

    private static String urlDecode(String v) {
        try {
            return java.net.URLDecoder.decode(v, "UTF-8");
        } catch (Exception e) {
            return v;
        }
    }
}
