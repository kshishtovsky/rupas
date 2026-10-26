package ru.rupas.android;

import java.util.ArrayDeque;
import java.util.Deque;

/**
 * Потокобезопасный кольцевой буфер строк лога (заполняется из core.Platform.log,
 * читается MainActivity). Максимум MAX_LINES, старые строки вытесняются.
 */
public final class LogBuffer {

    public interface Listener {
        void onLogChanged();
    }

    private static final int MAX_LINES = 500;

    private static final Deque<String> LINES = new ArrayDeque<>();
    private static volatile Listener listener;

    private LogBuffer() {}

    public static void setListener(Listener l) {
        listener = l;
    }

    public static void add(String line) {
        // Дублируем в logcat: стартовые строки ([vpn]/[settings]/[core]) иначе
        // видны только на экране приложения и недоступны для adb-диагностики.
        android.util.Log.d("RupasVpn", line);
        synchronized (LogBuffer.class) {
            LINES.addLast(line);
            while (LINES.size() > MAX_LINES) {
                LINES.removeFirst();
            }
        }
        Listener l = listener;
        if (l != null) {
            l.onLogChanged();
        }
    }

    /** Снимок буфера одной строкой (для UI). */
    public static String dump() {
        synchronized (LogBuffer.class) {
            StringBuilder sb = new StringBuilder();
            for (String s : LINES) {
                sb.append(s).append('\n');
            }
            return sb.toString();
        }
    }

    public static void clear() {
        synchronized (LogBuffer.class) {
            LINES.clear();
        }
        Listener l = listener;
        if (l != null) {
            l.onLogChanged();
        }
    }
}
