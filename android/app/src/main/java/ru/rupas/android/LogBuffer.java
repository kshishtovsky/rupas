package ru.rupas.android;

import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Date;
import java.util.Deque;
import java.util.Locale;

/**
 * Hallmark · diagnostics: ring buffer with INFO/DEBUG filtering and timestamping.
 */
public final class LogBuffer {

    public interface Listener {
        void onLogChanged(boolean debugOnly);
    }

    public static final class Entry {
        public final long timeMs;
        public final String text;
        public final boolean isDebug;

        public Entry(long timeMs, String text, boolean isDebug) {
            this.timeMs = timeMs;
            this.text = text;
            this.isDebug = isDebug;
        }
    }

    private static final int MAX_LINES = 1000;

    private static final Deque<Entry> ENTRIES = new ArrayDeque<>();
    // Сколько строк всего пришло (включая вытесненные): база для
    // инкрементальной выдачи entriesAfter().
    private static long totalAdded;

    private static final ThreadLocal<SimpleDateFormat> TIME_FMT =
            ThreadLocal.withInitial(() -> new SimpleDateFormat("HH:mm:ss.SSS", Locale.US));
    private static volatile Listener listener;

    private LogBuffer() {}

    public static void setListener(Listener l) {
        listener = l;
    }

    /** Сколько строк всего добавлено с момента последнего clear(). */
    public static synchronized long total() {
        return totalAdded;
    }

    /**
     * Строки, добавленные после заданного счётчика total(). Позволяет UI
     * дополнять журнал без полного setText (тот сбрасывает прокрутку).
     */
    public static synchronized Entry[] entriesAfter(long total) {
        Entry[] all = ENTRIES.toArray(new Entry[0]);
        long base = totalAdded - all.length;
        int skip = (int) Math.max(0, Math.min(all.length, total - base));
        return Arrays.copyOfRange(all, skip, all.length);
    }

    /** Готовая строка "HH:mm:ss.SSS текст\n". */
    public static String formatEntry(Entry e) {
        return TIME_FMT.get().format(new Date(e.timeMs)) + " " + e.text + '\n';
    }

    public static void add(String line) {
        if (line == null || line.trim().isEmpty()) {
            return;
        }
        long now = System.currentTimeMillis();
        boolean isDebug = isDebugLine(line);
        // Сетевые события остаются в кольцевом буфере, но не пишутся в logcat
        // при каждом новом соединении (дублирование I/O и расход батареи).
        if (!isDebug) android.util.Log.d("RupasVpn", line);

        synchronized (LogBuffer.class) {
            ENTRIES.addLast(new Entry(now, line, isDebug));
            while (ENTRIES.size() > MAX_LINES) {
                ENTRIES.removeFirst();
            }
            totalAdded++;
        }

        Listener l = listener;
        if (l != null) {
            l.onLogChanged(isDebug);
        }
    }

    /**
     * Возвращает дамп логов в зависимости от уровня (INFO vs DEBUG).
     * Снимок копируется под коротким локом, форматирование идёт вне его:
     * иначе рендер UI блокирует add() из Go-потока на всё время dump().
     */
    public static String dump(boolean includeDebug) {
        Entry[] snapshot;
        synchronized (LogBuffer.class) {
            snapshot = ENTRIES.toArray(new Entry[0]);
        }
        StringBuilder sb = new StringBuilder(snapshot.length * 48);
        for (Entry e : snapshot) {
            if (!includeDebug && e.isDebug) {
                continue;
            }
            sb.append(formatEntry(e));
        }
        return sb.toString();
    }

    public static String dump() {
        return dump(false); // default: INFO
    }

    public static void clear() {
        synchronized (LogBuffer.class) {
            ENTRIES.clear();
            totalAdded = 0;
        }
        Listener l = listener;
        if (l != null) {
            l.onLogChanged(false);
        }
    }

    private static boolean isDebugLine(String line) {
        String lower = line.toLowerCase(Locale.US);
        // Рутинный сетевой трассинг пакетов — это DEBUG.
        if (lower.contains("tcp flow:") || lower.contains("udp session:")) {
            return true;
        }
        if (lower.contains("debug") || lower.contains("trace")) {
            return true;
        }
        // [vpn], [settings], CH sni=, errors, warnings, relay up — это INFO.
        return false;
    }
}
