package ru.rupas.android;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.text.TextUtils;

import java.text.Collator;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Каталог приложений для 4-й стадии и экрана выбора (docs/PERAPP_ROUTING.md §4).
 *
 * Только PackageManager, без новых зависимостей: список — приложения с разрешением
 * INTERNET (без него правилу нечего маршрутизировать), себя не показываем —
 * rupas всегда вне VPN. Системные приложения не скрываются: они нужны фильтру
 * «Системные», где живут сервисы вроде Play.
 */
final class AppCatalog {

    /** Одно приложение: пакет, человеческое имя, флаг «системное», UID. */
    static final class Entry {
        final String pkg;
        final String label;
        final boolean system;
        final int uid;

        private final ApplicationInfo info;
        private Drawable icon;

        Entry(ApplicationInfo info, PackageManager pm) {
            this.info = info;
            this.pkg = info.packageName;
            this.uid = info.uid;
            this.system = (info.flags & ApplicationInfo.FLAG_SYSTEM) != 0
                    || (info.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0;
            CharSequence l;
            try {
                l = info.loadLabel(pm);
            } catch (Throwable t) {
                l = null; // пакет могли удалить между сканом и чтением
            }
            this.label = l == null || l.toString().trim().isEmpty() ? pkg : l.toString().trim();
        }

        /** Иконка грузится по требованию: 150 иконок сразу — лишние мегабайты. */
        Drawable icon(PackageManager pm) {
            if (icon == null) {
                try {
                    icon = info.loadIcon(pm);
                } catch (Throwable t) {
                    icon = null;
                }
                if (icon == null) {
                    icon = pm.getDefaultActivityIcon();
                }
            }
            return icon;
        }

        /** Поиск по имени и пакету (§4). */
        boolean matches(String query) {
            if (TextUtils.isEmpty(query)) {
                return true;
            }
            String q = query.trim().toLowerCase(Locale.ROOT);
            return label.toLowerCase(Locale.ROOT).contains(q)
                    || pkg.toLowerCase(Locale.ROOT).contains(q);
        }
    }

    private static volatile List<Entry> cachedAll;
    private static final Map<String, Entry> byPkg = new HashMap<>();

    private AppCatalog() {
    }

    /** Полный список (сканирование один раз на процесс). Блокирующий — звать не из UI-потока. */
    static List<Entry> all(Context ctx) {
        List<Entry> c = cachedAll;
        if (c != null) {
            return c;
        }
        return scan(ctx);
    }

    static synchronized List<Entry> scan(Context ctx) {
        if (cachedAll != null) {
            return cachedAll;
        }
        PackageManager pm = ctx.getPackageManager();
        String self = ctx.getPackageName();
        Map<String, Entry> map = new LinkedHashMap<>();

        // 1) Приложения с иконкой в лончере — MATCH_ALL, чтобы не терять отключённые компоненты.
        try {
            Intent main = new Intent(Intent.ACTION_MAIN, null);
            main.addCategory(Intent.CATEGORY_LAUNCHER);
            List<ResolveInfo> ris = pm.queryIntentActivities(main, PackageManager.MATCH_ALL);
            for (ResolveInfo ri : ris) {
                if (ri == null || ri.activityInfo == null || ri.activityInfo.applicationInfo == null) {
                    continue;
                }
                add(map, pm, self, ri.activityInfo.applicationInfo);
            }
        } catch (Throwable t) {
            LogBuffer.add("[apps] queryIntentActivities: " + t);
        }

        // 2) Всё остальное с INTERNET: сервисы и приложения без лончера тоже маршрутизируются.
        try {
            List<ApplicationInfo> apps = pm.getInstalledApplications(PackageManager.GET_META_DATA);
            for (ApplicationInfo ai : apps) {
                add(map, pm, self, ai);
            }
        } catch (Throwable t) {
            LogBuffer.add("[apps] getInstalledApplications: " + t);
        }

        List<Entry> out = new ArrayList<>(map.values());
        final Collator col = Collator.getInstance(new Locale("ru", "RU"));
        Collections.sort(out, (a, b) -> {
            int c = col.compare(a.label, b.label);
            return c != 0 ? c : a.pkg.compareTo(b.pkg);
        });
        byPkg.clear();
        byPkg.putAll(map);
        cachedAll = out;
        return out;
    }

    private static void add(Map<String, Entry> map, PackageManager pm, String self, ApplicationInfo ai) {
        if (ai == null || TextUtils.isEmpty(ai.packageName) || self.equals(ai.packageName)) {
            return; // себя не показываем: rupas всегда вне VPN (§4)
        }
        if (map.containsKey(ai.packageName) || !hasInternet(pm, ai.packageName)) {
            return;
        }
        map.put(ai.packageName, new Entry(ai, pm));
    }

    /** Разрешение INTERNET — единственный критерий «этому приложению есть что маршрутизировать». */
    private static boolean hasInternet(PackageManager pm, String pkg) {
        try {
            return pm.checkPermission(android.Manifest.permission.INTERNET, pkg)
                    == PackageManager.PERMISSION_GRANTED;
        } catch (Throwable t) {
            return false;
        }
    }

    /** Запись по пакету; null — приложение удалено (правило станет «висячим»). */
    static Entry get(Context ctx, String pkg) {
        if (TextUtils.isEmpty(pkg)) {
            return null;
        }
        Entry e = byPkg.get(pkg);
        if (e != null) {
            return e;
        }
        all(ctx);
        e = byPkg.get(pkg);
        if (e != null) {
            return e;
        }
        // Пакет не в списке (нет INTERNET-разрешения или появился позже) — резолвим точечно,
        // чтобы строка правила не потеряла имя и иконку.
        try {
            PackageManager pm = ctx.getPackageManager();
            ApplicationInfo ai = pm.getApplicationInfo(pkg, 0);
            e = new Entry(ai, pm);
            synchronized (AppCatalog.class) {
                byPkg.put(pkg, e);
            }
            return e;
        } catch (Throwable t) {
            return null;
        }
    }

    static String label(Context ctx, String pkg) {
        Entry e = get(ctx, pkg);
        return e == null ? pkg : e.label;
    }

    /** Алфавитный порядок для списка выбранных на экране «Маршруты». */
    static void sortByLabel(Context ctx, List<AppRule> rules) {
        if (rules == null || rules.isEmpty()) {
            return;
        }
        // Прогрев каталога обязателен: строки приложений читают имя и иконку в bind(),
        // а PackageManager-скан на главном потоке — это заметный подлаг при старте.
        all(ctx);
        if (rules.size() < 2) {
            return;
        }
        final Collator col = Collator.getInstance(new Locale("ru", "RU"));
        Collections.sort(rules, (a, b) -> {
            if (a == null || b == null) {
                return 0;
            }
            int c = col.compare(label(ctx, a.pkg), label(ctx, b.pkg));
            return c != 0 ? c : a.pkg.compareTo(b.pkg);
        });
    }

    /**
     * §5: у нескольких пакетов может быть один UID — правило применится ко всем.
     * Считаем, сколько ещё пакетов в выбранном наборе делят UID с этим.
     */
    static int sharedUidCount(Context ctx, String pkg, Collection<AppRule> rules) {
        if (rules == null || rules.size() < 2) {
            return 0;
        }
        Entry self = get(ctx, pkg);
        if (self == null || self.uid <= 0) {
            return 0;
        }
        int n = 0;
        for (AppRule r : rules) {
            if (r == null || pkg.equals(r.pkg)) {
                continue;
            }
            Entry other = get(ctx, r.pkg);
            if (other != null && other.uid == self.uid) {
                n++;
            }
        }
        return n;
    }

    /** Android 10+ — порог для TUNNEL/BLOCK по UID (§7.1). */
    static boolean supportsUidRouting() {
        return Build.VERSION.SDK_INT >= AppRule.ADVANCED_MIN_API;
    }
}
