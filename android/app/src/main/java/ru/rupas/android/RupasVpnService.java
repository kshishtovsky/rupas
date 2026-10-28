package ru.rupas.android;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.system.OsConstants;
import android.util.Log;

import androidx.core.app.NotificationCompat;

import org.json.JSONObject;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Map;

import core.Core;
import core.Platform;

/**
 * VpnService-каркас W2: поднимает TUN, отдаёт fd в core.Core.start(fd, platform).
 * Трафик на этом этапе — DIRECT (ядро само решает, куда его отправить).
 */
public class RupasVpnService extends VpnService {

    private static final String TAG = "RupasVpn";
    private static final String CHANNEL_ID = "rupas_vpn";
    private static final int NOTIFICATION_ID = 1;

    private static final String VPN_ADDRESS = "26.26.26.1";
    private static final int VPN_ADDRESS_PREFIX = 24;
    private static final String VPN_ROUTE = "0.0.0.0";
    private static final int VPN_ROUTE_PREFIX = 0;
    // W3-контракт с Go-стороной: она вешает на TUN fdfe:dcba:9876::1/126,
    // Java обязана задать тот же адрес и заворачивать весь IPv6 (::/0).
    private static final String VPN_ADDRESS_V6 = "fdfe:dcba:9876::1";
    private static final int VPN_ADDRESS_V6_PREFIX = 126;
    private static final String VPN_ROUTE_V6 = "::";
    private static final int VPN_ROUTE_V6_PREFIX = 0;
    // W2: локального резолвера в ядре ещё нет (SYSTEM_DESIGN §11 — W3), поэтому
    // DNS = публичный резолвер: его UDP:53 входит в TUN и релеится direct
    // через защищённый сокет. 26.26.26.1 (адрес TUN) здесь нельзя — запросы
    // зациклятся, резолв умирает ("unknown host").
    private static final String VPN_DNS = "8.8.8.8";
    private static final int VPN_MTU = 1500;

    // Per-app routing (docs/PERAPP_ROUTING.md §5): список DIRECT-приложений и
    // UID-правила теперь приходят из настроек (SettingsStore.appRules), здесь
    // констант нет. Пустой набор правил == поведение до per-app routing.

    private static volatile boolean running = false;
    private static volatile RupasVpnService instance = null;

    private ParcelFileDescriptor tun;
    private PlatformImpl platform;
    // Последнее собранное уведомление (честный статус туннеля после старта).
    private Notification notification;
    // Ядро запускалось именно этим экземпляром (binding с BIND_AUTO_CREATE
    // создаёт сервис без onStartCommand — останавливать нечего).
    private boolean coreStartedByInstance;

    /** Для MainActivity: поднят ли туннель. */
    public static boolean isRunning() {
        return running;
    }

    /** Действие: переподнять ядро с новыми настройками (см. onStartCommand). */
    public static final String ACTION_RESTART = "ru.rupas.android.RESTART";
    /** Действие: отключить VPN по нажатию кнопки в шторке уведомлений. */
    public static final String ACTION_DISCONNECT = "ru.rupas.android.DISCONNECT";

    /** Запустить VPN-сервис. */
    public static void start(Context ctx) {
        Intent i = new Intent(ctx, RupasVpnService.class);
        if (Build.VERSION.SDK_INT >= 26) {
            ctx.startForegroundService(i);
        } else {
            ctx.startService(i);
        }
    }

    /** Остановить VPN-сервис. */
    public static void stop(Context ctx) {
        if (instance != null) {
            instance.stopForegroundAndSelf();
            return;
        }
        Intent i = new Intent(ctx, RupasVpnService.class).setAction(ACTION_DISCONNECT);
        if (Build.VERSION.SDK_INT >= 26) {
            ctx.startForegroundService(i);
        } else {
            ctx.startService(i);
        }
    }

    /** Перезапустить VPN с текущими настройками, если он поднят. false — не поднят. */
    public static boolean restartIfRunning(Context ctx) {
        if (!running) {
            return false;
        }
        Intent i = new Intent(ctx, RupasVpnService.class).setAction(ACTION_RESTART);
        if (Build.VERSION.SDK_INT >= 26) {
            ctx.startForegroundService(i);
        } else {
            ctx.startService(i);
        }
        return true;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        instance = this;
        createNotificationChannel(this);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_DISCONNECT.equals(intent.getAction())) {
            LogBuffer.add("[vpn] отключение по кнопке из шторки");
            stopForegroundAndSelf();
            return START_NOT_STICKY;
        }

        // Не пересоздаём TUN при повторном startService без явного RESTART.
        if (coreStartedByInstance && (intent == null || !ACTION_RESTART.equals(intent.getAction()))) {
            return START_STICKY;
        }
        startForegroundWithStatus();
        // RESTART (пришёл из сохранения настроек): настроек на лету движок не
        // перечитывает (SetSettings при работающем движке = ошибка), поэтому
        // переподнимаем TUN+ядро целиком — иначе новый endpoint не применится.
        if (intent != null && ACTION_RESTART.equals(intent.getAction())) {
            LogBuffer.add("[vpn] restart: применяем новые настройки");
            stopCore();
        }
        if (!establishAndStartCore()) {
            Log.e(TAG, "failed to establish TUN or start core");
            stopForegroundAndSelf();
            return START_NOT_STICKY;
        }
        running = true;
        // Статистика отображается на открытом экране; фоновое уведомление
        // статично, чтобы не будить процесс и SystemUI каждые 1,5 секунды.
        // Состояние туннеля выставляется асинхронно (relay стартует в
        // goroutine ядра): сразу после старта его ещё нет, поэтому честный
        // статус подставляем одним отложенным апдейтом.
        new Handler(Looper.getMainLooper()).postDelayed(this::refreshTunnelNotification, 3000);
        return START_STICKY;
    }

    /**
     * Честный статус в уведомлении: «защищено» — только когда в Status()
     * туннель реально поднят. Иначе приложение утверждало защиту, пока все
     * TUNNEL-потоки эскалировали в direct (Telegram висел в соединении).
     */
    private void refreshTunnelNotification() {
        String state = "off";
        String detail = "";
        String adblock = "";
        int blocked = 0;
        try {
            JSONObject st = new JSONObject(Core.status());
            state = st.optString("tunnel", "off");
            detail = st.optString("tunnel_detail", "");
            adblock = st.optString("adblock", "");
            blocked = st.optInt("adblock_blocked", 0);
        } catch (Throwable ignored) {
        }
        // Фильтр рекламы (0.4.0): короткий суффикс, без новых таймеров.
        String adSuffix = "failed".equals(adblock) ? " · фильтр не поднялся"
                : ("on".equals(adblock) ? " · реклама: " + blocked : "");
        if ("on".equals(state)) {
            notification = buildNotification("Rupas: защищено", "Защита активна" + adSuffix,
                    "Туннель " + detail);
        } else {
            notification = buildNotification("Rupas: туннель не поднят", "Трафик идёт напрямую" + adSuffix,
                    detail.isEmpty() ? "Проверьте настройки" : detail);
        }
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm != null && running) {
            nm.notify(NOTIFICATION_ID, notification);
        }
    }

    @Override
    public void onRevoke() {
        // VPN-коннект разорван системой (или пользователь отключил в настройках).
        stopForegroundAndSelf();
    }

    @Override
    public void onDestroy() {
        stopCore();
        running = false;
        if (instance == this) {
            instance = null;
        }
        super.onDestroy();
    }

    private boolean establishAndStartCore() {
        // Per-app routing (§5): настройки читаются ДО Builder — DIRECT-приложения
        // обязаны быть исключены до establish(), иначе их трафик уже войдёт в TUN.
        SettingsStore.Settings st = null;
        try {
            st = new SettingsStore(this).load();
        } catch (Exception e) {
            // Отказ хранилища/битый JSON: стартуем как раньше, без per-app.
            Log.e(TAG, "settings load failed", e);
            LogBuffer.add("[vpn] настройки не прочитаны: " + e.getMessage());
        }
        Builder b = new Builder()
                .addAddress(VPN_ADDRESS, VPN_ADDRESS_PREFIX)
                .addAddress(VPN_ADDRESS_V6, VPN_ADDRESS_V6_PREFIX)
                .addRoute(VPN_ROUTE, VPN_ROUTE_PREFIX)
                .addRoute(VPN_ROUTE_V6, VPN_ROUTE_V6_PREFIX)
                .addDnsServer(VPN_DNS)
                .setMtu(VPN_MTU)
                .setSession("rupas");
        // Самопакет: иначе наш же трафик зациклится через TUN.
        try {
            b.addDisallowedApplication(getPackageName());
        } catch (Exception e) {
            Log.w(TAG, "disallowed self rejected: " + e);
        }
        // Per-app: DIRECT → вне VPN (ОС-слой), TUNNEL/BLOCK → uid в JSON для ядра.
        applyAppRules(b, st);
        try {
            tun = b.establish();
        } catch (Exception e) {
            Log.e(TAG, "establish() failed", e);
            return false;
        }
        if (tun == null) {
            return false;
        }
        platform = new PlatformImpl();
        // W3: настройки туннеля — ДО Core.start. Пустые настройки = tunnel off:
        // Go-сторона эскалирует все туннельные правила в direct. В логах —
        // только факт и хост; никаких uuid/ключей.
        try {
            if (st != null) {
                // Всегда отправляем снимок: в нём живёт и фильтр рекламы.
                // Документ без эндпоинта (ноль включённых профилей) ядро
                // принимает как «туннель off, фильтр работает».
                CoreBridge.setSettings(st.toJson());
                if (st.isConfigured()) {
                    LogBuffer.add("[vpn] tunnel: on (server " + st.server + ":" + st.port + ")");
                } else {
                    LogBuffer.add("[vpn] tunnel: off (профили не включены — трафик напрямую)");
                }
            }
        } catch (Exception e) {
            // Невалидный JSON/отказ хранилища/заглушечный AAR — стартуем без туннеля.
            Log.e(TAG, "setSettings failed", e);
            LogBuffer.add("[vpn] setSettings failed: " + e.getMessage() + " — tunnel off");
        }
        // W3: открепляем fd от ParcelFileDescriptor, передавая владение Go sing-tun (иначе
        // Android libc fdsan валит процесс SIGABRT при закрытии fd со стороны Go).
        int fd = tun.detachFd();
        try {
            // gobind: Go error → Java exception, метод возвращает void
            Core.start(fd, platform);
        } catch (Exception e) {
            Log.e(TAG, "core.Core.start failed", e);
            LogBuffer.add("[vpn] core start failed: " + e.getMessage());
            try {
                ParcelFileDescriptor.adoptFd(fd).close();
            } catch (Exception ignored) {
            }
            tun = null;
            return false;
        }
        LogBuffer.add("[vpn] TUN fd=" + fd + ", core started");
        coreStartedByInstance = true;
        return true;
    }

    /**
     * Раскладывает сохранённые per-app правила (§5) по двум слоям:
     * direct → {@code addDisallowedApplication} (приложение вне VPN, API 26+);
     * tunnel|block → package→uid через PackageManager, uid кладётся в JSON для ядра.
     * Неизвестный пакет/битая запись не валит старт — только строка в лог.
     */
    private void applyAppRules(Builder b, SettingsStore.Settings st) {
        if (st == null || st.appRules.isEmpty()) {
            return; // нет правил == поведение до per-app routing
        }
        PackageManager pm = getPackageManager();
        int direct = 0;
        int uidRules = 0;
        int skipped = 0;
        for (Map.Entry<String, String> e : st.appRules.entrySet()) {
            String pkg = e.getKey() == null ? "" : e.getKey().trim();
            String action = SettingsStore.normalizeAction(e.getValue());
            if (pkg.isEmpty() || action == null || pkg.equals(getPackageName())) {
                skipped++;
                continue;
            }
            if (SettingsStore.APP_DIRECT.equals(action)) {
                try {
                    b.addDisallowedApplication(pkg);
                    direct++;
                } catch (Exception ex) {
                    skipped++;
                    LogBuffer.add("[vpn] app direct " + pkg + ": пропущено ("
                            + ex.getClass().getSimpleName() + ")");
                }
                continue;
            }
            // tunnel|block: ядру нужен uid, а UID-резолв существует только с API 29.
            if (Build.VERSION.SDK_INT < 29) {
                skipped++;
                LogBuffer.add("[vpn] app " + action + " " + pkg + ": пропущено — нужен Android 10+");
                continue;
            }
            try {
                int uid = pm.getApplicationInfo(pkg, 0).uid;
                if (uid <= 0) {
                    skipped++;
                    continue;
                }
                st.coreAppRules.put(uid, action);
                uidRules++;
            } catch (Exception ex) {
                skipped++;
                LogBuffer.add("[vpn] app " + action + " " + pkg + ": пакет не найден, пропущено");
            }
        }
        LogBuffer.add("[vpn] app rules: direct " + direct + ", uid " + uidRules
                + (skipped > 0 ? ", пропущено " + skipped : ""));
    }

    private void stopCore() {
        if (!coreStartedByInstance) {
            return;
        }
        coreStartedByInstance = false;
        try {
            Core.stop();
        } catch (Throwable t) {
            Log.w(TAG, "core.stop: " + t);
        }
        if (tun != null) {
            try {
                tun.close();
            } catch (Exception ignored) {
            }
            tun = null;
        }
        if (platform != null && platform.uidFailCount > 0) {
            LogBuffer.add("[vpn] resolveUID: отказов " + platform.uidFailCount
                    + " — эти потоки шли по общим правилам");
        }
        platform = null;
        LogBuffer.add("[vpn] stopped");
    }

    private void stopForegroundAndSelf() {
        stopCore();
        running = false;
        if (Build.VERSION.SDK_INT >= 24) {
            stopForeground(STOP_FOREGROUND_REMOVE);
        } else {
            stopForeground(true);
        }
        Context appCtx = getApplicationContext();
        showOfflineNotification(appCtx);
        stopSelf();
    }

    public static void createNotificationChannel(Context ctx) {
        NotificationManager nm = ctx.getSystemService(NotificationManager.class);
        if (nm == null) {
            return;
        }
        NotificationChannel ch = new NotificationChannel(
                CHANNEL_ID, "Rupas VPN", NotificationManager.IMPORTANCE_LOW);
        ch.setDescription("Статус VPN-туннеля Rupas");
        nm.createNotificationChannel(ch);
    }

    public static void showOfflineNotification(Context context) {
        NotificationManager nm = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm == null) return;
        createNotificationChannel(context);

        Intent open = new Intent(context, MainActivity.class)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent piOpen = PendingIntent.getActivity(
                context, 0, open,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        PendingIntent piConnect;
        Intent prepare = VpnService.prepare(context);
        if (prepare != null) {
            Intent actConnect = new Intent(context, MainActivity.class)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP)
                    .putExtra("connect", true);
            piConnect = PendingIntent.getActivity(
                    context, 2, actConnect,
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        } else {
            Intent srvConnect = new Intent(context, RupasVpnService.class);
            if (Build.VERSION.SDK_INT >= 26) {
                piConnect = PendingIntent.getForegroundService(
                        context, 2, srvConnect,
                        PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            } else {
                piConnect = PendingIntent.getService(
                        context, 2, srvConnect,
                        PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            }
        }

        NotificationCompat.Builder b = new NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_stat_vpn)
                .setContentTitle("Туннель выключен")
                .setContentText("Трафик идёт напрямую")
                .setSubText("Rupas")
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setContentIntent(piOpen)
                .addAction(R.drawable.ic_power, "Включить", piConnect);

        nm.notify(NOTIFICATION_ID, b.build());
    }

    private void startForegroundWithStatus() {
        Notification n = buildNotification("Туннель включён", "Защита активна", "Запускаем…");
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, n,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NOTIFICATION_ID, n);
        }
    }

    private Notification buildNotification(String title, String content, String subText) {
        Intent open = new Intent(this, MainActivity.class);
        PendingIntent piOpen = PendingIntent.getActivity(
                this, 0, open,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Intent disconnect = new Intent(this, RupasVpnService.class).setAction(ACTION_DISCONNECT);
        PendingIntent piDisconnect;
        if (Build.VERSION.SDK_INT >= 26) {
            piDisconnect = PendingIntent.getForegroundService(
                    this, 1, disconnect,
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        } else {
            piDisconnect = PendingIntent.getService(
                    this, 1, disconnect,
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        }

        NotificationCompat.Builder b = new NotificationCompat.Builder(this, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_stat_vpn)
                .setContentTitle(title)
                .setContentText(content)
                .setSubText(subText)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setContentIntent(piOpen)
                .addAction(R.drawable.ic_power, "Отключить", piDisconnect);

        return b.build();
    }

    /** Реализация core.Platform: protect() → VpnService.protect(), log() → кольцевой буфер.
     *  Сигнатура long: gobind отображает Go int → Java long (реальный AAR). */
    private class PlatformImpl implements Platform {

        // Отказ резолва логируем один раз (иначе hot path зальёт LogBuffer),
        // дальше только считаем — счётчик виден в итоговой строке stopCore().
        private boolean uidFailLogged;
        private int uidFailCount;

        @Override
        public boolean protect(long fd) {
            return RupasVpnService.this.protect((int) fd);
        }

        @Override
        public void log(String line) {
            LogBuffer.add(line);
        }

        @Override
        public String filesDir() {
            // Go-сторона создаёт здесь protect unix-socket файл релея.
            return getFilesDir().getAbsolutePath();
        }

        /**
         * Per-app routing (§2): UID владельца flow для ядра. -1 == «неизвестен»
         * (Go честно деградирует к общим правилам), резолв только на новый flow.
         * Имя — ровно как в gobind-интерфейсе: Go `ResolveUID` → Java `resolveUID`
         * (проверено javap по собранному AAR; `resolveUid` из §6 не переопределил бы метод).
         */
        @Override
        public long resolveUID(String network, String srcIp, long srcPort, String dstIp, long dstPort) {
            if (Build.VERSION.SDK_INT < 29) {
                return -1; // getConnectionOwnerUid появился в Android 10
            }
            try {
                int proto = "udp".equalsIgnoreCase(network)
                        ? OsConstants.IPPROTO_UDP
                        : OsConstants.IPPROTO_TCP;
                ConnectivityManager cm = getSystemService(ConnectivityManager.class);
                if (cm == null) {
                    return -1;
                }
                InetSocketAddress src = new InetSocketAddress(
                        InetAddress.getByName(srcIp), (int) srcPort);
                InetSocketAddress dst = new InetSocketAddress(
                        InetAddress.getByName(dstIp), (int) dstPort);
                return cm.getConnectionOwnerUid(proto, src, dst);
            } catch (Exception ex) {
                // SecurityException / IllegalArgumentException / UnknownHost и прочее:
                // фича не работает, но туннель обязан жить.
                if (!uidFailLogged) {
                    uidFailLogged = true;
                    LogBuffer.add("[vpn] resolveUID недоступен: " + ex.getClass().getSimpleName()
                            + ": " + ex.getMessage() + " — правила по приложениям не применятся");
                } else {
                    uidFailCount++;
                }
                return -1;
            }
        }
    }
}
