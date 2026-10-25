package ru.rupas.android;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import androidx.core.app.NotificationCompat;

import java.util.Collections;
import java.util.Set;

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
    private static final String VPN_DNS = "26.26.26.1";
    private static final int VPN_MTU = 1500;

    // TODO(W5): зашитый список исключений заменить на GUI-экран (выбор приложений).
    // Сейчас, кроме собственного пакета, ничего не исключаем.
    private static final Set<String> EXTRA_DISALLOWED_PACKAGES = Collections.emptySet();

    private static volatile boolean running = false;

    private ParcelFileDescriptor tun;
    private PlatformImpl platform;

    /** Для MainActivity: поднят ли туннель. */
    public static boolean isRunning() {
        return running;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        startForegroundWithStatus();
        if (!establishAndStartCore()) {
            Log.e(TAG, "failed to establish TUN or start core");
            stopForegroundAndSelf();
            return START_NOT_STICKY;
        }
        running = true;
        updateNotificationText(statusLine());
        return START_STICKY;
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
        super.onDestroy();
    }

    private boolean establishAndStartCore() {
        Builder b = new Builder()
                .addAddress(VPN_ADDRESS, VPN_ADDRESS_PREFIX)
                .addRoute(VPN_ROUTE, VPN_ROUTE_PREFIX)
                .addDnsServer(VPN_DNS)
                .setMtu(VPN_MTU)
                .setSession("rupas");
        // Самопакет: иначе наш же трафик зациклится через TUN.
        // TODO(W5): список исключений приложений — на GUI-экране.
        try {
            b.addDisallowedApplication(getPackageName());
            for (String pkg : EXTRA_DISALLOWED_PACKAGES) {
                b.addDisallowedApplication(pkg);
            }
        } catch (Exception e) {
            Log.w(TAG, "disallowed package rejected: " + e);
        }
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
        try {
            // gobind: Go error → Java exception, метод возвращает void
            Core.start(tun.getFd(), platform);
        } catch (Exception e) {
            Log.e(TAG, "core.Core.start failed", e);
            LogBuffer.add("[vpn] core start failed: " + e.getMessage());
            return false;
        }
        LogBuffer.add("[vpn] TUN fd=" + tun.getFd() + ", core started");
        return true;
    }

    private void stopCore() {
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
        platform = null;
        LogBuffer.add("[vpn] stopped");
    }

    private void stopForegroundAndSelf() {
        stopCore();
        running = false;
        if (Build.VERSION.SDK_INT >= 33) {
            stopForeground(STOP_FOREGROUND_REMOVE);
        } else {
            stopForeground(true);
        }
        stopSelf();
    }

    private void createNotificationChannel() {
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm == null) {
            return;
        }
        NotificationChannel ch = new NotificationChannel(
                CHANNEL_ID, "Rupas VPN", NotificationManager.IMPORTANCE_LOW);
        ch.setDescription("Статус VPN-туннеля Rupas");
        nm.createNotificationChannel(ch);
    }

    private void startForegroundWithStatus() {
        Notification n = buildNotification(statusLine());
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, n,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NOTIFICATION_ID, n);
        }
    }

    private void updateNotificationText(String text) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm != null) {
            nm.notify(NOTIFICATION_ID, buildNotification(text));
        }
    }

    private Notification buildNotification(String text) {
        Intent open = new Intent(this, MainActivity.class);
        PendingIntent pi = PendingIntent.getActivity(
                this, 0, open,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_stat_vpn)
                .setContentTitle("Rupas VPN")
                .setContentText(text)
                .setOngoing(true)
                .setContentIntent(pi)
                .build();
    }

    private String statusLine() {
        try {
            return Core.status();
        } catch (Throwable t) {
            return "core: unavailable";
        }
    }

    /** Реализация core.Platform: protect() → VpnService.protect(), log() → кольцевой буфер.
     *  Сигнатура long: gobind отображает Go int → Java long (реальный AAR). */
    private class PlatformImpl implements Platform {
        @Override
        public boolean protect(long fd) {
            return RupasVpnService.this.protect((int) fd);
        }

        @Override
        public void log(String line) {
            Log.d(TAG, line);
            LogBuffer.add(line);
        }
    }
}
