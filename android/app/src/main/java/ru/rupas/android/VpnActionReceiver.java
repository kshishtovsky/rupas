package ru.rupas.android;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.util.Log;

/**
 * Принимает быстрые действия из шторки уведомлений (ВКЛЮЧИТЬ / ОТКЛЮЧИТЬ)
 * и сетевые события: на событии сети — будит probe через exact alarm.
 */
public class VpnActionReceiver extends BroadcastReceiver {

    public static final String ACTION_DISCONNECT = "ru.rupas.android.ACTION_DISCONNECT";
    public static final String ACTION_CONNECT = "ru.rupas.android.ACTION_CONNECT";
    /** Сетевое событие — будим probe (Doze-resume, смена Wi-Fi). */
    public static final String ACTION_NETWORK_CHANGE = "ru.rupas.android.NETWORK_CHANGE";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null) return;
        String action = intent.getAction();
        if (ACTION_DISCONNECT.equals(action) || RupasVpnService.ACTION_DISCONNECT.equals(action)) {
            LogBuffer.add("[vpn] отключение по кнопке из шторки");
            RupasVpnService.stop(context);
            // Сетевое событие: будим probe для re-classify (DESIGN §13: wakeup
            // политика probe только по событиям сети).
            if (ACTION_NETWORK_CHANGE.equals(action) && RupasVpnService.isRunning()) {
                scheduleProbeAlarm(context);
                return;
            }
        } else if (ACTION_CONNECT.equals(action)) {
        LogBuffer.add("[vpn] включение по кнопке из шторки");
            Intent prepare = VpnService.prepare(context);
            if (prepare != null) {
                Intent open = new Intent(context, MainActivity.class)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP)
                        .putExtra("connect", true);
                context.startActivity(open);
            } else {
                RupasVpnService.start(context);
            }
        }
    }

    /** Alarm: exact, с fallback на inexact (API 31+ SCHEDULE_EXACT_ALARM). */
    private static void scheduleProbeAlarm(Context ctx) {
        if (ctx == null) return;
        Intent i = new Intent(ctx, VpnActionReceiver.class)
                .setAction(ACTION_NETWORK_CHANGE);
        PendingIntent pi = PendingIntent.getBroadcast(
                ctx, 0, i,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        AlarmManager am = (AlarmManager) ctx.getSystemService(Context.ALARM_SERVICE);
        if (am == null) return;
        long when = System.currentTimeMillis() + 2000; // +2с, probe не нужен мгновенно
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            if (am.canScheduleExactAlarms()) {
                am.setExactAndAllowWhileIdle(AlarmManager.RTC, when, pi);
            } else {
                am.set(AlarmManager.RTC, when, pi);
            }
        } else {
            am.set(AlarmManager.RTC, when, pi);
        }
    }
}
