package ru.rupas.android;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;

/**
 * Принимает быстрые действия из шторки уведомлений (ВКЛЮЧИТЬ / ОТКЛЮЧИТЬ).
 */
public class VpnActionReceiver extends BroadcastReceiver {

    public static final String ACTION_DISCONNECT = "ru.rupas.android.ACTION_DISCONNECT";
    public static final String ACTION_CONNECT = "ru.rupas.android.ACTION_CONNECT";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null) return;
        String action = intent.getAction();
        if (ACTION_DISCONNECT.equals(action) || RupasVpnService.ACTION_DISCONNECT.equals(action)) {
            LogBuffer.add("[vpn] отключение по кнопке из шторки");
            RupasVpnService.stop(context);
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
}
