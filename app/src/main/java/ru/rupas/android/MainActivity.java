package ru.rupas.android;

import android.content.ComponentName;
import android.content.Intent;
import android.content.ServiceConnection;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import core.Core;

/**
 * W2 GUI: большая кнопка ON/OFF, строка статуса (опрос core.Core.status() раз в 2 с),
 * лог-экран из кольцевого буфера LogBuffer.
 */
public class MainActivity extends AppCompatActivity {

    private static final int VPN_REQUEST_CODE = 42;
    private static final long STATUS_POLL_INTERVAL_MS = 2000;

    private final Handler handler = new Handler(Looper.getMainLooper());

    private Button toggleButton;
    private Button settingsButton;
    private TextView statusView;
    private TextView logView;

    // W3-фикс: после пересоздания Activity статичный флаг мог не отразить живой
    // сервис (например, после убийства процесса и START_STICKY-рестарта). Держим
    // ещё и привязку: привязанный сервис = точно жив, но не обязательно foreground.
    private volatile boolean serviceBound;
    private final ServiceConnection serviceConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            serviceBound = true;
            refreshStatus();
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            serviceBound = false;
            refreshStatus();
        }
    };

    /** Реальное состояние: статичный флаг сервиса ИЛИ живая привязка. */
    private boolean vpnActive() {
        return RupasVpnService.isRunning() || serviceBound;
    }

    private final Runnable statusPoller = new Runnable() {
        @Override
        public void run() {
            refreshStatus();
            handler.postDelayed(this, STATUS_POLL_INTERVAL_MS);
        }
    };

    private final LogBuffer.Listener logListener = new LogBuffer.Listener() {
        @Override
        public void onLogChanged() {
            handler.post(new Runnable() {
                @Override
                public void run() {
                    refreshLog();
                }
            });
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        toggleButton = findViewById(R.id.toggleButton);
        settingsButton = findViewById(R.id.settingsButton);
        statusView = findViewById(R.id.statusView);
        logView = findViewById(R.id.logView);

        toggleButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                toggleVpn();
            }
        });
        settingsButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivity(new Intent(MainActivity.this, SettingsActivity.class));
            }
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        LogBuffer.setListener(logListener);
        // Привязка живого сервиса: даже если статичный флаг сброшен (процесс
        // пересоздан), привязка покажет реальное состояние и мгновенно обновит UI.
        bindService(new Intent(this, RupasVpnService.class), serviceConnection, BIND_AUTO_CREATE);
        refreshStatus();
        refreshLog();
        handler.postDelayed(statusPoller, STATUS_POLL_INTERVAL_MS);
    }

    @Override
    protected void onPause() {
        super.onPause();
        handler.removeCallbacks(statusPoller);
        LogBuffer.setListener(null);
        try {
            unbindService(serviceConnection);
        } catch (IllegalArgumentException ignored) {
            // не был привязан
        }
        serviceBound = false;
    }

    private void toggleVpn() {
        if (vpnActive()) {
            toggleButton.setEnabled(false);
            stopService(new Intent(this, RupasVpnService.class));
            toggleButton.setEnabled(true);
            refreshStatus();
            return;
        }
        Intent prepare = VpnService.prepare(this);
        if (prepare != null) {
            startActivityForResult(prepare, VPN_REQUEST_CODE);
        } else {
            startVpnService();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_REQUEST_CODE) {
            if (resultCode == RESULT_OK) {
                startVpnService();
            } else {
                Toast.makeText(this, R.string.vpn_permission_denied, Toast.LENGTH_SHORT).show();
            }
        }
    }

    private void startVpnService() {
        startService(new Intent(this, RupasVpnService.class));
        refreshStatus();
    }

    private void refreshStatus() {
        String s;
        try {
            s = Core.status();
        } catch (Throwable t) {
            s = "core: unavailable";
        }
        statusView.setText(getString(R.string.status_format,
                vpnActive() ? "ON" : "OFF", s));
        toggleButton.setText(vpnActive()
                ? R.string.turn_off : R.string.turn_on);
    }

    private void refreshLog() {
        logView.setText(LogBuffer.dump());
    }
}
