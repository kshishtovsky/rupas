package ru.rupas.android;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.net.Uri;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import androidx.core.content.FileProvider;
import androidx.core.widget.NestedScrollView;

import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.button.MaterialButtonToggleGroup;
import com.google.android.material.card.MaterialCardView;
import com.google.android.material.chip.Chip;
import com.google.android.material.materialswitch.MaterialSwitch;
import com.google.android.material.textfield.TextInputEditText;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

import core.Core;

/**
 * Hallmark · app screen: one key, one reading, a paper journal.
 * States: idle · connecting · connected · error · no endpoint · busy.
 */
public class MainActivity extends AppCompatActivity {

    private static final int VPN_REQUEST_CODE = 42;
    private static final long TELEMETRY_POLL_INTERVAL_MS = 1000;

    private final Handler handler = new Handler(Looper.getMainLooper());

    // Navigation & Views
    private View viewTabHome;
    private View viewTabSettings;
    private View viewTabLogs;
    private BottomNavigationView bottomNav;

    // Home Tab Elements
    private MaterialCardView btnPower;
    private ImageView ivPowerIcon;
    private TextView tvPowerLabel;
    private View statusDot;
    private TextView statusText;
    private TextView tvDuration;
    private TextView tvSpeedDown;
    private TextView tvSpeedUp;
    private TextView tvTotalTraffic;
    private TextView tvActiveFlows;
    private TextView tvEndpoint;
    private TextView tvHealth;
    private TextView tvCarrier;
    private TextView tvAdblock;

    // Settings Tab Elements
    private TextInputEditText etServer;
    private TextInputEditText etPort;
    private TextInputEditText etSni;
    private TextInputEditText etUuid;
    private TextInputEditText etPublicKey;
    private TextInputEditText etShortId;
    private MaterialSwitch switchFallback;
    private MaterialSwitch switchDpiFake;
    /** Фильтр рекламы/трекеров (0.4.0): оба тумблера живут в карточке «Фильтр рекламы». */
    private MaterialSwitch switchBlockAds;
    private MaterialSwitch switchBlockTrackers;
    private MaterialButton btnImport;
    private MaterialButton btnSave;
    /** Share links from the latest import (dial chain); empty = legacy flat config. */
    private String pendingLinks = "";
    // Приоритеты: контейнер строк каналов (порядок = порядок в pendingLinks).
    private LinearLayout llCarriers;
    // T3: подзаголовок карточки «Маршрутизация» (сводка из последнего чтения правил).
    private TextView tvRoutingSummary;

    // Logs Tab Elements
    private MaterialButtonToggleGroup toggleLogLevel;
    private MaterialButton btnClearLogs;
    private MaterialButton btnShareLogs;
    private Chip chipAutoscroll;
    private NestedScrollView scrollLogs;
    private TextView tvLogsContent;
    private volatile boolean isDebugLogs = false;

    // Telemetry State
    private long prevRxBytes = 0;
    private long prevTxBytes = 0;
    private long prevPollTimeMs = 0;
    private long sessionStartTimeMs = 0;
    private Boolean lastRenderedVpnState;
    private volatile boolean resumed;
    private volatile boolean logsVisible;
    private final AtomicBoolean logRenderPending = new AtomicBoolean();
    // Сколько строк журнала уже отрисовано (для инкрементального append).
    private long renderedTotal;
    // true, пока пользователь у нижнего края: только тогда автопрокрутка
    // имеет право тянуть журнал вниз.
    private volatile boolean userAtBottom = true;
    private boolean showingEmptyHint;

    private final Runnable logRender = () -> {
        logRenderPending.set(false);
        if (resumed && logsVisible) renderLogs(false);
    };

    private boolean vpnActive() {
        return RupasVpnService.isRunning();
    }

    private final Runnable telemetryPoller = new Runnable() {
        @Override
        public void run() {
            if (!resumed || viewTabHome.getVisibility() != View.VISIBLE) return;
            pollTelemetry();
            handler.postDelayed(this, TELEMETRY_POLL_INTERVAL_MS);
        }
    };

    // При шквале логов рисуем журнал максимум раз в четверть секунды и
    // только когда вкладка открыта; не ставим runnable на каждый пакет.
    private final LogBuffer.Listener logListener = debugOnly -> {
        if ((!debugOnly || isDebugLogs) && resumed && logsVisible
                && logRenderPending.compareAndSet(false, true)) {
            handler.postDelayed(logRender, 250);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        bindViews();
        setupNavigation();
        setupHomeTab();
        setupSettingsTab();
        setupLogsTab();

        if (android.os.Build.VERSION.SDK_INT >= 33) {
            if (checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[]{android.Manifest.permission.POST_NOTIFICATIONS}, 101);
            }
        }

        if (!RupasVpnService.isRunning()) {
            RupasVpnService.showOfflineNotification(this);
        }
    }

    private void bindViews() {
        viewTabHome = findViewById(R.id.viewTabHome);
        viewTabSettings = findViewById(R.id.viewTabSettings);
        viewTabLogs = findViewById(R.id.viewTabLogs);
        bottomNav = findViewById(R.id.bottomNavigation);

        // Home
        btnPower = findViewById(R.id.btnPower);
        ivPowerIcon = findViewById(R.id.ivPowerIcon);
        tvPowerLabel = findViewById(R.id.tvPowerLabel);
        statusDot = findViewById(R.id.statusDot);
        statusText = findViewById(R.id.statusText);
        tvDuration = findViewById(R.id.tvDuration);
        tvSpeedDown = findViewById(R.id.tvSpeedDown);
        tvSpeedUp = findViewById(R.id.tvSpeedUp);
        tvTotalTraffic = findViewById(R.id.tvTotalTraffic);
        tvActiveFlows = findViewById(R.id.tvActiveFlows);
        tvEndpoint = findViewById(R.id.tvEndpoint);
        tvHealth = findViewById(R.id.tvHealth);
        tvCarrier = findViewById(R.id.tvCarrier);
        tvAdblock = findViewById(R.id.tvAdblock);

        // Settings
        etServer = findViewById(R.id.etServer);
        etPort = findViewById(R.id.etPort);
        etSni = findViewById(R.id.etSni);
        etUuid = findViewById(R.id.etUuid);
        etPublicKey = findViewById(R.id.etPublicKey);
        etShortId = findViewById(R.id.etShortId);
        switchFallback = findViewById(R.id.switchFallback);
        switchDpiFake = findViewById(R.id.switchDpiFake);
        switchBlockAds = findViewById(R.id.switchBlockAds);
        switchBlockTrackers = findViewById(R.id.switchBlockTrackers);
        btnImport = findViewById(R.id.btnImport);
        btnSave = findViewById(R.id.btnSave);
        llCarriers = findViewById(R.id.llCarriers);
        tvRoutingSummary = findViewById(R.id.tvRoutingSummary);

        // Logs
        toggleLogLevel = findViewById(R.id.toggleLogLevel);
        btnClearLogs = findViewById(R.id.btnClearLogs);
        btnShareLogs = findViewById(R.id.btnShareLogs);
        chipAutoscroll = findViewById(R.id.chipAutoscroll);
        scrollLogs = findViewById(R.id.scrollLogs);
        tvLogsContent = findViewById(R.id.tvLogsContent);
    }

    private void setupNavigation() {
        bottomNav.setOnItemSelectedListener(item -> {
            int id = item.getItemId();
            if (id == R.id.nav_home) {
                viewTabHome.setVisibility(View.VISIBLE);
                viewTabSettings.setVisibility(View.GONE);
                viewTabLogs.setVisibility(View.GONE);
                logsVisible = false;
                scheduleTelemetry();
                return true;
            } else if (id == R.id.nav_settings) {
                loadSettingsForm();
                viewTabHome.setVisibility(View.GONE);
                viewTabSettings.setVisibility(View.VISIBLE);
                viewTabLogs.setVisibility(View.GONE);
                logsVisible = false;
                handler.removeCallbacks(telemetryPoller);
                return true;
            } else if (id == R.id.nav_logs) {
                viewTabHome.setVisibility(View.GONE);
                viewTabSettings.setVisibility(View.GONE);
                viewTabLogs.setVisibility(View.VISIBLE);
                logsVisible = true;
                handler.removeCallbacks(telemetryPoller);
                renderLogs(true);
                return true;
            }
            return false;
        });
    }

    @Override
    protected void onRestoreInstanceState(Bundle savedInstanceState) {
        super.onRestoreInstanceState(savedInstanceState);
        // The bar restores its checked item after onCreate; the panels do not follow it.
        syncTabWithNav();
    }

    private void syncTabWithNav() {
        int id = bottomNav.getSelectedItemId();
        if (id == R.id.nav_settings) {
            viewTabHome.setVisibility(View.GONE);
            viewTabSettings.setVisibility(View.VISIBLE);
            viewTabLogs.setVisibility(View.GONE);
            logsVisible = false;
            handler.removeCallbacks(telemetryPoller);
        } else if (id == R.id.nav_logs) {
            viewTabHome.setVisibility(View.GONE);
            viewTabSettings.setVisibility(View.GONE);
            viewTabLogs.setVisibility(View.VISIBLE);
            logsVisible = true;
            isDebugLogs = toggleLogLevel.getCheckedButtonId() == R.id.btnLogDebug;
            handler.removeCallbacks(telemetryPoller);
            renderLogs(true);
        } else {
            viewTabHome.setVisibility(View.VISIBLE);
            viewTabSettings.setVisibility(View.GONE);
            viewTabLogs.setVisibility(View.GONE);
            logsVisible = false;
            scheduleTelemetry();
        }
    }

    private void setupHomeTab() {
        btnPower.setOnClickListener(v -> toggleVpn());
    }

    private void setupSettingsTab() {
        loadSettingsForm();
        btnImport.setOnClickListener(v -> showImportDialog());
        btnSave.setOnClickListener(v -> saveSettingsForm());
        // Вход в «Маршруты» — отдельная activity, bottom-nav не расширяем (§3).
        View cardRouting = findViewById(R.id.cardRouting);
        if (cardRouting != null) {
            cardRouting.setOnClickListener(v ->
                    startActivity(new Intent(MainActivity.this, RoutingActivity.class)));
        }
        // direct-хвост управляется переключателем — перерисовываем список.
        switchFallback.setOnCheckedChangeListener((b, checked) -> renderCarriers());
    }

    /** Сводка в карточке маршрутов: пишется экраном «Маршруты» после чтения/применения. */
    private void updateRoutingSummary() {
        if (tvRoutingSummary == null) {
            return;
        }
        String summary = RoutingActivity.cachedSummary(this);
        tvRoutingSummary.setText(summary == null
                ? getString(R.string.routing_summary_unknown)
                : summary);
    }

    private void setupLogsTab() {
        toggleLogLevel.addOnButtonCheckedListener((group, checkedId, isChecked) -> {
            if (isChecked) {
                isDebugLogs = (checkedId == R.id.btnLogDebug);
                renderLogs(true);
            }
        });
        btnClearLogs.setOnClickListener(v -> {
            LogBuffer.clear();
            renderedTotal = 0;
            renderLogs(true);
        });
        btnShareLogs.setOnClickListener(v -> shareLogs());
        // Автопрокрутка имеет смысл только когда пользователь у нижнего края:
        // иначе каждые 250 мс его будет уносить вниз вопреки ручной прокрутке.
        scrollLogs.setOnScrollChangeListener(
                (NestedScrollView.OnScrollChangeListener) (v, x, y, ox, oy) -> {
                    View child = v.getChildAt(0);
                    if (child == null) {
                        userAtBottom = true;
                        return;
                    }
                    int diff = child.getBottom() - (v.getHeight() + v.getScrollY());
                    userAtBottom = diff <= 100;
                });
        chipAutoscroll.setOnCheckedChangeListener((buttonView, isChecked) -> {
            if (isChecked) {
                userAtBottom = true;
                scrollLogs.post(() -> scrollLogs.fullScroll(View.FOCUS_DOWN));
            }
        });
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        checkAutoConnect(intent);
    }

    private void checkAutoConnect(Intent intent) {
        if (intent != null && intent.getBooleanExtra("connect", false)) {
            intent.removeExtra("connect");
            if (!vpnActive()) {
                toggleVpn();
            }
        } else if (intent != null && intent.getBooleanExtra("disconnect", false)) {
            intent.removeExtra("disconnect");
            if (vpnActive()) {
                toggleVpn();
            }
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        resumed = true;
        logsVisible = viewTabLogs.getVisibility() == View.VISIBLE;
        LogBuffer.setListener(logListener);
        refreshUI();
        updateEndpointInfo();
        updateRoutingSummary();
        if (logsVisible) {
            // Полный ре-рендер: за время паузы фильтр/буфер могли измениться.
            userAtBottom = true;
            renderLogs(true);
        }
        checkAutoConnect(getIntent());
        scheduleTelemetry();
    }

    @Override
    protected void onPause() {
        super.onPause();
        resumed = false;
        logsVisible = false;
        handler.removeCallbacks(telemetryPoller);
        handler.removeCallbacks(logRender);
        logRenderPending.set(false);
        LogBuffer.setListener(null);
    }

    private void scheduleTelemetry() {
        handler.removeCallbacks(telemetryPoller);
        if (resumed && viewTabHome.getVisibility() == View.VISIBLE) {
            handler.post(telemetryPoller);
        }
    }

    private void toggleVpn() {
        if (vpnActive()) {
            btnPower.setEnabled(false);
            RupasVpnService.stop(this);
            sessionStartTimeMs = 0;
            // stop() синхронен, когда сервис жив: сбрасываем кеш состояния,
            // чтобы интерфейс перерисовался сразу, без ожидания опроса.
            lastRenderedVpnState = null;
            refreshUI();
            btnPower.setEnabled(true);
            return;
        }
        // Один раз предупреждаем, если конфиг не введён: без эндпоинта VPN
        // всё равно поднимется, но трафик пойдёт напрямую (правила direct).
        try {
            if (!new SettingsStore(this).load().isConfigured()) {
                Toast.makeText(this, R.string.toast_no_config, Toast.LENGTH_LONG).show();
            }
        } catch (Throwable ignored) {
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
        RupasVpnService.start(this);
        sessionStartTimeMs = System.currentTimeMillis();
        refreshUI();
    }

    private void refreshUI() {
        // Экран «Маршруты» перезапускает ядро при применении правил: в это окно
        // статус не должен мигать «Не подключено»/ошибкой (ROUTING_UI §5.7).
        if (RoutingActivity.isApplying()) {
            return;
        }
        boolean active = vpnActive();
        if (lastRenderedVpnState != null && lastRenderedVpnState == active) return;
        lastRenderedVpnState = active;
        prevPollTimeMs = 0;

        int accent = ContextCompat.getColor(this, R.color.accent);
        int rule = ContextCompat.getColor(this, R.color.rule);
        int surfaceIdle = ContextCompat.getColor(this, R.color.paper_2);
        int surfaceActive = ContextCompat.getColor(this, R.color.accent_soft);
        int ink = ContextCompat.getColor(this, R.color.ink);
        int inkSoft = ContextCompat.getColor(this, R.color.ink_soft);
        int inkFaint = ContextCompat.getColor(this, R.color.ink_faint);
        int inkSecond = ContextCompat.getColor(this, R.color.ink_2);

        if (active) {
            btnPower.setStrokeColor(accent);
            btnPower.setCardBackgroundColor(ColorStateList.valueOf(surfaceActive));
            ivPowerIcon.setImageTintList(ColorStateList.valueOf(accent));
            tvPowerLabel.setText(R.string.btn_disconnect);
            tvPowerLabel.setTextColor(accent);

            statusDot.setBackgroundTintList(ColorStateList.valueOf(accent));
            statusText.setText(R.string.status_connected);
            statusText.setTextColor(accent);

            if (sessionStartTimeMs == 0) {
                sessionStartTimeMs = System.currentTimeMillis();
            }
            tvDuration.setVisibility(View.VISIBLE);
        } else {
            btnPower.setStrokeColor(rule);
            btnPower.setCardBackgroundColor(ColorStateList.valueOf(surfaceIdle));
            ivPowerIcon.setImageTintList(ColorStateList.valueOf(inkSoft));
            tvPowerLabel.setText(R.string.btn_connect);
            tvPowerLabel.setTextColor(ink);

            statusDot.setBackgroundTintList(ColorStateList.valueOf(inkFaint));
            statusText.setText(R.string.status_disconnected);
            statusText.setTextColor(inkSecond);

            tvDuration.setVisibility(View.INVISIBLE);
            tvSpeedDown.setText(SPEED_ZERO);
            tvSpeedUp.setText(SPEED_ZERO);
            tvCarrier.setText(R.string.home_active_none);
            tvCarrier.setTextColor(ContextCompat.getColor(this, R.color.ink_soft));
            tvAdblock.setText(R.string.home_adblock_off);
            tvAdblock.setTextColor(ContextCompat.getColor(this, R.color.ink_soft));
        }

        updateEndpointInfo();
    }

    private void pollTelemetry() {
        refreshUI();
        if (!vpnActive()) return;
        if (sessionStartTimeMs > 0 && vpnActive()) {
            long durationSec = (System.currentTimeMillis() - sessionStartTimeMs) / 1000;
            long hours = durationSec / 3600;
            long mins = (durationSec % 3600) / 60;
            long secs = durationSec % 60;
            tvDuration.setText(getString(R.string.home_session,
                    String.format(Locale.US, "%02d:%02d:%02d", hours, mins, secs)));
        }

        try {
            String statusStr = Core.status();
            if (statusStr == null || statusStr.isEmpty()) return;
            JSONObject st = new JSONObject(statusStr);

            boolean running = st.optBoolean("running", false);
            long rx = st.optLong("rx_bytes", 0);
            long tx = st.optLong("tx_bytes", 0);
            long tcpFlows = st.optLong("tcp_flows", 0);
            long udpSessions = st.optLong("udp_sessions", 0);
            long escalated = st.optLong("tunnel_escalated", 0);

            // Честный статус: «Защищено» — только если туннель реально
            // поднялся. Иначе TUNNEL-потоки уходят в direct, и Telegram
            // молча висит в соединении (см. 0.3.1: tunnel/tunnel_detail).
            String tunnel = st.optString("tunnel", "");
            if ("on".equals(tunnel)) {
                statusDot.setBackgroundTintList(ColorStateList.valueOf(ContextCompat.getColor(this, R.color.accent)));
                statusText.setText(R.string.status_connected);
                statusText.setTextColor(ContextCompat.getColor(this, R.color.accent));
            } else if (!tunnel.isEmpty()) {
                String detail = st.optString("tunnel_detail", "");
                statusDot.setBackgroundTintList(ColorStateList.valueOf(ContextCompat.getColor(this, R.color.warn)));
                statusText.setText(detail.isEmpty()
                        ? getString(R.string.status_tunnel_off)
                        : getString(R.string.status_tunnel_failed, detail));
                statusText.setTextColor(ContextCompat.getColor(this, R.color.warn));
            }

            long now = System.currentTimeMillis();
            if (prevPollTimeMs > 0 && now > prevPollTimeMs && running) {
                double dt = (now - prevPollTimeMs) / 1000.0;
                long dRx = Math.max(0, rx - prevRxBytes);
                long dTx = Math.max(0, tx - prevTxBytes);
                long speedDown = (long) (dRx / dt);
                long speedUp = (long) (dTx / dt);

                tvSpeedDown.setText(formatSpeed(speedDown));
                tvSpeedUp.setText(formatSpeed(speedUp));
            } else if (!running) {
                tvSpeedDown.setText(SPEED_ZERO);
                tvSpeedUp.setText(SPEED_ZERO);
            }

            prevRxBytes = rx;
            prevTxBytes = tx;
            prevPollTimeMs = now;

            tvTotalTraffic.setText(getString(R.string.home_traffic, formatBytes(rx), formatBytes(tx)));
            long flows = tcpFlows + udpSessions;
            tvActiveFlows.setText(flows + " " + plural(flows, "соединение", "соединения", "соединений"));

            if (escalated > 0) {
                tvHealth.setText(getString(R.string.home_health_faults, escalated));
                tvHealth.setTextColor(ContextCompat.getColor(this, R.color.warn));
            } else {
                tvHealth.setText(R.string.home_health_ok);
                tvHealth.setTextColor(ContextCompat.getColor(this, R.color.accent));
            }

            // Фильтр рекламы (0.4.0): ядро отдаёт adblock = on|off|failed.
            String adblock = st.optString("adblock", "");
            if ("on".equals(adblock)) {
                tvAdblock.setText(getString(R.string.home_adblock, st.optInt("adblock_blocked", 0)));
                tvAdblock.setTextColor(ContextCompat.getColor(this, R.color.accent));
            } else if ("failed".equals(adblock)) {
                tvAdblock.setText(getString(R.string.home_adblock_failed,
                        st.optString("adblock_detail", "")));
                tvAdblock.setTextColor(ContextCompat.getColor(this, R.color.warn));
            } else {
                tvAdblock.setText(R.string.home_adblock_off);
                tvAdblock.setTextColor(ContextCompat.getColor(this, R.color.ink_soft));
            }

            // Активный канал: кто доставил последний полезный трафик
            // (движок помечает active/cooldown/ready по реальным dial-ам).
            String activeName = null;
            JSONArray cars = st.optJSONArray("carriers");
            if (cars != null) {
                for (int i = 0; i < cars.length(); i++) {
                    JSONObject c = cars.optJSONObject(i);
                    if (c != null && "active".equals(c.optString("state"))) {
                        activeName = c.optInt("index", i) + " · " + c.optString("name", "");
                        break;
                    }
                }
            }
            if (activeName != null) {
                tvCarrier.setText(getString(R.string.home_active_carrier, activeName));
                tvCarrier.setTextColor(ContextCompat.getColor(this, R.color.accent));
            } else {
                tvCarrier.setText(R.string.home_active_none);
                tvCarrier.setTextColor(ContextCompat.getColor(this, R.color.ink_soft));
            }
        } catch (Throwable ignored) {}
    }

    private void updateEndpointInfo() {
        try {
            SettingsStore.Settings s = new SettingsStore(this).load();
            if (s != null && s.isConfigured()) {
                String kind = (s.publicKey != null && !s.publicKey.isEmpty()) ? "Reality" : "VLESS";
                tvEndpoint.setText(getString(R.string.home_gateway, s.server, s.port, kind));
            } else {
                tvEndpoint.setText(R.string.home_gateway_none);
            }
        } catch (Throwable t) {
            tvEndpoint.setText(R.string.home_gateway_none);
        }
    }

    /**
     * Рисует журнал. force=true — полный setText (открытие вкладки, смена
     * фильтра, очистка). Иначе — только append новых строк: полный
     * setText сбрасывает прокрутку наверх каждые 250 мс, из-за чего журнал
     * «уводило в самый верх» и не давали читать вручную.
     */
    private void renderLogs(boolean force) {
        long total = LogBuffer.total();
        if (force || total == 0 || total < renderedTotal) {
            renderedTotal = total;
            if (total == 0) {
                tvLogsContent.setText(R.string.logs_empty);
                showingEmptyHint = true;
                return;
            }
            tvLogsContent.setText(LogBuffer.dump(isDebugLogs));
            showingEmptyHint = false;
        } else {
            LogBuffer.Entry[] fresh = LogBuffer.entriesAfter(renderedTotal);
            renderedTotal = total;
            if (fresh.length == 0) {
                return;
            }
            StringBuilder sb = new StringBuilder(fresh.length * 96);
            for (LogBuffer.Entry e : fresh) {
                if (!isDebugLogs && e.isDebug) {
                    continue;
                }
                sb.append(LogBuffer.formatEntry(e));
            }
            if (sb.length() == 0) {
                return;
            }
            int keepY = scrollLogs.getScrollY();
            if (showingEmptyHint) {
                tvLogsContent.setText(sb.toString());
                showingEmptyHint = false;
            } else {
                tvLogsContent.append(sb.toString());
            }
            boolean autoscroll = chipAutoscroll.isChecked() && userAtBottom;
            if (autoscroll) {
                scrollLogs.post(() -> scrollLogs.fullScroll(View.FOCUS_DOWN));
            } else {
                // append() может дёрнуть relayout/selection и сдвинуть скролл —
                // возвращаем читаемую позицию явно.
                int y = keepY;
                scrollLogs.post(() -> {
                    if (scrollLogs.getScrollY() != y) {
                        scrollLogs.scrollTo(0, y);
                    }
                });
            }
            return;
        }
        if (chipAutoscroll.isChecked() && userAtBottom) {
            scrollLogs.post(() -> scrollLogs.fullScroll(View.FOCUS_DOWN));
        }
    }

    private void shareLogs() {
        String logs = LogBuffer.dump(true); // полный трейс, включая DEBUG
        if (logs.isEmpty()) {
            Toast.makeText(this, "Журнал пуст", Toast.LENGTH_SHORT).show();
            return;
        }
        File file;
        try {
            file = writeLogShareFile(logs);
        } catch (IOException e) {
            LogBuffer.add("[logs] не удалось записать файл журнала: " + e.getMessage());
            Toast.makeText(this, "Не удалось создать файл журнала", Toast.LENGTH_LONG).show();
            return;
        }
        Uri uri = FileProvider.getUriForFile(this, getPackageName() + ".fileprovider", file);
        Intent sendIntent = new Intent(Intent.ACTION_SEND);
        sendIntent.setType("text/plain");
        sendIntent.putExtra(Intent.EXTRA_STREAM, uri);
        sendIntent.putExtra(Intent.EXTRA_SUBJECT, file.getName());
        sendIntent.setClipData(ClipData.newRawUri("log", uri));
        sendIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        Intent shareIntent = Intent.createChooser(sendIntent, "Логи Rupas (" + file.getName() + ")");
        startActivity(shareIntent);
    }

    /** Пишет журнал в cache/logs/rupas-logs-<метка времени>.log, подчищая старые выгрузки. */
    private File writeLogShareFile(String content) throws IOException {
        File dir = new File(getCacheDir(), "logs");
        if (!dir.exists() && !dir.mkdirs()) {
            throw new IOException("mkdirs failed: " + dir);
        }
        // Держим не больше одной прошлой выгрузки, чтобы кэш не разрастался.
        File[] old = dir.listFiles((d, name) -> name.endsWith(".log"));
        if (old != null) {
            for (File f : old) {
                //nolint // best effort cleanup
                f.delete();
            }
        }
        String stamp = new SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(new Date());
        File out = new File(dir, "rupas-logs-" + stamp + ".log");
        try (FileWriter w = new FileWriter(out)) {
            w.write(content);
        }
        return out;
    }

    // --- Settings tab handlers ---

    private void loadSettingsForm() {
        try {
            SettingsStore.Settings s = new SettingsStore(this).load();
            etUuid.setText(s.uuid);
            etServer.setText(s.server);
            etPort.setText(s.port > 0 ? String.valueOf(s.port) : "");
            etSni.setText(s.sni);
            etPublicKey.setText(s.publicKey);
            etShortId.setText(s.shortId);
            switchFallback.setChecked(s.fallback);
            switchBlockAds.setChecked(s.blockAds);
            switchBlockTrackers.setChecked(s.blockTrackers);
            pendingLinks = s.links == null ? "" : s.links;
            renderCarriers();
        } catch (Exception e) {
            Toast.makeText(this, R.string.settings_load_failed, Toast.LENGTH_SHORT).show();
        }
    }

    private void saveSettingsForm() {
        SettingsStore.Settings s = new SettingsStore.Settings();
        s.blockAds = switchBlockAds.isChecked();
        s.blockTrackers = switchBlockTrackers.isChecked();
        s.uuid = text(etUuid);
        s.server = text(etServer);
        s.sni = text(etSni);
        s.publicKey = text(etPublicKey);
        s.shortId = text(etShortId);
        s.fallback = switchFallback.isChecked();
        s.links = pendingLinks;

        String portStr = text(etPort);
        if (portStr.isEmpty()) {
            s.port = 0;
        } else {
            try {
                int p = Integer.parseInt(portStr);
                if (p < 1 || p > 65535) throw new NumberFormatException();
                s.port = p;
            } catch (NumberFormatException e) {
                Toast.makeText(this, R.string.settings_bad_port, Toast.LENGTH_LONG).show();
                return;
            }
        }

        if (s.isConfigured() || (s.uuid.isEmpty() && s.server.isEmpty())) {
            try {
                new SettingsStore(this).save(s);
            } catch (Exception e) {
                Toast.makeText(this, R.string.settings_save_failed, Toast.LENGTH_LONG).show();
                return;
            }
            LogBuffer.add("[settings] сохранено: tunnel " + (s.isConfigured() ? "on (" + s.server + ":" + s.port + ")" : "off"));
            if (RupasVpnService.restartIfRunning(this)) {
                LogBuffer.add("[settings] VPN поднят — перезапускаю ядро с новыми настройками");
            }
            Toast.makeText(this, R.string.settings_saved, Toast.LENGTH_SHORT).show();
            updateEndpointInfo();
        } else {
            Toast.makeText(this, R.string.settings_incomplete, Toast.LENGTH_LONG).show();
        }
    }

    private void showImportDialog() {
        final EditText input = new EditText(this);
        input.setHint(R.string.import_hint);

        // Auto-fill from clipboard if it contains vless://
        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard != null && clipboard.hasPrimaryClip()) {
            ClipData clip = clipboard.getPrimaryClip();
            if (clip != null && clip.getItemCount() > 0) {
                CharSequence text = clip.getItemAt(0).getText();
                if (text != null && text.toString().trim().matches("(?s)(vless|hysteria2|hy2|trojan)://.*")) {
                    input.setText(text.toString().trim());
                }
            }
        }

        new AlertDialog.Builder(this)
                .setTitle(R.string.import_title)
                .setView(input)
                .setPositiveButton(R.string.import_ok, (d, w) -> applyImport(input.getText().toString()))
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private void applyImport(String raw) {
        java.util.List<String> links;
        ParseLink.Flat r;
        try {
            links = ParseLink.splitInput(raw);
            r = ParseLink.flattenLegacy(links.get(0));
        } catch (IllegalArgumentException e) {
            Toast.makeText(this, getString(R.string.import_failed, e.getMessage()), Toast.LENGTH_LONG).show();
            return;
        }
        pendingLinks = String.join("\n", links);
        etUuid.setText(r.uuid);
        etServer.setText(r.server);
        etPort.setText(String.valueOf(r.port));
        etSni.setText(r.sni);
        etPublicKey.setText(r.publicKey);
        etShortId.setText(r.shortId);
        switchFallback.setChecked(true);
        renderCarriers();

        if (r.warning != null) {
            Toast.makeText(this, getString(R.string.import_warning, r.warning), Toast.LENGTH_LONG).show();
        } else {
            Toast.makeText(this, R.string.import_done, Toast.LENGTH_SHORT).show();
        }
    }

    private static String text(EditText et) {
        return et.getText() == null ? "" : et.getText().toString().trim();
    }

    // --- Carrier priorities UI (settings tab) ---

    /**
     * Рисует список каналов из pendingLinks в порядке приоритета (порядок =
     * порядок ссылок, движок перебирает их по очереди) и direct-хвост,
     * управляемый switchFallback. Кнопки ↑/↓ переставляют ссылки; порядок
     * попадает в настройки обычным «Сохранить и применить».
     */
    private void renderCarriers() {
        if (llCarriers == null) return;
        llCarriers.removeAllViews();
        java.util.List<String> links = new java.util.ArrayList<>();
        if (pendingLinks != null && !pendingLinks.trim().isEmpty()) {
            for (String l : pendingLinks.split("\n")) {
                String t = l.trim();
                if (!t.isEmpty()) links.add(t);
            }
        }
        if (links.isEmpty()) {
            TextView empty = new TextView(this);
            empty.setText(R.string.settings_priorities_empty);
            empty.setTextColor(ContextCompat.getColor(this, R.color.ink_soft));
            empty.setTextSize(13);
            llCarriers.addView(empty);
            return;
        }
        for (int i = 0; i < links.size(); i++) {
            llCarriers.addView(carrierRow(links, i));
        }
        if (switchFallback.isChecked()) {
            TextView direct = new TextView(this);
            direct.setText(getString(R.string.settings_priorities_direct));
            direct.setTextColor(ContextCompat.getColor(this, R.color.ink_soft));
            direct.setTextSize(13);
            direct.setPadding(0, dp(8), 0, 0);
            llCarriers.addView(direct);
        }
        pendingLinks = String.join("\n", links);
    }

    private View carrierRow(java.util.List<String> links, int i) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(android.view.Gravity.CENTER_VERTICAL);
        row.setPadding(0, dp(6), 0, dp(6));

        TextView label = new TextView(this);
        label.setText((i + 1) + ". " + ParseLink.describe(links.get(i)));
        label.setTextColor(ContextCompat.getColor(this, R.color.ink));
        label.setTextSize(13);
        label.setSingleLine(true);
        label.setEllipsize(android.text.TextUtils.TruncateAt.END);
        label.setLayoutParams(new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        row.addView(label);

        int size = dp(44);
        LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams(size, size);
        bp.setMargins(dp(8), 0, 0, 0);

        TextView up = carrierButton("▲", R.string.btn_move_up);
        up.setLayoutParams(bp);
        up.setEnabled(i > 0);
        final int pos = i;
        up.setOnClickListener(v -> {
            swap(links, pos, pos - 1);
            // Фиксируем перестановку ДО перерисовки: renderCarriers читает
            // pendingLinks, иначе swap молча откатывается (bug 2026-10-27).
            pendingLinks = String.join("\n", links);
            renderCarriers();
        });
        row.addView(up);

        TextView down = carrierButton("▼", R.string.btn_move_down);
        down.setLayoutParams(bp);
        down.setEnabled(i + 1 < links.size());
        down.setOnClickListener(v -> {
            swap(links, pos, pos + 1);
            pendingLinks = String.join("\n", links);
            renderCarriers();
        });
        row.addView(down);
        return row;
    }

    /**
     * Круглая кнопка перестановки. Специально не MaterialButton: у
     * программно созданной MaterialButton с фиксированным размером глиф
     * не отрисовывается (кватирк темы, live finding 2026-10-27) — TextView
     * с овальным GradientDrawable рисует текст гарантированно.
     */
    private TextView carrierButton(String arrow, int cdRes) {
        TextView b = new TextView(this);
        b.setText(arrow);
        b.setContentDescription(getString(cdRes));
        b.setTextSize(14);
        b.setGravity(android.view.Gravity.CENTER);
        b.setTypeface(android.graphics.Typeface.create("sans-serif-medium", android.graphics.Typeface.NORMAL));
        android.graphics.drawable.GradientDrawable bg = new android.graphics.drawable.GradientDrawable();
        bg.setShape(android.graphics.drawable.GradientDrawable.OVAL);
        bg.setColor(ContextCompat.getColor(this, R.color.accent_soft));
        b.setBackground(bg);
        b.setTextColor(ContextCompat.getColor(this, R.color.accent));
        return b;
    }

    private static void swap(java.util.List<String> l, int a, int b) {
        if (a < 0 || b < 0 || a >= l.size() || b >= l.size()) return;
        String t = l.set(a, l.get(b));
        l.set(b, t);
    }

    private int dp(int v) {
        return Math.round(getResources().getDisplayMetrics().density * v);
    }

    private static String plural(long n, String one, String few, String many) {
        long mod10 = n % 10;
        long mod100 = n % 100;
        if (mod10 == 1 && mod100 != 11) return one;
        if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) return few;
        return many;
    }

    private static final Locale RU = Locale.forLanguageTag("ru");
    private static final String SPEED_ZERO = "0,0 КБ/с";
    private static final String[] BYTE_UNITS = {"Б", "КБ", "МБ", "ГБ", "ТБ", "ПБ", "ЭБ"};

    private static String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " Б";
        int exp = (int) (Math.log(bytes) / Math.log(1024));
        if (exp > BYTE_UNITS.length - 1) exp = BYTE_UNITS.length - 1;
        return String.format(RU, "%.1f %s", bytes / Math.pow(1024, exp), BYTE_UNITS[exp]);
    }

    private static String formatSpeed(long bytesPerSec) {
        if (bytesPerSec <= 0) return SPEED_ZERO;
        if (bytesPerSec < 1024 * 1024) {
            return String.format(RU, "%.1f КБ/с", bytesPerSec / 1024.0);
        }
        return String.format(RU, "%.1f МБ/с", bytesPerSec / (1024.0 * 1024.0));
    }
}
