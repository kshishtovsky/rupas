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
import android.view.LayoutInflater;
import android.view.View;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatDelegate;
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
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
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
    /**
     * Профили VPN (0.5.0) в порядке приоритета: источник истины для links.
     * Копия из настроек, живёт до «Сохранить и применить», как и остальная форма.
     */
    private final List<SettingsStore.Profile> pendingProfiles = new ArrayList<>();
    /** Контейнер карточек профилей (порядок = порядок перебора в ядре). */
    private LinearLayout llProfiles;
    private TextView tvNoProfiles;
    private TextView tvProfilesEmpty;
    private MaterialButton btnToggleServerFields;
    private LinearLayout llServerFields;
    /** id профиля, который сейчас проверяется (null — проверок нет). */
    private String runningTestId;
    /** Результаты тестов по id профиля: только в памяти, в prefs не пишутся. */
    private final Map<String, TestResult> testResults = new HashMap<>();
    /** Один поток: ядро тестирует один профиль за раз. */
    private final ExecutorService testExecutor = Executors.newSingleThreadExecutor();
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
        // Тема — ДО super.onCreate: иначе активити построит окно в прошлом режиме
        // и пересоздастся вторым проходом.
        androidx.appcompat.app.AppCompatDelegate.setDefaultNightMode(
                SettingsStore.loadThemeMode(this));
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        bindViews();
        setupThemeButton();
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

    private ImageButton btnTheme;

    /**
     * Тема: тап листает «светлая → тёмная → как в системе». Иконка показывает
     * текущий режим, тост — что включилось (иначе третье состояние невидимо).
     */
    private void setupThemeButton() {
        btnTheme = findViewById(R.id.btnTheme);
        if (btnTheme == null) {
            return; // разметка без кнопки (старая тема) — молча живём как раньше
        }
        btnTheme.setOnClickListener(v -> {
            int cur = SettingsStore.loadThemeMode(this);
            int next = cur == AppCompatDelegate.MODE_NIGHT_NO
                    ? AppCompatDelegate.MODE_NIGHT_YES
                    : cur == AppCompatDelegate.MODE_NIGHT_YES
                        ? AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM
                        : AppCompatDelegate.MODE_NIGHT_NO;
            SettingsStore.saveThemeMode(this, next);
            // Иконку ставим сразу: если режим сменился на «как в системе» при
            // совпадающем с ним виде, uiMode не меняется и пересоздания нет.
            renderThemeButton(next);
            Toast.makeText(this, themeLabel(next), Toast.LENGTH_SHORT).show();
            AppCompatDelegate.setDefaultNightMode(next);
        });
        renderThemeButton(SettingsStore.loadThemeMode(this));
    }

    private void renderThemeButton(int mode) {
        btnTheme.setImageResource(mode == AppCompatDelegate.MODE_NIGHT_YES
                ? R.drawable.ic_theme_dark
                : mode == AppCompatDelegate.MODE_NIGHT_NO
                    ? R.drawable.ic_theme_light
                    : R.drawable.ic_theme_system);
    }

    private String themeLabel(int mode) {
        return getString(mode == AppCompatDelegate.MODE_NIGHT_YES
                ? R.string.theme_now_dark
                : mode == AppCompatDelegate.MODE_NIGHT_NO
                    ? R.string.theme_now_light
                    : R.string.theme_now_system);
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
        llProfiles = findViewById(R.id.llProfiles);
        tvNoProfiles = findViewById(R.id.tvNoProfiles);
        tvProfilesEmpty = findViewById(R.id.tvProfilesEmpty);
        btnToggleServerFields = findViewById(R.id.btnToggleServerFields);
        llServerFields = findViewById(R.id.llServerFields);
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
        // direct-хвост управляется переключателем — в карточках профилей его нет,
        // значение уходит в настройки обычным «Сохранить и применить».
        btnToggleServerFields.setOnClickListener(v -> toggleServerFields());
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

    @Override
    protected void onDestroy() {
        super.onDestroy();
        // Один поток проверки профилей: после выхода активити он не нужен.
        testExecutor.shutdownNow();
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
            if (s != null && !s.isConfigured() && s.firstEnabled() == null
                    && !s.profiles.isEmpty()) {
                // Ноль включённых профилей: внятное предупреждение вместо «напрямую».
                tvEndpoint.setText(R.string.profiles_none_enabled);
                tvEndpoint.setTextColor(ContextCompat.getColor(this, R.color.warn));
            } else if (s != null && s.isConfigured()) {
                String kind = (s.publicKey != null && !s.publicKey.isEmpty()) ? "Reality" : "VLESS";
                tvEndpoint.setText(getString(R.string.home_gateway, s.server, s.port, kind));
                tvEndpoint.setTextColor(ContextCompat.getColor(this, R.color.ink_soft));
            } else {
                tvEndpoint.setText(R.string.home_gateway_none);
                tvEndpoint.setTextColor(ContextCompat.getColor(this, R.color.ink_soft));
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
            pendingProfiles.clear();
            pendingProfiles.addAll(s.profiles);
            renderProfiles();
            updateEndpointInfo();
        } catch (Exception e) {
            Toast.makeText(this, R.string.settings_load_failed, Toast.LENGTH_SHORT).show();
        }
    }

    private void saveSettingsForm() {
        SettingsStore store;
        SettingsStore.Settings s;
        try {
            store = new SettingsStore(this);
            // Снимок из prefs: чужие поля (профили, app_rules) не теряются.
            s = store.load();
        } catch (Exception e) {
            Toast.makeText(this, R.string.settings_load_failed, Toast.LENGTH_SHORT).show();
            return;
        }
        s.blockAds = switchBlockAds.isChecked();
        s.blockTrackers = switchBlockTrackers.isChecked();
        s.uuid = text(etUuid);
        s.server = text(etServer);
        s.sni = text(etSni);
        s.publicKey = text(etPublicKey);
        s.shortId = text(etShortId);
        s.fallback = switchFallback.isChecked();

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
        applyProfiles(s); // профили перекрывают плоские поля, когда они есть

        if (s.isConfigured() || (s.uuid.isEmpty() && s.server.isEmpty())) {
            try {
                store.save(s);
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

    /**
     * Импорт добавляет профили в конец списка: существующие не затираются,
     * точные дубли ссылок пропускаются.
     */
    private void applyImport(String raw) {
        java.util.List<String> links;
        try {
            links = ParseLink.splitInput(raw);
        } catch (IllegalArgumentException e) {
            Toast.makeText(this, getString(R.string.import_failed, e.getMessage()), Toast.LENGTH_LONG).show();
            return;
        }
        int added = 0;
        for (String link : links) {
            if (findByLink(link) != null) continue;
            pendingProfiles.add(new SettingsStore.Profile(
                    UUID.randomUUID().toString(), link, ParseLink.label(link), true));
            added++;
        }
        renderProfiles();
        if (added > 0) {
            persistProfiles();
            Toast.makeText(this, getString(R.string.profiles_added, added), Toast.LENGTH_SHORT).show();
        } else {
            Toast.makeText(this, R.string.profiles_duplicates, Toast.LENGTH_SHORT).show();
        }
    }

    private SettingsStore.Profile findByLink(String link) {
        String needle = link == null ? "" : link.trim();
        for (SettingsStore.Profile p : pendingProfiles) {
            if (p.link != null && p.link.trim().equals(needle)) return p;
        }
        return null;
    }

    private static String text(EditText et) {
        return et.getText() == null ? "" : et.getText().toString().trim();
    }

    // --- Профили VPN (0.5.0): карточки, порядок, тест ---

    /**
     * Карточки профилей в порядке приоритета (порядок = порядок перебора в ядре).
     * tvNoProfiles — заметное предупреждение: ноль включённых = VPN не подключится.
     */
    private void renderProfiles() {
        if (llProfiles == null) return;
        llProfiles.removeAllViews();
        LayoutInflater inflater = LayoutInflater.from(this);
        int enabled = 0;
        for (SettingsStore.Profile p : pendingProfiles) {
            if (p.enabled) enabled++;
        }
        tvProfilesEmpty.setVisibility(pendingProfiles.isEmpty() ? View.VISIBLE : View.GONE);
        tvNoProfiles.setVisibility(!pendingProfiles.isEmpty() && enabled == 0
                ? View.VISIBLE : View.GONE);
        for (int i = 0; i < pendingProfiles.size(); i++) {
            llProfiles.addView(profileCard(inflater, pendingProfiles.get(i), i));
        }
    }

    private View profileCard(LayoutInflater inflater, final SettingsStore.Profile p, int index) {
        View card = inflater.inflate(R.layout.item_profile, llProfiles, false);

        TextView tvLabel = card.findViewById(R.id.tvProfileLabel);
        String label = p.label == null || p.label.trim().isEmpty()
                ? ParseLink.label(p.link)
                : p.label.trim();
        tvLabel.setText(label);
        tvLabel.setTextColor(ContextCompat.getColor(this, p.enabled ? R.color.ink : R.color.ink_soft));
        ((TextView) card.findViewById(R.id.tvProfileMeta)).setText(ParseLink.subtitle(p.link));

        MaterialSwitch sw = card.findViewById(R.id.switchProfile);
        sw.setContentDescription(label);
        sw.setChecked(p.enabled);
        sw.setOnCheckedChangeListener((b, checked) -> {
            p.enabled = checked;
            // Перерисовка — после анимации переключателя: карточка живёт в llProfiles.
            llProfiles.post(this::renderProfiles);
            persistProfiles();
        });

        // Строка результата: «Проверяю…», результат из памяти или «недоступна».
        TextView tvTest = card.findViewById(R.id.tvProfileTest);
        if (p.id != null && p.id.equals(runningTestId)) {
            tvTest.setVisibility(View.VISIBLE);
            tvTest.setText(R.string.profile_test_running);
            tvTest.setTextColor(ContextCompat.getColor(this, R.color.ink_soft));
        } else if (testResults.get(p.id) != null) {
            TestResult r = testResults.get(p.id);
            int c = ContextCompat.getColor(this, r.ok ? R.color.accent : R.color.warn);
            tvTest.setVisibility(View.VISIBLE);
            tvTest.setText(r.text);
            tvTest.setTextColor(c);
            card.findViewById(R.id.profileStateDot).setBackgroundTintList(ColorStateList.valueOf(c));
        } else if (!testAvailable()) {
            // Старый AAR без TestProfile: кнопка disabled, причина написана.
            tvTest.setVisibility(View.VISIBLE);
            tvTest.setText(R.string.profile_test_unavailable);
            tvTest.setTextColor(ContextCompat.getColor(this, R.color.ink_faint));
        }

        TextView btnTest = card.findViewById(R.id.btnProfileTest);
        boolean canTest = testAvailable() && runningTestId == null;
        btnTest.setEnabled(canTest);
        btnTest.setAlpha(canTest ? 1f : 0.4f);
        btnTest.setOnClickListener(v -> startProfileTest(p));

        card.findViewById(R.id.btnProfileEdit)
                .setOnClickListener(v -> showEditProfileDialog(p));
        card.findViewById(R.id.btnProfileDelete)
                .setOnClickListener(v -> confirmDeleteProfile(p));

        TextView up = card.findViewById(R.id.btnProfileUp);
        up.setEnabled(index > 0);
        up.setAlpha(index > 0 ? 1f : 0.35f);
        up.setOnClickListener(v -> moveProfile(p, -1));

        TextView down = card.findViewById(R.id.btnProfileDown);
        boolean canDown = index + 1 < pendingProfiles.size();
        down.setEnabled(canDown);
        down.setAlpha(canDown ? 1f : 0.35f);
        down.setOnClickListener(v -> moveProfile(p, 1));
        return card;
    }

    /** Перестановка: порядок профилей = приоритет перебора (первая включённая — primary). */
    private void moveProfile(SettingsStore.Profile p, int delta) {
        int from = pendingProfiles.indexOf(p);
        int to = from + delta;
        if (from < 0 || to < 0 || to >= pendingProfiles.size()) return;
        pendingProfiles.remove(from);
        pendingProfiles.add(to, p);
        renderProfiles();
        persistProfiles();
    }

    private void showEditProfileDialog(final SettingsStore.Profile p) {
        final EditText input = new EditText(this);
        input.setHint(R.string.import_hint);
        input.setText(p.link);
        input.setSelection(input.getText().length());
        new AlertDialog.Builder(this)
                .setTitle(R.string.profile_edit_title)
                .setView(input)
                .setPositiveButton(R.string.editor_save, (d, w) -> {
                    String link;
                    try {
                        link = ParseLink.splitInput(input.getText().toString()).get(0);
                    } catch (IllegalArgumentException e) {
                        Toast.makeText(this, getString(R.string.import_failed, e.getMessage()),
                                Toast.LENGTH_LONG).show();
                        return;
                    }
                    p.link = link;
                    p.label = ParseLink.label(link);
                    testResults.remove(p.id); // старый результат — про другую ссылку
                    renderProfiles();
                    persistProfiles();
                })
                .setNegativeButton(R.string.btn_cancel, null)
                .show();
    }

    private void confirmDeleteProfile(final SettingsStore.Profile p) {
        String label = p.label == null || p.label.trim().isEmpty()
                ? ParseLink.label(p.link)
                : p.label.trim();
        new AlertDialog.Builder(this)
                .setTitle(R.string.profile_delete_title)
                .setMessage(getString(R.string.profile_delete_message, label))
                .setPositiveButton(R.string.profile_delete_ok, (d, w) -> {
                    pendingProfiles.remove(p);
                    testResults.remove(p.id);
                    renderProfiles();
                    persistProfiles();
                })
                .setNegativeButton(R.string.btn_cancel, null)
                .show();
    }

    private void toggleServerFields() {
        boolean show = llServerFields.getVisibility() != View.VISIBLE;
        llServerFields.setVisibility(show ? View.VISIBLE : View.GONE);
        btnToggleServerFields.setText(show
                ? R.string.profile_hide_fields
                : R.string.profile_show_fields);
    }

    /**
     * Профили — источник истины: links и плоские поля (их читает старое ядро и
     * строка шлюза) считаются из первого включённого; ноль включённых — пустые.
     * Пустой список профилей оставляет плоскую форму как есть.
     */
    private void applyProfiles(SettingsStore.Settings s) {
        s.profiles.clear();
        s.profiles.addAll(pendingProfiles);
        if (pendingProfiles.isEmpty()) return;
        s.links = SettingsStore.joinEnabled(s.profiles);
        SettingsStore.Profile first = s.firstEnabled();
        ParseLink.Flat f = null;
        if (first != null) {
            try {
                f = ParseLink.flattenLegacy(first.link);
            } catch (IllegalArgumentException ignored) {
                // битую ссылку отбраковал импорт; плоские поля остаются пустыми
            }
        }
        s.uuid = f == null ? "" : f.uuid;
        s.server = f == null ? "" : f.server;
        s.port = f == null ? 0 : f.port;
        s.sni = f == null ? "" : f.sni;
        s.publicKey = f == null ? "" : f.publicKey;
        s.shortId = f == null ? "" : f.shortId;
    }

    /** Пишет профили и пересобранную цепочку; ядро перезапускается, если VPN поднят. */
    private void persistProfiles() {
        try {
            SettingsStore store = new SettingsStore(this);
            SettingsStore.Settings s = store.load();
            applyProfiles(s);
            store.save(s);
            if (RupasVpnService.restartIfRunning(this)) {
                LogBuffer.add("[profiles] цепочка изменена — перезапускаю ядро");
            }
            updateEndpointInfo();
        } catch (Exception e) {
            Toast.makeText(this, R.string.settings_save_failed, Toast.LENGTH_LONG).show();
        }
    }

    /** core.Core.TestProfile(link, filesDir) есть только в новом AAR. */
    private static final java.lang.reflect.Method TEST_PROFILE = lookupTestProfile();

    private static java.lang.reflect.Method lookupTestProfile() {
        try {
            return Core.class.getMethod("testProfile", String.class, String.class);
        } catch (Throwable t) {
            return null; // старый AAR: тест недоступен, наружу ничего не бросаем
        }
    }

    private boolean testAvailable() {
        return TEST_PROFILE != null;
    }

    /** Вызов как в CoreBridge: рефлексия, текст ошибки движка — как есть. */
    private String callTestProfile(String link) throws Exception {
        try {
            return (String) TEST_PROFILE.invoke(null, link, getFilesDir().getAbsolutePath());
        } catch (java.lang.reflect.InvocationTargetException e) {
            Throwable cause = e.getCause();
            throw (cause instanceof Exception) ? (Exception) cause : e;
        }
    }

    private void startProfileTest(final SettingsStore.Profile p) {
        if (!testAvailable() || runningTestId != null) return;
        runningTestId = p.id;
        renderProfiles();
        testExecutor.execute(() -> {
            TestResult r;
            try {
                r = parseTestResult(callTestProfile(p.link));
            } catch (Throwable t) {
                String why = t.getMessage() == null ? t.getClass().getSimpleName() : t.getMessage();
                r = new TestResult(false, getString(R.string.profile_test_fail, why));
            }
            final TestResult result = r;
            runOnUiThread(() -> {
                runningTestId = null;
                testResults.put(p.id, result);
                if (!isFinishing() && !isDestroyed()) renderProfiles();
            });
        });
    }

    /** {"ok":bool,"ms":int,"stage":"start|dial|payload|busy","err":"…"} → строка карточки. */
    private TestResult parseTestResult(String raw) {
        JSONObject o;
        try {
            o = new JSONObject(raw == null ? "" : raw);
        } catch (org.json.JSONException e) {
            return new TestResult(false, getString(R.string.profile_test_fail, String.valueOf(raw)));
        }
        if (o.optBoolean("ok", false)) {
            return new TestResult(true, getString(R.string.profile_test_ok, o.optInt("ms", 0)));
        }
        String err = o.optString("err", "").trim();
        if (err.isEmpty()) {
            String stage = o.optString("stage", "").trim();
            err = stage.isEmpty()
                    ? getString(R.string.profile_test_unavailable)
                    : getString(R.string.profile_test_stage, stage);
        }
        return new TestResult(false, getString(R.string.profile_test_fail, err));
    }

    /** Результат проверки профиля: ok + готовая строка для карточки. */
    private static final class TestResult {
        final boolean ok;
        final String text;

        TestResult(boolean ok, String text) {
            this.ok = ok;
            this.text = text;
        }
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
