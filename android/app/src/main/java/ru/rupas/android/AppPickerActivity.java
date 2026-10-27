package ru.rupas.android;

import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.OnBackPressedCallback;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.chip.ChipGroup;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Выбор приложений для 4-й стадии «Маршруты» (docs/PERAPP_ROUTING.md §4).
 *
 * Полноэкранный, вход только из стадии «Приложения». Показывает приложения с
 * разрешением INTERNET (себя — нет, rupas всегда вне VPN), поиск по имени и пакету,
 * фильтры «Все · С правилом · Системные» и переключатель действия из 4 позиций.
 *
 * Сохранение — сразу в SettingsStore (§5: Java-сторона читает app_rules при
 * establish()), поэтому экран не возвращает результат: «Маршруты» при возврате
 * перечитывают хранилище и показывают панель «Применить правила». Применение =
 * перезапуск VPN (~2 с), и это сказано в счётчике внизу дословно.
 */
public class AppPickerActivity extends AppCompatActivity implements AppPickerAdapter.Listener {

    private final ExecutorService io = Executors.newSingleThreadExecutor();
    private final Handler ui = new Handler(Looper.getMainLooper());

    /** Источник истины экрана: package → action ("" — наследует). */
    private final Map<String, String> actions = new LinkedHashMap<>();

    private AppPickerAdapter adapter;
    private RecyclerView listApps;
    private EditText etSearch;
    private TextView tvCounter;
    private TextView tvEmpty;
    private TextView tvLoading;
    private TextView tvApiNote;
    private LinearLayout bottomBar;

    private boolean loaded;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_app_picker);

        bottomBar = findViewById(R.id.pickerBottomBar);
        listApps = findViewById(R.id.listApps);
        etSearch = findViewById(R.id.etPickerSearch);
        tvCounter = findViewById(R.id.tvPickerCounter);
        tvEmpty = findViewById(R.id.tvPickerEmpty);
        tvLoading = findViewById(R.id.tvPickerLoading);
        tvApiNote = findViewById(R.id.tvPickerApiNote);

        // API < 29: TUNNEL/BLOCK недоступны — подпись видна, а не спрятана в сером.
        tvApiNote.setVisibility(AppCatalog.supportsUidRouting() ? View.GONE : View.VISIBLE);

        findViewById(R.id.btnPickerBack).setOnClickListener(v -> finish());
        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                finish();
            }
        });

        adapter = new AppPickerAdapter(this, this);
        listApps.setLayoutManager(new LinearLayoutManager(this));
        listApps.setAdapter(adapter);

        setupInsets();
        setupSearch();
        setupFilters();
        updateCounter();
        loadApps();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        io.shutdownNow();
        ui.removeCallbacksAndMessages(null);
    }

    // ------------------------------------------------------------------- setup

    /**
     * Safe-area: окно рисуется под системными полосами (targetSdk 36 + принудительный
     * edge-to-edge на Android 15+), поэтому верхний inset отдаём КОРНЮ — у тулбара
     * фиксированная высота 56dp, и padding на нём сжал бы содержимое. Нижний inset —
     * нижней полосе (она wrap_content, фон остаётся до края экрана), чтобы
     * навигационная полоса не съела «Выбрано N».
     */
    private void setupInsets() {
        final View root = findViewById(R.id.pickerRoot);
        final int rootTop = root.getPaddingTop();
        final int barBottom = bottomBar.getPaddingBottom();
        ViewCompat.setOnApplyWindowInsetsListener(root, (v, insets) -> {
            androidx.core.graphics.Insets bars =
                    insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(v.getPaddingLeft(), rootTop + Math.max(bars.top, 0),
                    v.getPaddingRight(), v.getPaddingBottom());
            bottomBar.setPadding(bottomBar.getPaddingLeft(), bottomBar.getPaddingTop(),
                    bottomBar.getPaddingRight(), barBottom + Math.max(bars.bottom, 0));
            return insets;
        });
        ViewCompat.requestApplyInsets(root);
    }

    private void setupSearch() {
        etSearch.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            @Override
            public void afterTextChanged(Editable s) {
                adapter.setQuery(s == null ? "" : s.toString());
                updateEmpty();
            }
        });
    }

    private void setupFilters() {
        ChipGroup group = findViewById(R.id.chipFilters);
        group.setOnCheckedStateChangeListener((g, checkedIds) -> {
            int id = checkedIds.isEmpty() ? R.id.chipAll : checkedIds.get(0);
            if (id == R.id.chipWithRule) {
                adapter.setFilter(AppPickerAdapter.FILTER_RULE);
            } else if (id == R.id.chipSystem) {
                adapter.setFilter(AppPickerAdapter.FILTER_SYSTEM);
            } else {
                adapter.setFilter(AppPickerAdapter.FILTER_ALL);
            }
            updateEmpty();
        });
    }

    // -------------------------------------------------------------------- data

    private void loadApps() {
        tvLoading.setVisibility(View.VISIBLE);
        tvEmpty.setVisibility(View.GONE);
        io.execute(() -> {
            List<AppCatalog.Entry> entries = AppCatalog.all(this);
            Map<String, String> saved = new LinkedHashMap<>();
            try {
                saved.putAll(new SettingsStore(this).load().appRules);
            } catch (Throwable t) {
                LogBuffer.add("[apps] app_rules не прочитаны: " + t);
            }
            ui.post(() -> {
                if (isFinishing() || isDestroyed()) {
                    return;
                }
                actions.clear();
                actions.putAll(saved);
                adapter.setData(entries, actions);
                loaded = true;
                tvLoading.setVisibility(View.GONE);
                updateCounter();
                updateEmpty();
            });
        });
    }

    private void updateEmpty() {
        boolean empty = loaded && adapter.getItemCount() == 0;
        tvEmpty.setVisibility(empty ? View.VISIBLE : View.GONE);
    }

    private void updateCounter() {
        int n = AppPickerAdapter.countWithRule(actions);
        tvCounter.setText(n == 0
                ? getString(R.string.routing_apps_counter_zero)
                : getString(R.string.routing_apps_counter, n));
    }

    /**
     * Сохранение «на лету»: экран не отдаёт результат, потому что правило должно
     * лежать в хранилище до старта VPN. Пишем в фоне — Keystore дорогой.
     */
    private void persist() {
        final Context app = getApplicationContext();
        final Map<String, String> snapshot = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : actions.entrySet()) {
            if (e.getValue() != null && !e.getValue().isEmpty()) {
                snapshot.put(e.getKey(), e.getValue());
            }
        }
        io.execute(() -> {
            try {
                new SettingsStore(app).saveAppRules(snapshot);
            } catch (Throwable t) {
                final String m = String.valueOf(t);
                ui.post(() -> {
                    if (isFinishing() || isDestroyed()) {
                        return;
                    }
                    Toast.makeText(this, R.string.routing_apps_save_error, Toast.LENGTH_LONG).show();
                    LogBuffer.add("[apps] app_rules не сохранены: " + m);
                });
            }
        });
    }

    // ---------------------------------------------------------------- listener

    @Override
    public void onActionPicked(AppCatalog.Entry entry, String action) {
        if (entry == null) {
            return;
        }
        String normalized = AppRule.normalize(action);
        if (AppRule.needsApi29(normalized) && !AppCatalog.supportsUidRouting()) {
            onLockedAction();
            return;
        }
        if (normalized.isEmpty()) {
            actions.remove(entry.pkg);
        } else {
            actions.put(entry.pkg, normalized);
        }
        adapter.onActionsChanged();
        updateCounter();
        updateEmpty();
        persist();
    }

    @Override
    public void onLockedAction() {
        Toast.makeText(this, R.string.routing_apps_need_android10, Toast.LENGTH_SHORT).show();
    }
}
