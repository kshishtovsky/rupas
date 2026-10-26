package ru.rupas.android;

import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.OnBackPressedCallback;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.PopupMenu;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.ItemTouchHelper;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Экран «Маршруты» (docs/ROUTING_UI.md §4.2).
 *
 * Информационная архитектура = семантика движка: правила сгруппированы по стадиям
 * (IP → Домены → Порты), порядок меняется только внутри стадии, default закреплён
 * и не удаляется. Правка живёт в памяти до «Применить правила»: ядро читает правила
 * только при старте, поэтому применение = полный перезапуск ядра через VpnService.
 */
public class RoutingActivity extends AppCompatActivity implements RoutingAdapter.Listener {

    /** Пока идёт применение, статус не должен мигать в «Ошибка» (§5.7). */
    private static volatile boolean applying;

    /** Статус применения для внешних наблюдателей (MainActivity не мигает в «Ошибка»). */
    public static boolean isApplying() {
        return applying;
    }

    /** Сводка последнего успешного чтения правил — для карточки в Настройках. */
    static String cachedSummary(Context ctx) {
        return ctx.getSharedPreferences(PREFS, MODE_PRIVATE).getString(PREF_SUMMARY, null);
    }

    private static final String PREFS = "routing";
    private static final String PREF_SUMMARY = "summary";
    private static final String STATE_RULES = "rules";
    private static final String STATE_PRISTINE = "pristine";

    private static final long SAVED_STRIP_MS = 2000L;
    /** --dur-short §7: появление панели, полоска «Применено», раскрытие секции. */
    private static final long DUR_SHORT_MS = 180L;

    private final ExecutorService io = Executors.newSingleThreadExecutor();
    private final Handler ui = new Handler(Looper.getMainLooper());

    private RecyclerView listRules;
    private LinearLayoutManager layoutManager;
    private RoutingAdapter adapter;

    private TextView tvSummary;
    private TextView tvDangerDefault;
    private TextView tvChanges;
    private TextView tvSaved;
    private TextView tvErrorTitle;
    private TextView tvErrorText;
    private TextView tvCheckStage;
    private TextView tvCheckRule;
    private TextView tvCheckNote;
    private TextView tvCheckError;
    private EditText etQuery;
    private LinearLayout llViolations;
    private MaterialButton btnApply;
    private MaterialButton btnCheck;
    private MaterialButton btnRetry;
    private View chipCheck;

    private View summarySkeleton;
    private View savedStrip;
    private View emptyBox;
    private View skeletonBox;
    private View errorBox;
    private View checkResult;
    private View checkErrorBox;
    private View dirtyPanel;
    private View dirtyRule;
    private View savingOverlay;

    private final List<RoutingRule> pristineRules = new ArrayList<>();
    private RoutingRule pristineDefault = RoutingRule.Parsed.defaultRule();
    private String pristineJson = "";

    private boolean loading;
    private boolean saving;
    private boolean finishAfterApply;
    private boolean retryApplies;
    private String errorTitle;
    private final List<String> violations = new ArrayList<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_routing);

        bindViews();
        setupList();
        setupToolbar();
        setupCheck();
        setupDirtyPanel();
        setupBack();

        if (!restoreState(savedInstanceState)) {
            loadRules();
        }
    }

    /**
     * Поворот экрана не должен выбрасывать несохранённые правки:
     * восстанавливаем и текущий список, и снимок «как было».
     */
    private boolean restoreState(Bundle saved) {
        if (saved == null) {
            return false;
        }
        String current = saved.getString(STATE_RULES);
        if (current == null) {
            return false;
        }
        try {
            RoutingRule.Parsed parsed = RoutingRule.parseRules(current);
            adapter.setData(parsed.rules, parsed.def);
            String pristine = saved.getString(STATE_PRISTINE);
            if (pristine != null) {
                RoutingRule.Parsed base = RoutingRule.parseRules(pristine);
                pristineRules.clear();
                for (RoutingRule r : base.rules) {
                    pristineRules.add(r.copy());
                }
                pristineDefault = base.def;
                pristineJson = pristine;
                render();
            } else {
                snapshotFromAdapter();
                render();
            }
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        outState.putString(STATE_RULES, currentJson());
        outState.putString(STATE_PRISTINE, pristineJson);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        io.shutdownNow();
        ui.removeCallbacksAndMessages(null);
    }

    // ------------------------------------------------------------------- setup

    private void bindViews() {
        listRules = findViewById(R.id.listRules);
        tvSummary = findViewById(R.id.tvSummary);
        tvDangerDefault = findViewById(R.id.tvDangerDefault);
        tvChanges = findViewById(R.id.tvChanges);
        tvSaved = findViewById(R.id.tvSaved);
        tvErrorTitle = findViewById(R.id.tvErrorTitle);
        tvErrorText = findViewById(R.id.tvErrorText);
        tvCheckStage = findViewById(R.id.tvCheckStage);
        tvCheckRule = findViewById(R.id.tvCheckRule);
        tvCheckNote = findViewById(R.id.tvCheckNote);
        tvCheckError = findViewById(R.id.tvCheckError);
        etQuery = findViewById(R.id.etQuery);
        llViolations = findViewById(R.id.llViolations);
        btnApply = findViewById(R.id.btnApply);
        btnCheck = findViewById(R.id.btnCheck);
        btnRetry = findViewById(R.id.btnRetry);
        findViewById(R.id.btnErrorDismiss).setOnClickListener(v -> {
            errorTitle = null;
            violations.clear();
            fillViolations();
            render();
        });
        chipCheck = findViewById(R.id.chipCheck);

        summarySkeleton = findViewById(R.id.summarySkeleton);
        savedStrip = findViewById(R.id.savedStrip);
        emptyBox = findViewById(R.id.emptyBox);
        skeletonBox = findViewById(R.id.skeletonBox);
        errorBox = findViewById(R.id.errorBox);
        checkResult = findViewById(R.id.checkResult);
        checkErrorBox = findViewById(R.id.checkErrorBox);
        dirtyPanel = findViewById(R.id.dirtyPanel);
        dirtyRule = findViewById(R.id.dirtyRule);
        savingOverlay = findViewById(R.id.savingOverlay);
    }

    private void setupList() {
        layoutManager = new LinearLayoutManager(this);
        listRules.setLayoutManager(layoutManager);
        adapter = new RoutingAdapter(this, this);
        adapter.attach(listRules);
        listRules.setAdapter(adapter);
        new ItemTouchHelper(dragCallback).attachToRecyclerView(listRules);
    }

    private void setupToolbar() {
        findViewById(R.id.btnBack).setOnClickListener(v -> onBackRequested());
        findViewById(R.id.btnAdd).setOnClickListener(v -> openEditor(null, -1, RoutingRule.STAGE_IP));
    }

    private void setupCheck() {
        btnCheck.setOnClickListener(v -> runCheck());
        etQuery.setOnEditorActionListener((v, actionId, event) -> {
            runCheck();
            return true;
        });
        findViewById(R.id.btnCheckRetry).setOnClickListener(v -> runCheck());
    }

    private void setupDirtyPanel() {
        btnApply.setOnClickListener(v -> applyRules(false));
        findViewById(R.id.btnRevert).setOnClickListener(v -> revertToPristine());
        findViewById(R.id.btnEmptyAdd).setOnClickListener(v -> openEditor(null, -1, RoutingRule.STAGE_IP));
        findViewById(R.id.btnEmptyPreset).setOnClickListener(v -> showPresets());
        btnRetry.setOnClickListener(v -> {
            if (retryApplies) {
                applyRules(false);
            } else {
                loadRules();
            }
        });
    }

    private void setupBack() {
        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                onBackRequested();
            }
        });
    }

    // ------------------------------------------------------------------ loading

    private void loadRules() {
        loading = true;
        errorTitle = null;
        violations.clear();
        render();
        io.execute(() -> {
            String raw = null;
            String error = null;
            try {
                raw = CoreRouting.rulesJson();
            } catch (Throwable t) {
                error = message(t);
            }
            final String fRaw = raw;
            final String fErr = error;
            ui.post(() -> {
                loading = false;
                if (fErr != null) {
                    errorTitle = getString(R.string.routing_load_error);
                    retryApplies = false;
                    showErrorLines(getString(R.string.routing_load_error), fErr);
                } else {
                    try {
                        RoutingRule.Parsed parsed = RoutingRule.parseRules(fRaw);
                        adapter.setData(parsed.rules, parsed.def);
                        snapshotFromAdapter();
                    } catch (Throwable t) {
                        errorTitle = getString(R.string.routing_load_error);
                        retryApplies = false;
                        showErrorLines(getString(R.string.routing_load_error), message(t));
                    }
                }
                render();
            });
        });
    }

    /** Ошибка = первая строка движка дословно + остальные строки как переходы к правилам. */
    private void showErrorLines(String title, String full) {
        String text = full == null ? "" : full.trim();
        tvErrorTitle.setText(title);
        tvErrorText.setText(RoutingRule.firstLine(text));
        violations.clear();
        String[] parts = text.split("\n");
        for (int i = 1; i < parts.length; i++) {
            String line = parts[i].trim();
            if (!line.isEmpty()) {
                violations.add(line);
            }
        }
        fillViolations();
    }

    private void fillViolations() {
        llViolations.removeAllViews();
        llViolations.setVisibility(violations.isEmpty() ? View.GONE : View.VISIBLE);
        for (String line : violations) {
            TextView tv = new TextView(this);
            tv.setText(line);
            tv.setTextSize(12f);
            tv.setTypeface(android.graphics.Typeface.MONOSPACE);
            tv.setTextColor(ContextCompat.getColor(this, R.color.ink_2));
            tv.setPadding(0, dp(6), 0, dp(6));
            final int index = ruleIndexFromViolation(line);
            if (index >= 0) {
                tv.setClickable(true);
                tv.setFocusable(true);
                tv.setOnClickListener(v -> jumpToRule(index));
            }
            llViolations.addView(tv, new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        }
    }

    private static int ruleIndexFromViolation(String line) {
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("rule\\s+(\\d+)", java.util.regex.Pattern.CASE_INSENSITIVE)
                .matcher(line);
        if (!m.find()) {
            return -1;
        }
        try {
            // Нумерация движка 1-based («config: rule 12»), список — 0-based.
            return Integer.parseInt(m.group(1)) - 1;
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private void jumpToRule(int index) {
        if (index < 0 || index >= adapter.rules().size()) {
            return;
        }
        RoutingRule rule = adapter.rules().get(index);
        if (rule == null) {
            return;
        }
        adapter.expandStage(rule.stage());
        int pos = adapter.positionOfRule(index);
        if (pos >= 0) {
            layoutManager.scrollToPositionWithOffset(pos, dp(24));
        }
    }

    // -------------------------------------------------------------------- dirty

    private String currentJson() {
        return RoutingRule.rulesJson(adapter.rules(), adapter.defaultRule());
    }

    private boolean isDirty() {
        if (loading) {
            return false;
        }
        if (errorTitle != null && !retryApplies) {
            // Правила не прочитаны — сравнивать не с чем.
            return false;
        }
        return !currentJson().equals(pristineJson);
    }

    private void snapshotFromAdapter() {
        pristineRules.clear();
        for (RoutingRule r : adapter.rules()) {
            pristineRules.add(r.copy());
        }
        pristineDefault = adapter.defaultRule().copy();
        pristineJson = currentJson();
    }

    private void revertToPristine() {
        List<RoutingRule> copies = new ArrayList<>();
        for (RoutingRule r : pristineRules) {
            copies.add(r.copy());
        }
        adapter.setData(copies, pristineDefault.copy());
        render();
    }

    private int countChanges() {
        List<RoutingRule> cur = adapter.rules();
        int diff = Math.abs(cur.size() - pristineRules.size());
        int n = Math.min(cur.size(), pristineRules.size());
        for (int i = 0; i < n; i++) {
            if (!cur.get(i).sameAs(pristineRules.get(i))) {
                diff++;
            }
        }
        if (!pristineDefault.sameAs(adapter.defaultRule())) {
            diff++;
        }
        return diff;
    }

    // ------------------------------------------------------------------- render

    private void render() {
        boolean hasError = !loading && errorTitle != null;
        // Ошибка чтения — показывать нечего; ошибка сохранения правила не теряет.
        boolean loadFailed = hasError && !retryApplies;

        skeletonBox.setVisibility(loading ? View.VISIBLE : View.GONE);
        summarySkeleton.setVisibility(loading ? View.VISIBLE : View.GONE);
        tvSummary.setVisibility(loading ? View.GONE : View.VISIBLE);
        errorBox.setVisibility(hasError ? View.VISIBLE : View.GONE);
        findViewById(R.id.btnErrorDismiss).setVisibility(retryApplies ? View.VISIBLE : View.GONE);
        listRules.setVisibility(loading || loadFailed ? View.GONE : View.VISIBLE);

        boolean empty = !loading && !loadFailed && adapter.rules().isEmpty();
        emptyBox.setVisibility(empty ? View.VISIBLE : View.GONE);

        updateSummary();
        refreshDirtyUi();
    }

    private void updateSummary() {
        if (loading || errorTitle != null) {
            tvSummary.setText(R.string.routing_summary_unknown);
            tvDangerDefault.setVisibility(View.GONE);
            return;
        }
        int count = adapter.rules().size();
        String rules = getResources().getQuantityString(R.plurals.rules_count, count, count);
        String action = adapter.defaultRule().action;
        String summary = getString(R.string.routing_summary, rules, action);
        tvSummary.setText(summary);
        getSharedPreferences(PREFS, MODE_PRIVATE).edit().putString(PREF_SUMMARY, summary).apply();
        tvDangerDefault.setVisibility(RoutingRule.ACT_DIRECT.equals(action) ? View.VISIBLE : View.GONE);
    }

    private void refreshDirtyUi() {
        boolean dirty = isDirty();
        dirtyPanel.setVisibility(dirty ? View.VISIBLE : View.GONE);
        dirtyRule.setVisibility(dirty ? View.VISIBLE : View.GONE);
        if (dirty) {
            int changes = Math.max(1, countChanges());
            tvChanges.setText(getResources().getQuantityString(R.plurals.changes_count, changes, changes));
        }
        renderSaving();
    }

    private void renderSaving() {
        btnApply.setEnabled(!saving);
        btnApply.setText(saving ? R.string.routing_saving : R.string.btn_apply_rules);
        savingOverlay.setVisibility(saving ? View.VISIBLE : View.GONE);
        listRules.setAlpha(saving ? 0.55f : 1f);
        listRules.setImportantForAccessibility(saving
                ? View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
                : View.IMPORTANT_FOR_ACCESSIBILITY_AUTO);
    }

    // -------------------------------------------------------------------- apply

    /**
     * Применение = полный рестарт ядра: правила читаются только на старте, а
     * SetRulesJSON отказывает при работающем ядре. Порядок из §5.7:
     * stop core → close tun → правила → establish → SetSettings → Start.
     * Во время рестарта экран остаётся в saving, «Ошибка» не показывается.
     */
    private void applyRules(boolean finishAfter) {
        if (applying || saving) {
            return;
        }
        final String json = currentJson();
        saving = true;
        applying = true;
        finishAfterApply = finishAfter;
        renderSaving();
        io.execute(() -> {
            String error = null;
            boolean restarted = false;
            try {
                restarted = restartWithRules(json);
            } catch (Throwable t) {
                error = message(t);
            }
            final String fErr = error;
            final boolean fRestarted = restarted;
            ui.post(() -> onApplyResult(fErr, json, fRestarted));
        });
    }

    /**
     * Останавливает ядро, ставит правила и поднимает туннель заново.
     * Если правила не приняты, туннель возвращается в прежнее состояние —
     * пользователь не остаётся без VPN из-за опечатки в правиле.
     *
     * @return true, если VPN был поднят и перезапущен
     */
    private boolean restartWithRules(String json) throws Exception {
        boolean wasRunning = RupasVpnService.isRunning();
        if (wasRunning) {
            RupasVpnService.stop(this);
            // stop() синхронен, но onDestroy идёт следом: ждём, пока ядро отпустит правила.
            for (int i = 0; i < 20 && RupasVpnService.isRunning(); i++) {
                Thread.sleep(100L);
            }
        }
        try {
            CoreRouting.setRulesJson(json);
        } catch (Exception e) {
            if (wasRunning) {
                RupasVpnService.start(this);
            }
            throw e;
        }
        if (wasRunning) {
            RupasVpnService.start(this);
        }
        return wasRunning;
    }

    private void onApplyResult(String error, String json, boolean restarted) {
        saving = false;
        if (error != null) {
            applying = false;
            renderSaving();
            finishAfterApply = false;
            errorTitle = getString(R.string.routing_save_error);
            retryApplies = true;
            showErrorLines(getString(R.string.routing_save_error), error);
            render();
            return;
        }

        LogBuffer.add(restarted
                ? "[routing] правила сохранены, VPN перезапускается (~2 с)"
                : "[routing] правила сохранены, применятся при следующем включении VPN");

        errorTitle = null;
        retryApplies = false;
        violations.clear();
        fillViolations();
        pristineJson = json;
        snapshotFromAdapter();
        applying = false;
        render();
        showSavedStrip(restarted);
        if (finishAfterApply) {
            finishAfterApply = false;
            finish();
        }
    }

    private void showSavedStrip(boolean restarted) {
        tvSaved.setText(restarted ? R.string.routing_saved : R.string.routing_apply_not_running);
        savedStrip.setVisibility(View.VISIBLE);
        savedStrip.setAlpha(0f);
        animateAlpha(savedStrip, 1f, DUR_SHORT_MS);
        ui.postDelayed(() -> {
            if (isFinishing() || isDestroyed()) {
                return;
            }
            animateAlpha(savedStrip, 0f, DUR_SHORT_MS, () -> savedStrip.setVisibility(View.GONE));
        }, SAVED_STRIP_MS);
    }

    // ------------------------------------------------------------------ editing

    private void openEditor(RoutingRule rule, int index, int stage) {
        boolean defaultMode = rule != null && rule.isDefault();
        RuleEditorSheet sheet = new RuleEditorSheet(this, adapter.rules(), index, rule, stage,
                defaultMode, (saved, editIndex) -> {
                    if (saved.isDefault()) {
                        adapter.defaultRule().action = saved.action;
                    } else if (editIndex >= 0 && editIndex < adapter.rules().size()) {
                        adapter.rules().set(editIndex, saved);
                        adapter.expandStage(saved.stage());
                    } else {
                        adapter.rules().add(saved);
                        adapter.expandStage(saved.stage());
                    }
                    adapter.rebuild();
                    render();
                });
        sheet.show();
    }

    private void duplicateRule(RoutingRule rule, int index) {
        if (rule == null) {
            return;
        }
        RoutingRule copy = rule.copy();
        int at = Math.max(0, Math.min(index + 1, adapter.rules().size()));
        adapter.rules().add(at, copy);
        adapter.rebuild();
        render();
        Toast.makeText(this, R.string.routing_duplicated, Toast.LENGTH_SHORT).show();
    }

    private void confirmDelete(RoutingRule rule, int index) {
        if (rule == null) {
            return;
        }
        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.routing_delete_title)
                .setMessage(rule.matcher())
                .setPositiveButton(R.string.menu_delete, (d, w) -> {
                    if (index >= 0 && index < adapter.rules().size()) {
                        adapter.rules().remove(index);
                        adapter.rebuild();
                        render();
                        Toast.makeText(this, R.string.routing_deleted, Toast.LENGTH_SHORT).show();
                    }
                })
                .setNegativeButton(R.string.btn_cancel, null)
                .show();
    }

    // ------------------------------------------------------------ adapter hooks

    @Override
    public void onRuleClick(RoutingRule rule, int index) {
        openEditor(rule, index, rule == null ? RoutingRule.STAGE_IP : rule.stage());
    }

    @Override
    public void onRuleMenu(View anchor, RoutingRule rule, int index) {
        PopupMenu menu = new PopupMenu(this, anchor);
        menu.getMenu().add(0, 1, 0, R.string.menu_edit);
        menu.getMenu().add(0, 2, 1, R.string.menu_duplicate);
        menu.getMenu().add(0, 3, 2, R.string.menu_delete);
        menu.setOnMenuItemClickListener(item -> {
            switch (item.getItemId()) {
                case 1:
                    openEditor(rule, index, rule == null ? RoutingRule.STAGE_IP : rule.stage());
                    return true;
                case 2:
                    duplicateRule(rule, index);
                    return true;
                case 3:
                    confirmDelete(rule, index);
                    return true;
                default:
                    return false;
            }
        });
        menu.show();
    }

    @Override
    public void onStageToggle(int stage) {
        adapter.toggleStage(stage);
        listRules.setAlpha(0.7f);
        animateAlpha(listRules, 1f, DUR_SHORT_MS);
    }

    @Override
    public void onAddRule(int stage) {
        openEditor(null, -1, stage);
    }

    @Override
    public void onDefaultClick() {
        openEditor(adapter.defaultRule(), -1, RoutingRule.STAGE_IP);
    }

    // --------------------------------------------------------------------- drag

    private final ItemTouchHelper.Callback dragCallback = new ItemTouchHelper.Callback() {
        @Override
        public int getMovementFlags(RecyclerView rv, RecyclerView.ViewHolder vh) {
            if (!adapter.isRuleRow(vh.getAdapterPosition())) {
                return makeMovementFlags(0, 0);
            }
            int drag = ItemTouchHelper.UP | ItemTouchHelper.DOWN;
            return makeMovementFlags(drag, 0);
        }

        @Override
        public boolean isLongPressDragEnabled() {
            // §5.2: на Android ручка появляется по long-press, а не постоянно.
            return true;
        }

        @Override
        public boolean canDropOver(RecyclerView rv, RecyclerView.ViewHolder current,
                                   RecyclerView.ViewHolder target) {
            return adapter.sameStage(current.getAdapterPosition(),
                    target.getAdapterPosition());
        }

        @Override
        public boolean onMove(RecyclerView rv, RecyclerView.ViewHolder vh, RecyclerView.ViewHolder target) {
            boolean moved = adapter.moveRule(vh.getAdapterPosition(),
                    target.getAdapterPosition());
            if (moved) {
                refreshDirtyUi();
            }
            return moved;
        }

        @Override
        public void onSwiped(RecyclerView.ViewHolder vh, int direction) {
            // Только перестановка: свайп не удаляет правило.
        }

        @Override
        public void onSelectedChanged(RecyclerView.ViewHolder vh, int actionState) {
            super.onSelectedChanged(vh, actionState);
            if (actionState == ItemTouchHelper.ACTION_STATE_DRAG) {
                adapter.setDragMode(true);
                listRules.setAlpha(0.96f);
            }
        }

        @Override
        public void clearView(RecyclerView rv, RecyclerView.ViewHolder vh) {
            super.clearView(rv, vh);
            adapter.setDragMode(false);
            listRules.setAlpha(1f);
            adapter.rebuild();
            render();
        }
    };

    // ------------------------------------------------------------------- check

    private void runCheck() {
        final String query = etQuery.getText() == null ? "" : etQuery.getText().toString().trim();
        if (query.isEmpty()) {
            checkResult.setVisibility(View.GONE);
            checkErrorBox.setVisibility(View.GONE);
            return;
        }
        if (!CoreRouting.hasTestRoute()) {
            showCheckError();
            return;
        }
        btnCheck.setEnabled(false);
        checkErrorBox.setVisibility(View.GONE);
        io.execute(() -> {
            String raw = null;
            String error = null;
            try {
                raw = CoreRouting.testRoute(query);
            } catch (Throwable t) {
                error = message(t);
            }
            final String fRaw = raw;
            final String fErr = error;
            ui.post(() -> {
                btnCheck.setEnabled(true);
                String now = etQuery.getText() == null ? "" : etQuery.getText().toString().trim();
                if (!query.equals(now)) {
                    return;
                }
                if (fErr != null || fRaw == null) {
                    showCheckError();
                } else {
                    renderTrace(fRaw, query);
                }
            });
        });
    }

    private void showCheckError() {
        showCheckError(null);
    }

    /** Ошибка ядра: копирайт §5.5 плюс дословная причина от движка, если она есть. */
    private void showCheckError(String detail) {
        checkResult.setVisibility(View.GONE);
        checkErrorBox.setVisibility(View.VISIBLE);
        String line = RoutingRule.firstLine(detail);
        if (line.isEmpty()) {
            tvCheckError.setText(R.string.routing_check_unavailable);
        } else {
            tvCheckError.setText(getString(R.string.routing_check_unavailable_detail, line));
            LogBuffer.add("[routing] route-test: " + line);
        }
    }

    /** Трасса решения (§5.5) — единственное, что владелец должен запомнить. */
    private void renderTrace(String raw, String query) {
        try {
            JSONObject o = new JSONObject(raw.trim());
            if (o.has("error")) {
                showCheckError(o.optString("error", ""));
                return;
            }
            int stage = o.optInt("stage", 0);
            String stageName = o.optString("stageName", o.optString("stage_name", ""));
            String matcher = o.optString("matcher", "");
            String action = RoutingRule.normalizeAction(o.optString("action", ""));
            String note = o.optString("note", "");
            String warn = o.optString("warning", "");

            boolean defaultHit = stage >= 4 || stage <= 0 && matcher.isEmpty();
            tvCheckStage.setText(defaultHit
                    ? getString(R.string.routing_check_default_stage)
                    : getString(R.string.routing_check_stage, stage, stageName));
            tvCheckRule.setText(getString(R.string.routing_check_rule,
                    matcher.isEmpty() ? getString(R.string.routing_default_name) : matcher));
            RoutingStyle.applyChip(chipCheck, action);

            String noteText = note;
            boolean dangerNote = false;
            if (looksLikeIp(query)) {
                if (noteText.isEmpty()) {
                    noteText = getString(R.string.routing_check_no_domains);
                }
            }
            if (defaultHit && RoutingRule.ACT_DIRECT.equals(action)) {
                noteText = getString(R.string.routing_check_ip_exposed);
                dangerNote = true;
            }
            // Правило-наборная оговорка (например, недоступная geoip-таблица)
            // относится к ЛЮБОЙ проверке — показываем её отдельной строкой,
            // а не подмешиваем в note конкретного запроса.
            if (!warn.isEmpty()) {
                String warnText = getString(R.string.routing_check_warning, warn);
                noteText = noteText.isEmpty() ? warnText : noteText + "\n" + warnText;
            }
            tvCheckNote.setText(noteText);
            tvCheckNote.setTextColor(ContextCompat.getColor(this,
                    dangerNote ? R.color.danger : R.color.ink_soft));
            tvCheckNote.setVisibility(noteText.isEmpty() ? View.GONE : View.VISIBLE);

            checkResult.setVisibility(View.VISIBLE);
            checkErrorBox.setVisibility(View.GONE);
        } catch (Throwable t) {
            showCheckError();
        }
    }

    private static boolean looksLikeIp(String q) {
        if (q == null) {
            return false;
        }
        return q.matches("\\d{1,3}(\\.\\d{1,3}){3}") || (q.contains(":") && q.matches("[0-9a-fA-F:.]+"));
    }

    // ----------------------------------------------------------------- presets

    private void showPresets() {
        final String[] items = {
                getString(R.string.preset_owner),
                getString(R.string.preset_ru),
                getString(R.string.preset_all_tunnel),
                getString(R.string.preset_all_direct)
        };
        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.routing_presets)
                .setItems(items, (d, which) -> {
                    switch (which) {
                        case 0:
                        case 1:
                            // Данных этих пресетов на Android нет: правила приходят из ядра.
                            Toast.makeText(this, R.string.preset_unavailable, Toast.LENGTH_SHORT).show();
                            break;
                        case 2:
                            applyPreset(RoutingRule.ACT_TUNNEL);
                            break;
                        case 3:
                            confirmAllDirect();
                            break;
                        default:
                            break;
                    }
                })
                .setNegativeButton(R.string.btn_cancel, null)
                .show();
    }

    private void confirmAllDirect() {
        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.preset_all_direct)
                .setMessage(R.string.preset_all_direct_confirm)
                .setPositiveButton(R.string.preset_all_direct, (d, w) -> applyPreset(RoutingRule.ACT_DIRECT))
                .setNegativeButton(R.string.btn_cancel, null)
                .show();
    }

    private void applyPreset(String defaultAction) {
        RoutingRule def = RoutingRule.Parsed.defaultRule();
        def.action = defaultAction;
        adapter.setData(new ArrayList<>(), def);
        render();
    }

    // -------------------------------------------------------------------- misc

    private void onBackRequested() {
        if (saving) {
            return;
        }
        if (!isDirty()) {
            finish();
            return;
        }
        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.routing_unsaved_title)
                .setMessage(R.string.routing_unsaved_text)
                .setPositiveButton(R.string.btn_apply_rules, (d, w) -> applyRules(true))
                .setNeutralButton(R.string.routing_discard, (d, w) -> {
                    revertToPristine();
                    finish();
                })
                .setNegativeButton(R.string.routing_stay, null)
                .show();
    }

    /** Только transform/opacity; при выключенной анимации — мгновенно (§7). */
    private void animateAlpha(View v, float to, long duration) {
        animateAlpha(v, to, duration, null);
    }

    private void animateAlpha(View v, float to, long duration, Runnable end) {
        if (!animationsOn() || duration <= 0) {
            v.setAlpha(to);
            if (end != null) {
                end.run();
            }
            return;
        }
        v.animate().alpha(to).setDuration(duration).withEndAction(end).start();
    }

    private boolean animationsOn() {
        try {
            return Settings.Global.getFloat(getContentResolver(),
                    Settings.Global.ANIMATOR_DURATION_SCALE, 1f) > 0f;
        } catch (Throwable t) {
            return true;
        }
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private static String message(Throwable t) {
        if (t == null) {
            return "";
        }
        String m = t.getMessage();
        return m == null || m.trim().isEmpty() ? t.getClass().getSimpleName() : m;
    }
}
