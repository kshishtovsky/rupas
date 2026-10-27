package ru.rupas.android;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import java.util.ArrayList;
import java.util.List;

/**
 * Список правил, сгруппированный по стадиям движка (§2):
 * заголовок стадии → правила → «+ Правило», затем четвёртая стадия «Приложения»
 * (docs/PERAPP_ROUTING.md §4: заголовок со счётчиком → строки приложений →
 * «+ Выбрать приложения» либо пустое состояние), в конце закреплённый default.
 *
 * Типы строк: stage header, rule row, default row, строка добавления внутри стадии,
 * app row, пустое состояние стадии приложений, вход в выбор приложений.
 */
final class RoutingAdapter extends RecyclerView.Adapter<RecyclerView.ViewHolder> {

    static final int T_STAGE = 0;
    static final int T_RULE = 1;
    static final int T_DEFAULT = 2;
    static final int T_ADD = 3;
    static final int T_APP = 4;
    static final int T_APP_EMPTY = 5;
    static final int T_APP_ADD = 6;

    /** Стадии экрана: 0..2 — правила движка, 3 — приложения (PERAPP_ROUTING §4). */
    static final int STAGE_APPS = 3;
    private static final int STAGE_COUNT = 4;

    interface Listener {
        void onRuleClick(RoutingRule rule, int index);

        void onRuleMenu(View anchor, RoutingRule rule, int index);

        void onStageToggle(int stage);

        void onAddRule(int stage);

        void onDefaultClick();

        /** «+ Выбрать приложения» / кнопка пустого состояния. */
        void onAppsAdd();

        void onAppClick(AppRule rule, int index);

        void onAppMenu(View anchor, AppRule rule, int index);
    }

    private static final class Row {
        int type;
        int stage;
        RoutingRule rule;
        AppRule app;
        int index;
        int appIndex;
        int posInStage;
        int stageTotal;
        int count;
        boolean collapsed;
    }

    private final Context ctx;
    private final Listener listener;
    private final List<Row> rows = new ArrayList<>();
    private final List<RoutingRule> rules = new ArrayList<>();
    private final List<AppRule> appRules = new ArrayList<>();
    private final boolean[] collapsed = new boolean[STAGE_COUNT];
    private RoutingRule def = RoutingRule.Parsed.defaultRule();
    private boolean dragMode;
    private RecyclerView list;


    RoutingAdapter(Context ctx, Listener listener) {
        this.ctx = ctx;
        this.listener = listener;
        setHasStableIds(false);
    }

    void attach(RecyclerView rv) {
        this.list = rv;
    }

    List<RoutingRule> rules() {
        return rules;
    }

    /** Правила по приложениям (4-я стадия); изменяются на месте, как и rules(). */
    List<AppRule> appRules() {
        return appRules;
    }

    void setAppRules(List<AppRule> data) {
        appRules.clear();
        if (data != null) {
            for (AppRule r : data) {
                if (r != null && r.isValid() && !r.inherited()) {
                    appRules.add(r);
                }
            }
        }
        rebuild();
    }

    RoutingRule defaultRule() {
        return def;
    }

    void toggleStage(int stage) {
        if (stage < 0 || stage >= collapsed.length) {
            return;
        }
        collapsed[stage] = !collapsed[stage];
        rebuild();
    }

    void expandStage(int stage) {
        if (stage < 0 || stage >= collapsed.length || !collapsed[stage]) {
            return;
        }
        collapsed[stage] = false;
        rebuild();
    }

    void setData(List<RoutingRule> data, RoutingRule defaultRule) {
        rules.clear();
        if (data != null) {
            for (RoutingRule r : data) {
                if (r != null && !r.isDefault()) {
                    rules.add(r);
                }
            }
        }
        def = defaultRule == null ? RoutingRule.Parsed.defaultRule() : defaultRule;
        rebuild();
    }

    /** Позиция строки правила по индексу в списке правил; -1 если стадия свёрнута. */
    int positionOfRule(int ruleIndex) {
        for (int i = 0; i < rows.size(); i++) {
            Row row = rows.get(i);
            if (row.type == T_RULE && row.index == ruleIndex) {
                return i;
            }
        }
        return -1;
    }

    /** Перетаскивать можно только строки правил: заголовки и default не двигаются. */
    boolean isRuleRow(int position) {
        return position >= 0 && position < rows.size() && rows.get(position).type == T_RULE;
    }

    void rebuild() {
        rows.clear();
        for (int stage = 0; stage < 3; stage++) {
            int total = 0;
            for (RoutingRule r : rules) {
                if (r.stage() == stage) {
                    total++;
                }
            }
            Row head = new Row();
            head.type = T_STAGE;
            head.stage = stage;
            head.count = total;
            head.collapsed = collapsed[stage];
            rows.add(head);
            if (collapsed[stage]) {
                continue;
            }
            int pos = 0;
            for (int i = 0; i < rules.size(); i++) {
                RoutingRule r = rules.get(i);
                if (r.stage() != stage) {
                    continue;
                }
                pos++;
                Row row = new Row();
                row.type = T_RULE;
                row.stage = stage;
                row.rule = r;
                row.index = i;
                row.posInStage = pos;
                row.stageTotal = total;
                rows.add(row);
            }
            Row add = new Row();
            add.type = T_ADD;
            add.stage = stage;
            rows.add(add);
        }
        appendAppsStage();
        Row d = new Row();
        d.type = T_DEFAULT;
        rows.add(d);
        notifyDataSetChanged();
    }

    /**
     * 4-я стадия «Приложения» (PERAPP_ROUTING §4): заголовок со счётчиком, строки
     * выбранных приложений, затем либо пустое состояние с кнопкой, либо «+ Выбрать
     * приложения». Пустое состояние уже содержит кнопку, поэтому вторую не рисуем.
     */
    private void appendAppsStage() {
        Row head = new Row();
        head.type = T_STAGE;
        head.stage = STAGE_APPS;
        head.count = appRules.size();
        head.collapsed = collapsed[STAGE_APPS];
        rows.add(head);
        if (collapsed[STAGE_APPS]) {
            return;
        }
        if (appRules.isEmpty()) {
            Row empty = new Row();
            empty.type = T_APP_EMPTY;
            empty.stage = STAGE_APPS;
            rows.add(empty);
            return;
        }
        for (int i = 0; i < appRules.size(); i++) {
            Row row = new Row();
            row.type = T_APP;
            row.stage = STAGE_APPS;
            row.app = appRules.get(i);
            row.appIndex = i;
            row.posInStage = i + 1;
            row.stageTotal = appRules.size();
            rows.add(row);
        }
        Row add = new Row();
        add.type = T_APP_ADD;
        add.stage = STAGE_APPS;
        rows.add(add);
    }

    // ------------------------------------------------------------------- drag

    /** Перестановка разрешена только внутри своей стадии (§2: порядок важен лишь там). */
    boolean sameStage(int fromPos, int toPos) {
        if (fromPos < 0 || toPos < 0 || fromPos >= rows.size() || toPos >= rows.size()) {
            return false;
        }
        Row a = rows.get(fromPos);
        Row b = rows.get(toPos);
        return a.type == T_RULE && b.type == T_RULE && a.stage == b.stage;
    }

    boolean moveRule(int fromPos, int toPos) {
        if (!sameStage(fromPos, toPos)) {
            return false;
        }
        Row from = rows.get(fromPos);
        Row to = rows.get(toPos);
        int fi = rules.indexOf(from.rule);
        int ti = rules.indexOf(to.rule);
        if (fi < 0 || ti < 0 || fi == ti) {
            return false;
        }
        RoutingRule moved = rules.remove(fi);
        rules.add(ti, moved);
        rows.remove(fromPos);
        rows.add(toPos, from);
        renumber();
        notifyItemMoved(fromPos, toPos);
        return true;
    }

    private void renumber() {
        int[] pos = new int[3];
        for (Row row : rows) {
            if (row.type == T_RULE && row.stage >= 0 && row.stage < pos.length) {
                pos[row.stage]++;
                row.posInStage = pos[row.stage];
            }
        }
    }

    /**
     * Ручка перетаскивания живёт только пока идёт перетаскивание (§5.2):
     * на Android она не должна быть постоянным визуальным шумом.
     */
    void setDragMode(boolean on) {
        if (dragMode == on) {
            return;
        }
        dragMode = on;
        if (list == null) {
            return;
        }
        for (int i = 0; i < list.getChildCount(); i++) {
            View child = list.getChildAt(i);
            View handle = child.findViewById(R.id.handleDrag);
            if (handle != null) {
                handle.setVisibility(on ? View.VISIBLE : View.INVISIBLE);
            }
        }
    }

    // --------------------------------------------------------------- recycling

    @Override
    public int getItemCount() {
        return rows.size();
    }

    @Override
    public int getItemViewType(int position) {
        return rows.get(position).type;
    }

    @NonNull
    @Override
    public RecyclerView.ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        LayoutInflater inf = LayoutInflater.from(parent.getContext());
        switch (viewType) {
            case T_STAGE:
                return new StageHolder(inf.inflate(R.layout.item_stage_header, parent, false));
            case T_RULE:
                return new RuleHolder(inf.inflate(R.layout.item_rule, parent, false));
            case T_DEFAULT:
                return new DefaultHolder(inf.inflate(R.layout.item_default_row, parent, false));
            case T_ADD:
                return new AddHolder(inf.inflate(R.layout.item_add_rule, parent, false));
            case T_APP:
                return new AppHolder(inf.inflate(R.layout.item_app_row, parent, false));
            case T_APP_EMPTY:
                return new AppEmptyHolder(inf.inflate(R.layout.item_app_empty, parent, false));
            case T_APP_ADD:
            default:
                return new AppAddHolder(inf.inflate(R.layout.item_app_add, parent, false));
        }
    }

    @Override
    public void onBindViewHolder(@NonNull RecyclerView.ViewHolder holder, int position) {
        Row row = rows.get(position);
        if (holder instanceof StageHolder) {
            bindStage((StageHolder) holder, row);
        } else if (holder instanceof RuleHolder) {
            bindRule((RuleHolder) holder, row);
        } else if (holder instanceof DefaultHolder) {
            bindDefault((DefaultHolder) holder);
        } else if (holder instanceof AddHolder) {
            bindAdd((AddHolder) holder, row);
        } else if (holder instanceof AppHolder) {
            bindApp((AppHolder) holder, row);
        } else if (holder instanceof AppEmptyHolder) {
            bindAppEmpty((AppEmptyHolder) holder);
        } else if (holder instanceof AppAddHolder) {
            bindAppAdd((AppAddHolder) holder);
        }
    }

    private void bindStage(StageHolder h, Row row) {
        h.name.setText(stageNameRes(row.stage));
        h.count.setText(String.valueOf(row.count));
        h.chevron.setRotation(row.collapsed ? -90f : 0f);
        h.itemView.setContentDescription(ctx.getString(R.string.a11y_stage_state,
                ctx.getString(stageNameRes(row.stage)), row.count,
                ctx.getString(row.collapsed ? R.string.a11y_stage_closed : R.string.a11y_stage_open)));
        final int stage = row.stage;
        h.itemView.setOnClickListener(v -> listener.onStageToggle(stage));
    }

    private void bindRule(RuleHolder h, Row row) {
        RoutingRule r = row.rule;
        String caption = r.caption(ctx);
        h.matcher.setText(r.matcher());
        h.caption.setText(caption);
        RoutingStyle.applyChip(h.chip, r.action);
        h.handle.setVisibility(dragMode ? View.VISIBLE : View.INVISIBLE);
        h.itemView.setContentDescription(ctx.getString(R.string.routing_a11y_rule,
                caption, r.action, r.matcher(), row.posInStage, Math.max(row.stageTotal, 1),
                ctx.getString(stageNameRes(row.stage))));
        final int index = row.index;
        h.itemView.setOnClickListener(v -> listener.onRuleClick(r, index));
        h.menu.setOnClickListener(v -> listener.onRuleMenu(v, r, index));
        h.itemView.setLongClickable(true);
    }

    private void bindDefault(DefaultHolder h) {
        RoutingStyle.applyChip(h.chip, def.action);
        h.danger.setVisibility(RoutingRule.ACT_DIRECT.equals(def.action) ? View.VISIBLE : View.GONE);
        h.itemView.setContentDescription(ctx.getString(R.string.routing_stage_default)
                + ", " + def.action + ", " + ctx.getString(R.string.routing_default_name));
        h.itemView.setOnClickListener(v -> listener.onDefaultClick());
        h.chip.setOnClickListener(v -> listener.onDefaultClick());
    }

    private void bindAdd(AddHolder h, Row row) {
        final int stage = row.stage;
        h.itemView.setContentDescription(ctx.getString(R.string.routing_add_rule) + ": "
                + ctx.getString(stageNameRes(stage)));
        h.itemView.setOnClickListener(v -> listener.onAddRule(stage));
    }

    /**
     * Строка приложения: иконка из PackageManager, имя, пакет второй строкой,
     * чип действия (§5.3). Если пакет удалён, показываем сам пакет — правило
     * не исчезает из списка молча.
     */
    private void bindApp(AppHolder h, Row row) {
        final AppRule rule = row.app;
        final AppCatalog.Entry entry = AppCatalog.get(ctx, rule.pkg);
        if (entry != null) {
            h.icon.setImageDrawable(entry.icon(ctx.getPackageManager()));
            h.name.setText(entry.label);
        } else {
            h.icon.setImageDrawable(ctx.getPackageManager().getDefaultActivityIcon());
            h.name.setText(rule.pkg);
        }
        String pkgLine = rule.pkg;
        int shared = AppCatalog.sharedUidCount(ctx, rule.pkg, appRules);
        if (shared > 0) {
            // §5: у нескольких пакетов один UID — правило применится ко всем.
            pkgLine = pkgLine + " · " + ctx.getResources()
                    .getQuantityString(R.plurals.app_shared_uid, shared, shared);
        }
        h.pkg.setText(pkgLine);
        RoutingStyle.applyChip(h.chip, rule.chipAction());

        String actionLabel = ctx.getString(RoutingStyle.labelRes(rule.chipAction()));
        h.itemView.setContentDescription(ctx.getString(R.string.app_a11y_row,
                entry == null ? rule.pkg : entry.label, actionLabel, rule.pkg));
        final int index = row.appIndex;
        h.itemView.setOnClickListener(v -> listener.onAppClick(rule, index));
        h.menu.setOnClickListener(v -> listener.onAppMenu(v, rule, index));
    }

    private void bindAppEmpty(AppEmptyHolder h) {
        h.action.setOnClickListener(v -> listener.onAppsAdd());
    }

    private void bindAppAdd(AppAddHolder h) {
        h.itemView.setContentDescription(ctx.getString(R.string.routing_apps_add));
        h.itemView.setOnClickListener(v -> listener.onAppsAdd());
    }

    static int stageNameRes(int stage) {
        switch (stage) {
            case RoutingRule.STAGE_IP:
                return R.string.routing_stage_ip;
            case RoutingRule.STAGE_DOMAINS:
                return R.string.routing_stage_domains;
            case RoutingRule.STAGE_PORTS:
                return R.string.routing_stage_ports;
            case STAGE_APPS:
                return R.string.routing_stage_apps;
            default:
                return R.string.routing_stage_default;
        }
    }

    // ---------------------------------------------------------------- holders

    static final class StageHolder extends RecyclerView.ViewHolder {
        final TextView name;
        final TextView count;
        final ImageView chevron;

        StageHolder(View v) {
            super(v);
            name = v.findViewById(R.id.tvStageName);
            count = v.findViewById(R.id.tvStageCount);
            chevron = v.findViewById(R.id.ivStageChevron);
        }
    }

    static final class RuleHolder extends RecyclerView.ViewHolder {
        final TextView matcher;
        final TextView caption;
        final TextView menu;
        final TextView handle;
        final View chip;

        RuleHolder(View v) {
            super(v);
            matcher = v.findViewById(R.id.tvMatcher);
            caption = v.findViewById(R.id.tvCaption);
            menu = v.findViewById(R.id.btnMenu);
            handle = v.findViewById(R.id.handleDrag);
            chip = v.findViewById(R.id.chipAction);
        }
    }

    static final class DefaultHolder extends RecyclerView.ViewHolder {
        final TextView danger;
        final View chip;

        DefaultHolder(View v) {
            super(v);
            danger = v.findViewById(R.id.tvDefaultDanger);
            chip = v.findViewById(R.id.chipAction);
        }
    }

    static final class AddHolder extends RecyclerView.ViewHolder {
        AddHolder(View v) {
            super(v);
        }
    }

    static final class AppHolder extends RecyclerView.ViewHolder {
        final ImageView icon;
        final TextView name;
        final TextView pkg;
        final TextView menu;
        final View chip;

        AppHolder(View v) {
            super(v);
            icon = v.findViewById(R.id.ivAppIcon);
            name = v.findViewById(R.id.tvAppName);
            pkg = v.findViewById(R.id.tvAppPackage);
            menu = v.findViewById(R.id.btnAppMenu);
            chip = v.findViewById(R.id.chipAction);
        }
    }

    static final class AppEmptyHolder extends RecyclerView.ViewHolder {
        final View action;

        AppEmptyHolder(View v) {
            super(v);
            action = v.findViewById(R.id.btnAppsEmpty);
        }
    }

    static final class AppAddHolder extends RecyclerView.ViewHolder {
        AppAddHolder(View v) {
            super(v);
        }
    }
}
