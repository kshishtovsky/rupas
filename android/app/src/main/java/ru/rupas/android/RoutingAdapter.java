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
 * заголовок стадии → правила → «+ Правило», в конце закреплённый default.
 *
 * Три обязательных типа строк: stage header, rule row, default row;
 * четвёртый — строка добавления внутри стадии (в макете §4.2 «[+ Правило]»).
 */
final class RoutingAdapter extends RecyclerView.Adapter<RecyclerView.ViewHolder> {

    static final int T_STAGE = 0;
    static final int T_RULE = 1;
    static final int T_DEFAULT = 2;
    static final int T_ADD = 3;

    interface Listener {
        void onRuleClick(RoutingRule rule, int index);

        void onRuleMenu(View anchor, RoutingRule rule, int index);

        void onStageToggle(int stage);

        void onAddRule(int stage);

        void onDefaultClick();
    }

    private static final class Row {
        int type;
        int stage;
        RoutingRule rule;
        int index;
        int posInStage;
        int stageTotal;
        int count;
        boolean collapsed;
    }

    private final Context ctx;
    private final Listener listener;
    private final List<Row> rows = new ArrayList<>();
    private final List<RoutingRule> rules = new ArrayList<>();
    private final boolean[] collapsed = new boolean[3];
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
        Row d = new Row();
        d.type = T_DEFAULT;
        rows.add(d);
        notifyDataSetChanged();
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
            default:
                return new AddHolder(inf.inflate(R.layout.item_add_rule, parent, false));
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

    static int stageNameRes(int stage) {
        switch (stage) {
            case RoutingRule.STAGE_IP:
                return R.string.routing_stage_ip;
            case RoutingRule.STAGE_DOMAINS:
                return R.string.routing_stage_domains;
            case RoutingRule.STAGE_PORTS:
                return R.string.routing_stage_ports;
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
}
