package ru.rupas.android;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.RecyclerView;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Список приложений на экране выбора (docs/PERAPP_ROUTING.md §4).
 *
 * Справа у каждого — переключатель действия из 4 позиций: «наследует» (правила нет) /
 * DIRECT / TUNNEL / BLOCK. На API < 29 TUNNEL и BLOCK не выбираются: ядро не видит
 * UID потока, доступен только DIRECT (§1, §7.1) — но нажатие объясняет причину,
 * а не молчит.
 */
final class AppPickerAdapter extends RecyclerView.Adapter<AppPickerAdapter.Holder> {

    static final int FILTER_ALL = 0;
    static final int FILTER_RULE = 1;
    static final int FILTER_SYSTEM = 2;

    interface Listener {
        void onActionPicked(AppCatalog.Entry entry, String action);

        /** Нажали на TUNNEL/BLOCK там, где нужен Android 10+. */
        void onLockedAction();
    }

    /** Позиции переключателя: индекс = порядок в макете (§4). */
    private static final String[] ACTIONS = {
            "", AppRule.ACT_DIRECT, AppRule.ACT_TUNNEL, AppRule.ACT_BLOCK
    };

    private final Context ctx;
    private final Listener listener;
    private final List<AppCatalog.Entry> all = new ArrayList<>();
    private final List<AppCatalog.Entry> shown = new ArrayList<>();
    /** Ссылка на карту экрана, а не копия: экран её мутирует, фильтр должен видеть. */
    private Map<String, String> actions = new LinkedHashMap<>();
    private String query = "";
    private int filter = FILTER_ALL;

    AppPickerAdapter(Context ctx, Listener listener) {
        this.ctx = ctx;
        this.listener = listener;
        setHasStableIds(false);
    }

    /**
     * Карта действий живёт на экране (он же её сохраняет), адаптер держит ссылку:
     * копия сделала бы фильтр «С правилом» слепым к только что поставленному правилу.
     */
    void setData(List<AppCatalog.Entry> entries, Map<String, String> actions) {
        all.clear();
        if (entries != null) {
            all.addAll(entries);
        }
        this.actions = actions == null ? new LinkedHashMap<>() : actions;
        rebuild();
    }

    void setQuery(String q) {
        String next = q == null ? "" : q.trim();
        if (next.equals(query)) {
            return;
        }
        query = next;
        rebuild();
    }

    void setFilter(int f) {
        if (f == filter) {
            return;
        }
        filter = f;
        rebuild();
    }

    /** После смены действия: под фильтром «С правилом» строка может исчезнуть. */
    void onActionsChanged() {
        rebuild();
    }

    /** Сколько приложений реально получило правило (для счётчика внизу). */
    static int countWithRule(Map<String, String> map) {
        int n = 0;
        if (map != null) {
            for (String a : map.values()) {
                if (a != null && !a.isEmpty()) {
                    n++;
                }
            }
        }
        return n;
    }

    private void rebuild() {
        shown.clear();
        for (AppCatalog.Entry e : all) {
            if (filter == FILTER_RULE) {
                String a = actions.get(e.pkg);
                if (a == null || a.isEmpty()) {
                    continue;
                }
            } else if (filter == FILTER_SYSTEM && !e.system) {
                continue;
            }
            if (!e.matches(query)) {
                continue;
            }
            shown.add(e);
        }
        notifyDataSetChanged();
    }

    @Override
    public int getItemCount() {
        return shown.size();
    }

    @NonNull
    @Override
    public Holder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        return new Holder(LayoutInflater.from(parent.getContext())
                .inflate(R.layout.item_app_picker, parent, false));
    }

    @Override
    public void onBindViewHolder(@NonNull Holder h, int position) {
        final AppCatalog.Entry e = shown.get(position);
        h.icon.setImageDrawable(e.icon(ctx.getPackageManager()));
        h.name.setText(e.label);
        h.pkg.setText(e.pkg);

        String current = AppRule.normalize(actions.get(e.pkg));
        boolean uidRouting = AppCatalog.supportsUidRouting();
        for (int i = 0; i < ACTIONS.length; i++) {
            final String action = ACTIONS[i];
            final TextView seg = h.segments[i];
            boolean selected = current.equals(action);
            boolean locked = AppRule.needsApi29(action) && !uidRouting;
            paint(seg, selected, locked);
            if (locked) {
                seg.setContentDescription(ctx.getString(R.string.app_picker_a11y_segment_off,
                        seg.getText(), ctx.getString(R.string.routing_apps_need_android10)));
            } else {
                seg.setContentDescription(null);
            }
            seg.setOnClickListener(v -> {
                if (AppRule.needsApi29(action) && !AppCatalog.supportsUidRouting()) {
                    listener.onLockedAction();
                    return;
                }
                listener.onActionPicked(e, action);
            });
        }
    }

    /** Выбранное — accent_soft/accent_deep; недоступное — приглушённая бумага. */
    private void paint(TextView seg, boolean selected, boolean locked) {
        int bg = selected ? R.color.accent_soft
                : (locked ? R.color.paper_3 : R.color.paper_2);
        int fg = selected ? R.color.accent_deep
                : (locked ? R.color.ink_soft : R.color.ink_2);
        if (seg.getBackground() != null) {
            seg.getBackground().mutate().setTint(ContextCompat.getColor(ctx, bg));
        }
        seg.setTextColor(ContextCompat.getColor(ctx, fg));
    }

    static final class Holder extends RecyclerView.ViewHolder {
        final ImageView icon;
        final TextView name;
        final TextView pkg;
        final TextView[] segments;

        Holder(View v) {
            super(v);
            icon = v.findViewById(R.id.ivPickIcon);
            name = v.findViewById(R.id.tvPickName);
            pkg = v.findViewById(R.id.tvPickPackage);
            segments = new TextView[]{
                    v.findViewById(R.id.segInherit),
                    v.findViewById(R.id.segDirect),
                    v.findViewById(R.id.segTunnel),
                    v.findViewById(R.id.segBlock)
            };
        }
    }
}
