package ru.rupas.android;

import android.view.View;
import android.widget.TextView;

import androidx.core.content.ContextCompat;

/**
 * Цвета действий (§5.3) и общая отрисовка чипа действия.
 * Цвета берутся только из res/values/colors.xml — литералов здесь нет.
 */
final class RoutingStyle {

    static final String[] ACTIONS = {
            RoutingRule.ACT_DIRECT,
            RoutingRule.ACT_TUNNEL,
            RoutingRule.ACT_DESYNC,
            RoutingRule.ACT_BLOCK
    };

    private RoutingStyle() {
    }

    static int backgroundRes(String action) {
        switch (normalize(action)) {
            case RoutingRule.ACT_TUNNEL:
                return R.color.accent_tint;
            case RoutingRule.ACT_DESYNC:
                return R.color.warn_soft;
            case RoutingRule.ACT_BLOCK:
                return R.color.danger_soft;
            case RoutingRule.ACT_DIRECT:
            default:
                return R.color.paper_3;
        }
    }

    static int textRes(String action) {
        switch (normalize(action)) {
            case RoutingRule.ACT_TUNNEL:
                return R.color.accent_deep;
            case RoutingRule.ACT_DESYNC:
                return R.color.warn;
            case RoutingRule.ACT_BLOCK:
                return R.color.danger;
            case RoutingRule.ACT_DIRECT:
            default:
                return R.color.ink;
        }
    }

    static int labelRes(String action) {
        switch (normalize(action)) {
            case RoutingRule.ACT_TUNNEL:
                return R.string.action_tunnel;
            case RoutingRule.ACT_DESYNC:
                return R.string.action_desync;
            case RoutingRule.ACT_BLOCK:
                return R.string.action_block;
            case RoutingRule.ACT_DIRECT:
            default:
                return R.string.action_direct;
        }
    }

    /** Подпись смысла действия в редакторе (§9). */
    static int hintRes(String action) {
        switch (normalize(action)) {
            case RoutingRule.ACT_TUNNEL:
                return R.string.action_tunnel_hint;
            case RoutingRule.ACT_DESYNC:
                return R.string.action_desync_hint;
            case RoutingRule.ACT_BLOCK:
                return R.string.action_block_hint;
            case RoutingRule.ACT_DIRECT:
            default:
                return R.string.action_direct_hint;
        }
    }

    static String normalize(String action) {
        String a = action == null ? "" : action.trim().toUpperCase(java.util.Locale.ROOT);
        switch (a) {
            case RoutingRule.ACT_TUNNEL:
            case RoutingRule.ACT_DESYNC:
            case RoutingRule.ACT_BLOCK:
            case RoutingRule.ACT_DIRECT:
                return a;
            default:
                return RoutingRule.ACT_DIRECT;
        }
    }

    /**
     * Чип действия: фон, текст и точка — по таблице §5.3.
     * Чип остаётся текстом (никаких иконок вместо действия), точка только акцент.
     */
    static void applyChip(View chipRoot, String action) {
        if (chipRoot == null) {
            return;
        }
        View dot = chipRoot.findViewById(R.id.dotAction);
        TextView label = chipRoot.findViewById(R.id.tvAction);
        int bg = ContextCompat.getColor(chipRoot.getContext(), backgroundRes(action));
        int fg = ContextCompat.getColor(chipRoot.getContext(), textRes(action));
        if (chipRoot.getBackground() != null) {
            chipRoot.getBackground().mutate().setTint(bg);
        }
        if (dot != null && dot.getBackground() != null) {
            dot.getBackground().mutate().setTint(fg);
        }
        if (label != null) {
            label.setText(labelRes(action));
            label.setTextColor(fg);
        }
        chipRoot.setContentDescription(chipRoot.getContext().getString(labelRes(action)));
    }

}
