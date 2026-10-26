package ru.rupas.android;

import android.content.Context;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.view.WindowManager;
import android.widget.TextView;

import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.google.android.material.bottomsheet.BottomSheetDialog;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.chip.ChipGroup;
import com.google.android.material.textfield.TextInputEditText;
import com.google.android.material.textfield.TextInputLayout;

import java.util.List;
import java.util.Locale;

/**
 * Редактор правила (§5.4, Android): BottomSheetDialog.
 *
 * Вид правила — взаимоисключающий селектор (одно правило = ровно один матчер),
 * протокол — 3 сегмента, действие — 4 сегмента с фиксированными цветами (§5.3).
 *
 * Валидация клиентская и до сохранения: пусто, кривой CIDR, кривой порт/диапазон,
 * пересечение портов с существующим правилом (с именем конфликтующего правила).
 */
final class RuleEditorSheet extends BottomSheetDialog {

    interface OnSave {
        void onSave(RoutingRule rule, int editIndex);
    }

    private static final String[] PROTO_VALUES = {"", "tcp", "udp"};

    private final List<RoutingRule> existing;
    private final int editIndex;
    private final boolean defaultMode;
    private final OnSave callback;

    private final ChipGroup kindGroup;
    private final View groupKind;
    private final View groupProto;
    private final TextInputLayout tilValue;
    private final TextInputEditText etValue;
    private final TextView tvError;
    private final TextView tvQuicNote;
    private final TextView tvActionHint;
    private final View[] protoSegs;
    private final View[] actionSegs;

    private String protoValue = "";
    private String action = RoutingRule.ACT_DIRECT;
    private boolean ready;

    RuleEditorSheet(Context ctx, List<RoutingRule> existing, int editIndex, RoutingRule initial,
                    int stage, boolean defaultMode, OnSave callback) {
        super(ctx);
        this.existing = existing;
        this.editIndex = editIndex;
        this.defaultMode = defaultMode;
        this.callback = callback;

        setContentView(R.layout.rule_editor);

        kindGroup = findViewById(R.id.groupKindChips);
        groupKind = findViewById(R.id.groupKind);
        groupProto = findViewById(R.id.groupProto);
        tilValue = findViewById(R.id.tilValue);
        etValue = findViewById(R.id.etValue);
        tvError = findViewById(R.id.tvEditorError);
        tvQuicNote = findViewById(R.id.tvQuicNote);
        tvActionHint = findViewById(R.id.tvActionHint);
        MaterialButton save = findViewById(R.id.btnEditorSave);
        TextView title = findViewById(R.id.tvEditorTitle);

        protoSegs = new View[]{
                findViewById(R.id.segProtoAny),
                findViewById(R.id.segProtoTcp),
                findViewById(R.id.segProtoUdp)
        };
        actionSegs = new View[]{
                findViewById(R.id.segActionDirect),
                findViewById(R.id.segActionTunnel),
                findViewById(R.id.segActionDesync),
                findViewById(R.id.segActionBlock)
        };

        String kind = initial != null ? initial.kind : kindForStage(stage);
        String value = initial != null ? initial.value : "";
        protoValue = initial != null ? RoutingRule.normalizeProto(initial.proto) : "";
        action = initial != null ? RoutingRule.normalizeAction(initial.action) : RoutingRule.ACT_DIRECT;

        if (defaultMode) {
            title.setText(R.string.editor_default_action);
            groupKind.setVisibility(View.GONE);
            groupProto.setVisibility(View.GONE);
            tilValue.setVisibility(View.GONE);
        } else {
            title.setText(editIndex >= 0 ? R.string.editor_edit_rule : R.string.editor_new_rule);
            if (!value.isEmpty()) {
                etValue.setText(value);
                etValue.setSelection(etValue.getText() == null ? 0 : etValue.getText().length());
            }
            kindGroup.check(chipForKind(kind));
            updateHint(kind);
        }

        selectProto(protoValue);
        selectAction(action);

        kindGroup.setOnCheckedStateChangeListener((group, checkedIds) -> {
            if (!ready) {
                return;
            }
            updateHint(currentKind());
            clearError();
            updateQuicNote();
        });
        for (int i = 0; i < protoSegs.length; i++) {
            final int index = i;
            protoSegs[i].setOnClickListener(v -> {
                selectProto(PROTO_VALUES[index]);
                clearError();
                updateQuicNote();
            });
        }
        for (int i = 0; i < actionSegs.length; i++) {
            final String value2 = RoutingStyle.ACTIONS[i];
            actionSegs[i].setOnClickListener(v -> selectAction(value2));
        }
        etValue.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            @Override
            public void afterTextChanged(Editable s) {
                clearError();
            }
        });

        save.setOnClickListener(v -> submit());
        ready = true;
    }

    @Override
    public void show() {
        super.show();
        View sheet = findViewById(com.google.android.material.R.id.design_bottom_sheet);
        if (sheet != null) {
            BottomSheetBehavior<View> behavior = BottomSheetBehavior.from(sheet);
            behavior.setState(BottomSheetBehavior.STATE_EXPANDED);
            behavior.setSkipCollapsed(true);
        }
        if (getWindow() != null) {
            getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);
        }
        if (!defaultMode && etValue != null) {
            etValue.requestFocus();
        }
    }

    // ------------------------------------------------------------------- state

    private static String kindForStage(int stage) {
        switch (stage) {
            case RoutingRule.STAGE_DOMAINS:
                return RoutingRule.KIND_SNI;
            case RoutingRule.STAGE_PORTS:
                return RoutingRule.KIND_PORTS;
            case RoutingRule.STAGE_IP:
            default:
                return RoutingRule.KIND_CIDR;
        }
    }

    private static int chipForKind(String kind) {
        switch (kind == null ? "" : kind) {
            case RoutingRule.KIND_GEOIP:
                return R.id.chipKindCountry;
            case RoutingRule.KIND_SNI:
                return R.id.chipKindDomain;
            case RoutingRule.KIND_PORTS:
                return R.id.chipKindPort;
            case RoutingRule.KIND_CIDR:
            default:
                return R.id.chipKindIp;
        }
    }

    private String currentKind() {
        if (defaultMode) {
            return "";
        }
        int id = kindGroup.getCheckedChipId();
        if (id == R.id.chipKindCountry) {
            return RoutingRule.KIND_GEOIP;
        }
        if (id == R.id.chipKindDomain) {
            return RoutingRule.KIND_SNI;
        }
        if (id == R.id.chipKindPort) {
            return RoutingRule.KIND_PORTS;
        }
        return RoutingRule.KIND_CIDR;
    }

    private void updateHint(String kind) {
        switch (kind == null ? "" : kind) {
            case RoutingRule.KIND_GEOIP:
                tilValue.setHint(R.string.editor_hint_country);
                break;
            case RoutingRule.KIND_SNI:
                tilValue.setHint(R.string.editor_hint_domain);
                break;
            case RoutingRule.KIND_PORTS:
                tilValue.setHint(R.string.editor_hint_port);
                break;
            case RoutingRule.KIND_CIDR:
            default:
                tilValue.setHint(R.string.editor_hint_ip);
                break;
        }
        updateQuicNote();
    }

    private void selectProto(String proto) {
        protoValue = RoutingRule.normalizeProto(proto);
        int index = 0;
        for (int i = 0; i < PROTO_VALUES.length; i++) {
            if (PROTO_VALUES[i].equals(protoValue)) {
                index = i;
            }
        }
        for (int i = 0; i < protoSegs.length; i++) {
            protoSegs[i].setSelected(i == index);
        }
        updateQuicNote();
    }

    private void selectAction(String value) {
        action = RoutingRule.normalizeAction(value);
        int index = 0;
        for (int i = 0; i < RoutingStyle.ACTIONS.length; i++) {
            if (RoutingStyle.ACTIONS[i].equals(action)) {
                index = i;
            }
        }
        for (int i = 0; i < actionSegs.length; i++) {
            actionSegs[i].setSelected(i == index);
        }
        tvActionHint.setText(RoutingStyle.hintRes(action));
    }

    /** Порт без протокола действует и на tcp, и на udp — про QUIC говорим вслух. */
    private void updateQuicNote() {
        boolean show = RoutingRule.KIND_PORTS.equals(currentKind()) && protoValue.isEmpty();
        tvQuicNote.setVisibility(show ? View.VISIBLE : View.GONE);
    }

    private void showError(String text) {
        tvError.setText(text);
        tvError.setVisibility(View.VISIBLE);
    }

    private void clearError() {
        if (tvError.getVisibility() == View.VISIBLE) {
            tvError.setVisibility(View.GONE);
        }
    }

    // ------------------------------------------------------------------ submit

    private void submit() {
        if (defaultMode) {
            RoutingRule def = RoutingRule.Parsed.defaultRule();
            def.action = action;
            callback.onSave(def, -1);
            dismiss();
            return;
        }

        String kind = currentKind();
        String value = etValue.getText() == null ? "" : etValue.getText().toString().trim();

        int errorRes = RoutingRule.validateValue(kind, value);
        if (errorRes != 0) {
            showError(getContext().getString(errorRes));
            return;
        }

        if (RoutingRule.KIND_PORTS.equals(kind)) {
            RoutingRule conflict = RoutingRule.findPortConflict(existing, editIndex, value, protoValue);
            if (conflict != null) {
                String span = RoutingRule.overlapSpan(conflict.value, value);
                showError(getContext().getString(R.string.editor_conflict,
                        conflict.matcher(), span == null ? conflict.value : span));
                return;
            }
            value = value.replaceAll("\\s+", "");
        } else if (RoutingRule.KIND_GEOIP.equals(kind) || RoutingRule.KIND_SNI.equals(kind)) {
            value = value.toLowerCase(Locale.ROOT);
        }

        callback.onSave(new RoutingRule(kind, value, protoValue, action), editIndex);
        dismiss();
    }
}
