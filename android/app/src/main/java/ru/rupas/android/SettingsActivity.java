package ru.rupas.android;

import android.os.Bundle;
import android.text.InputType;
import android.text.method.PasswordTransformationMethod;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

/**
 * W3: экран настроек эндпоинта. Секретные поля (uuid, publicKey) маскируются
 * точками, справа — «глаз»-toggle. Кнопка «Импорт vless://» разбирает ссылку
 * и заполняет форму. Сохранение — в SettingsStore (EncryptedSharedPreferences).
 */
public class SettingsActivity extends AppCompatActivity {

    private EditText etUuid;
    private EditText etServer;
    private EditText etPort;
    private EditText etSni;
    private EditText etPublicKey;
    private EditText etShortId;
    private CheckBox cbFallback;

    private boolean uuidVisible;
    private boolean publicKeyVisible;
    /** Share links from the latest import (dial chain); empty = legacy flat config. */
    private String pendingLinks = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_settings);
        setupInsets();

        etUuid = findViewById(R.id.etUuid);
        etServer = findViewById(R.id.etServer);
        etPort = findViewById(R.id.etPort);
        etSni = findViewById(R.id.etSni);
        etPublicKey = findViewById(R.id.etPublicKey);
        etShortId = findViewById(R.id.etShortId);
        cbFallback = findViewById(R.id.cbFallback);

        Button btnToggleUuid = findViewById(R.id.btnToggleUuid);
        Button btnTogglePbk = findViewById(R.id.btnTogglePbk);
        Button btnImport = findViewById(R.id.btnImport);
        Button btnSave = findViewById(R.id.btnSave);

        applySecretMask(etUuid, false);
        applySecretMask(etPublicKey, false);
        btnToggleUuid.setOnClickListener(v -> {
            uuidVisible = !uuidVisible;
            applySecretMask(etUuid, uuidVisible);
            btnToggleUuid.setText(uuidVisible ? R.string.eye_open : R.string.eye_closed);
        });
        btnTogglePbk.setOnClickListener(v -> {
            publicKeyVisible = !publicKeyVisible;
            applySecretMask(etPublicKey, publicKeyVisible);
            btnTogglePbk.setText(publicKeyVisible ? R.string.eye_open : R.string.eye_closed);
        });

        loadForm();

        btnImport.setOnClickListener(v -> showImportDialog());
        btnSave.setOnClickListener(v -> saveForm());
    }

    /**
     * Edge-to-edge принудителен на Android 15+ (targetSdk 36): без верхнего инсета
     * заголовок «Настройки» уезжает под статус-бар. Инсет отдаём корню-ScrollView
     * (clipToPadding=false в макете), чтобы содержимое не резалось на прокрутке,
     * а фон под полосами оставался @color/paper.
     */
    private void setupInsets() {
        final View root = findViewById(R.id.settingsRoot);
        final int padTop = root.getPaddingTop();
        final int padBottom = root.getPaddingBottom();
        ViewCompat.setOnApplyWindowInsetsListener(root, (v, insets) -> {
            androidx.core.graphics.Insets bars =
                    insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(v.getPaddingLeft(), padTop + Math.max(bars.top, 0),
                    v.getPaddingRight(), padBottom + Math.max(bars.bottom, 0));
            return insets;
        });
        ViewCompat.requestApplyInsets(root);
    }

    private void applySecretMask(EditText et, boolean visible) {
        if (visible) {
            et.setTransformationMethod(null);
            et.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD);
        } else {
            et.setTransformationMethod(PasswordTransformationMethod.getInstance());
            et.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        }
        et.setSelection(et.getText() == null ? 0 : et.getText().length());
    }

    private void loadForm() {
        try {
            SettingsStore.Settings s = new SettingsStore(this).load();
            etUuid.setText(s.uuid);
            etServer.setText(s.server);
            etPort.setText(s.port > 0 ? String.valueOf(s.port) : "");
            etSni.setText(s.sni);
            etPublicKey.setText(s.publicKey);
            etShortId.setText(s.shortId);
            cbFallback.setChecked(s.fallback);
            pendingLinks = s.links == null ? "" : s.links;
        } catch (Exception e) {
            Toast.makeText(this, getString(R.string.settings_load_failed), Toast.LENGTH_LONG).show();
        }
    }

    private void showImportDialog() {
        final EditText input = new EditText(this);
        input.setHint(R.string.import_hint);
        input.setSingleLine(false);
        new AlertDialog.Builder(this)
                .setTitle(R.string.import_title)
                .setView(input)
                .setPositiveButton(R.string.import_ok, (d, w) -> applyImport(input))
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private void applyImport(EditText input) {
        java.util.List<String> links;
        ParseLink.Flat r;
        try {
            links = ParseLink.splitInput(input.getText().toString());
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
        cbFallback.setChecked(true);
        if (r.warning != null) {
            Toast.makeText(this, getString(R.string.import_warning, r.warning), Toast.LENGTH_LONG).show();
        } else {
            Toast.makeText(this, R.string.import_done, Toast.LENGTH_SHORT).show();
        }
    }

    private void saveForm() {
        SettingsStore.Settings s = new SettingsStore.Settings();
        s.uuid = text(etUuid);
        s.server = text(etServer);
        s.sni = text(etSni);
        s.publicKey = text(etPublicKey);
        s.shortId = text(etShortId);
        s.fallback = cbFallback.isChecked();
        s.links = pendingLinks;
        String portStr = text(etPort);
        if (portStr.isEmpty()) {
            s.port = 0;
        } else {
            try {
                s.port = Integer.parseInt(portStr);
            } catch (NumberFormatException e) {
                Toast.makeText(this, R.string.settings_bad_port, Toast.LENGTH_LONG).show();
                return;
            }
        }
        // Частичная форма без uuid/server — считаем «туннель off»; это валидно.
        if (s.isConfigured() || (s.uuid.isEmpty() && s.server.isEmpty())) {
            try {
                new SettingsStore(this).save(s);
            } catch (Exception e) {
                Toast.makeText(this, getString(R.string.settings_save_failed), Toast.LENGTH_LONG).show();
                return;
            }
            LogBuffer.add("[settings] сохранено: tunnel "
                    + (s.isConfigured() ? "on (server " + s.server + ")" : "off"));
            // Настройки на лету не применяются — если VPN поднят, переподнимаем
            // ядро, иначе новый endpoint не вступит в силу до ручного OFF/ON.
            if (RupasVpnService.restartIfRunning(this)) {
                LogBuffer.add("[settings] VPN поднят — перезапускаю ядро с новыми настройками");
            }
            Toast.makeText(this, R.string.settings_saved, Toast.LENGTH_SHORT).show();
            finish();
        } else {
            Toast.makeText(this, R.string.settings_incomplete, Toast.LENGTH_LONG).show();
        }
    }

    private static String text(EditText et) {
        return et.getText() == null ? "" : et.getText().toString().trim();
    }
}
