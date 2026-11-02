package ru.rupas.android;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.text.InputType;
import android.text.method.PasswordTransformationMethod;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;

/**
 * W3: экран настроек эндпоинта. Секретные поля (uuid, publicKey) маскируются
 * точками, справа — «глаз»-toggle. Кнопка «Импорт vless://» разбирает ссылку
 * и заполняет форму. Сохранение — в SettingsStore (EncryptedSharedPreferences).
 */
public class SettingsActivity extends AppCompatActivity {

    /** Код запроса разрешения камеры (импорт конфига из QR). */
    private static final int REQ_CAMERA = 4711;

    private EditText etUuid;
    private EditText etServer;
    private EditText etPort;
    private EditText etSni;
    private EditText etPublicKey;
    private EditText etShortId;
    private CheckBox cbFallback;
    private CheckBox cbBlockAds;
    private CheckBox cbBlockTrackers;

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
        cbBlockAds = findViewById(R.id.cbBlockAds);
        cbBlockTrackers = findViewById(R.id.cbBlockTrackers);

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
        ((Button) findViewById(R.id.btnShareQr)).setOnClickListener(v -> showQrDialog());
        ((Button) findViewById(R.id.btnScanQr)).setOnClickListener(v -> showQrImportDialog());

        ((TextView) findViewById(R.id.tvVersion))
                .setText(getString(R.string.update_version_current, BuildConfig.VERSION_NAME));
        findViewById(R.id.btnCheckUpdates).setOnClickListener(v -> UpdateChecker.checkManual(this));
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
            cbBlockAds.setChecked(s.blockAds);
            cbBlockTrackers.setChecked(s.blockTrackers);
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
        s.blockAds = cbBlockAds.isChecked();
        s.blockTrackers = cbBlockTrackers.isChecked();
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

    // ----------------------------------------------------------- QR: обмен конфигом

    /**
     * Экспорт: собираем payload и рисуем QR. Сборка идёт в фоне — она читает
     * EncryptedSharedPreferences и зовёт ядро за правилами.
     */
    private void showQrDialog() {
        Toast.makeText(this, R.string.qr_dialog_title, Toast.LENGTH_SHORT).show();
        new Thread(() -> {
            String text;
            String summary;
            boolean tooBig;
            try {
                QrPayload.Result r = QrPayload.export(this);
                text = r.text;
                summary = r.summary;
                tooBig = r.tooBig;
            } catch (Throwable t) {
                final String msg = message(t);
                runOnUiThread(() -> Toast.makeText(this,
                        getString(R.string.qr_export_failed, msg), Toast.LENGTH_LONG).show());
                return;
            }
            runOnUiThread(() -> showQrResult(text, summary, tooBig));
        }, "qr-export").start();
    }

    private void showQrResult(String payload, String summary, boolean tooBig) {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (20 * getResources().getDisplayMetrics().density);
        box.setPadding(pad, pad, pad, pad);

        TextView tvSummary = new TextView(this);
        tvSummary.setText(summary);
        tvSummary.setTextSize(13);
        box.addView(tvSummary);

        if (tooBig) {
            // В один QR не влезает — честно говорим и оставляем текст копируемым.
            TextView warn = new TextView(this);
            warn.setText(R.string.qr_too_big);
            warn.setTextSize(12);
            box.addView(warn);

            EditText et = new EditText(this);
            et.setTextIsSelectable(true);
            et.setText(payload);
            et.setSingleLine(false);
            box.addView(et);
        } else {
            try {
                int target = (int) (280 * getResources().getDisplayMetrics().density);
                ImageView iv = new ImageView(this);
                // Без фильтрации: билинейное растягивание размывает границы модулей.
                iv.setAdjustViewBounds(true);
                iv.setImageBitmap(QrImage.render(payload, target));
                box.addView(iv, new LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT));
            } catch (Throwable t) {
                LogBuffer.add("[qrcode] рендер не удался: " + t);
                Toast.makeText(this, getString(R.string.qr_export_failed, message(t)), Toast.LENGTH_LONG).show();
                return;
            }
            TextView hint = new TextView(this);
            hint.setText(R.string.qr_dialog_scan_from_pc);
            hint.setTextSize(12);
            box.addView(hint);
        }

        ScrollView sc = new ScrollView(this);
        sc.addView(box);
        new AlertDialog.Builder(this)
                .setTitle(R.string.qr_dialog_title)
                .setView(sc)
                .setPositiveButton(android.R.string.ok, null)
                .setNeutralButton(R.string.qr_copy, (d, w) -> copyPayload(payload))
                .show();
    }

    private void copyPayload(String payload) {
        android.content.ClipboardManager cm =
                (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        if (cm != null) {
            cm.setPrimaryClip(android.content.ClipData.newPlainText("rupas-config", payload));
            Toast.makeText(this, R.string.qr_copied, Toast.LENGTH_SHORT).show();
        }
    }

    /** Импорт: камера либо вставка текста (эмулятор и «QR не читается»). */
    private void showQrImportDialog() {
        new AlertDialog.Builder(this)
                .setTitle(R.string.qr_import_title)
                .setItems(new CharSequence[]{getString(R.string.qr_import_scan),
                        getString(R.string.qr_import_ok)}, (d, which) -> {
                    if (which == 0) {
                        startQrScan();
                    } else {
                        showQrPasteDialog();
                    }
                })
                .show();
    }

    private void startQrScan() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA)
                != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.CAMERA}, REQ_CAMERA);
            return;
        }
        launchScanner();
    }

    private void launchScanner() {
        try {
            new IntentIntegrator(this)
                    .setDesiredBarcodeFormats(IntentIntegrator.QR_CODE)
                    .setPrompt(getString(R.string.qr_scan_prompt))
                    .setBeepEnabled(false)
                    .setOrientationLocked(false)
                    .initiateScan();
        } catch (Throwable t) {
            LogBuffer.add("[qrcode] сканер недоступен: " + t);
            Toast.makeText(this, R.string.qr_no_camera, Toast.LENGTH_LONG).show();
            showQrPasteDialog();
        }
    }

    @Override
    public void onRequestPermissionsResult(int code, String[] perms, int[] results) {
        super.onRequestPermissionsResult(code, perms, results);
        if (code != REQ_CAMERA) {
            return;
        }
        if (results.length > 0 && results[0] == PackageManager.PERMISSION_GRANTED) {
            launchScanner();
        } else {
            Toast.makeText(this, R.string.qr_no_camera, Toast.LENGTH_LONG).show();
            showQrPasteDialog();
        }
    }

    private void showQrPasteDialog() {
        final EditText input = new EditText(this);
        input.setHint(R.string.qr_import_hint);
        input.setSingleLine(false);
        new AlertDialog.Builder(this)
                .setTitle(R.string.qr_import_title)
                .setView(input)
                .setPositiveButton(R.string.qr_import_ok, (d, w) -> applyQr(input.getText().toString()))
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    /** Разбор и применение payload; всё в фоне, тост — по результату. */
    private void applyQr(String payload) {
        if (payload == null || payload.trim().isEmpty()) {
            return;
        }
        new Thread(() -> {
            String summary = null;
            String error = null;
            boolean restarted = false;
            try {
                summary = QrPayload.apply(this, payload).summary;
                // Настройки на лету не применяются: если VPN поднят, ядро надо
                // перезапустить, иначе новый конфиг вступит в силу до ручного OFF/ON.
                restarted = RupasVpnService.restartIfRunning(this);
            } catch (Throwable t) {
                error = message(t);
            }
            final String fSummary = summary;
            final String fError = error;
            final boolean fRestarted = restarted;
            runOnUiThread(() -> {
                if (fError != null) {
                    Toast.makeText(this, getString(R.string.qr_import_failed, fError), Toast.LENGTH_LONG).show();
                    return;
                }
                String done = getString(R.string.qr_import_done, fSummary == null ? "" : fSummary);
                Toast.makeText(this, fRestarted ? done + " · " + getString(R.string.qr_import_restarted) : done,
                        Toast.LENGTH_LONG).show();
                LogBuffer.add("[qrcode] импорт: " + fSummary);
                // Форма должна показать то, что теперь в хранилище.
                loadForm();
                finish();
            });
        }, "qr-import").start();
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        IntentResult scan = IntentIntegrator.parseActivityResult(req, res, data);
        if (scan != null) {
            if (scan.getContents() == null) {
                Toast.makeText(this, R.string.qr_import_title, Toast.LENGTH_SHORT).show();
            } else {
                applyQr(scan.getContents());
            }
            return;
        }
        super.onActivityResult(req, res, data);
    }

    /** Текст исключения без "java.lang." — тосты читает человек, а не лог. */
    private static String message(Throwable t) {
        String m = t == null ? "" : t.getMessage();
        if (m == null || m.trim().isEmpty()) {
            m = t == null ? "неизвестная ошибка" : t.getClass().getSimpleName();
        }
        return m.replace("java.lang.", "").replace("java.lang.IllegalArgumentException: ", "");
    }
}
