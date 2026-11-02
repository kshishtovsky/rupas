package ru.rupas.android;

import android.Manifest;
import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.core.content.ContextCompat;

import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;

/**
 * Экран «Перенос настройки» на вкладке настроек: показать QR конфигурации и
 * импортировать его сканированием или вставкой текста.
 *
 * Живёт отдельно от Activity, потому что логика одинакова для любого экрана,
 * а состояние (активность, ядро) приходит параметром.
 */
final class QrUi {

    /** Код запроса разрешения камеры. */
    static final int REQ_CAMERA = 4711;

    private QrUi() {
    }

    /** Экспорт: собрать payload в фоне (prefs + ядро) и показать QR. */
    static void share(Activity act) {
        new Thread(() -> {
            QrPayload.Result r;
            try {
                r = QrPayload.export(act);
            } catch (Throwable t) {
                String msg = message(t);
                act.runOnUiThread(() -> Toast.makeText(act,
                        act.getString(R.string.qr_export_failed, msg), Toast.LENGTH_LONG).show());
                return;
            }
            act.runOnUiThread(() -> showPayload(act, r));
        }, "qr-export").start();
    }

    private static void showPayload(Activity act, QrPayload.Result r) {
        LinearLayout box = new LinearLayout(act);
        box.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (20 * act.getResources().getDisplayMetrics().density);
        box.setPadding(pad, pad, pad, pad);

        TextView summary = new TextView(act);
        summary.setText(r.summary);
        summary.setTextSize(13);
        box.addView(summary);

        if (r.tooBig) {
            // В один QR не влезает — говорим честно и оставляем текст копируемым.
            TextView warn = new TextView(act);
            warn.setText(R.string.qr_too_big);
            warn.setTextSize(12);
            box.addView(warn);

            EditText et = new EditText(act);
            et.setTextIsSelectable(true);
            et.setSingleLine(false);
            et.setText(r.text);
            box.addView(et);
        } else {
            try {
                int target = (int) (280 * act.getResources().getDisplayMetrics().density);
                ImageView iv = new ImageView(act);
                iv.setAdjustViewBounds(true);
                iv.setImageBitmap(QrImage.render(r.text, target));
                box.addView(iv);
            } catch (Throwable t) {
                LogBuffer.add("[qrcode] рендер не удался: " + t);
                Toast.makeText(act, act.getString(R.string.qr_export_failed, message(t)),
                        Toast.LENGTH_LONG).show();
                return;
            }
            TextView hint = new TextView(act);
            hint.setText(R.string.qr_dialog_scan_from_pc);
            hint.setTextSize(12);
            box.addView(hint);
        }

        ScrollView sc = new ScrollView(act);
        sc.addView(box);
        new AlertDialog.Builder(act)
                .setTitle(R.string.qr_dialog_title)
                .setView(sc)
                .setPositiveButton(android.R.string.ok, null)
                .setNeutralButton(R.string.qr_copy, (d, w) -> copy(act, r.text))
                .show();
    }

    private static void copy(Activity act, String payload) {
        ClipboardManager cm = (ClipboardManager) act.getSystemService(Activity.CLIPBOARD_SERVICE);
        if (cm != null) {
            cm.setPrimaryClip(ClipData.newPlainText("rupas-config", payload));
            Toast.makeText(act, R.string.qr_copied, Toast.LENGTH_SHORT).show();
        }
    }

    /** Импорт: камера либо вставка текста (эмулятор, «QR не читается»). */
    static void importDialog(Activity act, Runnable onApplied) {
        new AlertDialog.Builder(act)
                .setTitle(R.string.qr_import_title)
                .setItems(new CharSequence[]{act.getString(R.string.qr_import_scan),
                        act.getString(R.string.qr_import_ok)}, (d, which) -> {
                    if (which == 0) {
                        startScan(act, onApplied);
                    } else {
                        pasteDialog(act, onApplied);
                    }
                })
                .show();
    }

    private static void startScan(Activity act, Runnable onApplied) {
        if (ContextCompat.checkSelfPermission(act, Manifest.permission.CAMERA)
                != PackageManager.PERMISSION_GRANTED) {
            act.requestPermissions(new String[]{Manifest.permission.CAMERA}, REQ_CAMERA);
            return; // продолжение — в onRequestPermissionsResult экрана
        }
        launch(act);
    }

    private static void launch(Activity act) {
        try {
            new IntentIntegrator(act)
                    .setDesiredBarcodeFormats(IntentIntegrator.QR_CODE)
                    .setPrompt(act.getString(R.string.qr_scan_prompt))
                    .setBeepEnabled(false)
                    .setOrientationLocked(false)
                    .initiateScan();
        } catch (Throwable t) {
            LogBuffer.add("[qrcode] сканер недоступен: " + t);
            Toast.makeText(act, R.string.qr_no_camera, Toast.LENGTH_LONG).show();
        }
    }

    /** Результат запроса камеры; true — обработано. */
    static boolean onPermissions(Activity act, int code, int[] results) {
        if (code != REQ_CAMERA) {
            return false;
        }
        if (results.length > 0 && results[0] == PackageManager.PERMISSION_GRANTED) {
            launch(act);
        } else {
            Toast.makeText(act, R.string.qr_no_camera, Toast.LENGTH_LONG).show();
            pasteDialog(act, null);
        }
        return true;
    }

    private static void pasteDialog(Activity act, Runnable onApplied) {
        final EditText input = new EditText(act);
        input.setHint(R.string.qr_import_hint);
        input.setSingleLine(false);
        new AlertDialog.Builder(act)
                .setTitle(R.string.qr_import_title)
                .setView(input)
                .setPositiveButton(R.string.qr_import_ok,
                        (d, w) -> apply(act, input.getText().toString(), onApplied))
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    /** Результат сканера; true — обработано. */
    static boolean onScanResult(Activity act, int req, int res, Intent data, Runnable onApplied) {
        IntentResult scan = IntentIntegrator.parseActivityResult(req, res, data);
        if (scan == null) {
            return false;
        }
        if (scan.getContents() != null) {
            apply(act, scan.getContents(), onApplied);
        }
        return true;
    }

    private static void apply(Activity act, String payload, Runnable onApplied) {
        if (payload == null || payload.trim().isEmpty()) {
            return;
        }
        new Thread(() -> {
            String summary;
            String error = null;
            boolean restarted = false;
            try {
                summary = QrPayload.apply(act, payload).summary;
                // Настройки на лету не применяются: поднятый VPN надо перезапустить,
                // иначе новый конфиг вступит в силу только после ручного OFF/ON.
                restarted = RupasVpnService.restartIfRunning(act);
            } catch (Throwable t) {
                summary = null;
                error = message(t);
            }
            final String fSummary = summary;
            final String fError = error;
            final boolean fRestarted = restarted;
            act.runOnUiThread(() -> {
                if (fError != null) {
                    Toast.makeText(act, act.getString(R.string.qr_import_failed, fError),
                            Toast.LENGTH_LONG).show();
                    return;
                }
                String done = act.getString(R.string.qr_import_done, fSummary == null ? "" : fSummary);
                Toast.makeText(act, fRestarted
                        ? done + " · " + act.getString(R.string.qr_import_restarted) : done,
                        Toast.LENGTH_LONG).show();
                LogBuffer.add("[qrcode] импорт: " + fSummary);
                if (onApplied != null) {
                    onApplied.run(); // экран перечитывает форму из хранилища
                }
            });
        }, "qr-import").start();
    }

    /** Текст исключения без "java.lang." — тосты читает человек. */
    static String message(Throwable t) {
        String m = t == null ? "" : t.getMessage();
        if (m == null || m.trim().isEmpty()) {
            m = t == null ? "неизвестная ошибка" : t.getClass().getSimpleName();
        }
        return m.replace("java.lang.", "");
    }
}
