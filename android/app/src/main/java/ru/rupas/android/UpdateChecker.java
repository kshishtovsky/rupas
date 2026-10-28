package ru.rupas.android;

import android.app.Activity;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.net.Uri;
import android.provider.Settings;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.core.content.FileProvider;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Обновления из публичного GitHub Releases: HttpURLConnection + org.json,
 * без сторонних библиотек. Авто-проверка — не чаще раза в 12 часов,
 * ручная (кнопкой) — всегда.
 *
 * Установка: скачиваем APK во внутренний кэш, сверяем SHA-256 сертификата с
 * установленным приложением (иначе чужой APK ушёл бы в системный установщик)
 * и только потом отдаём файл через FileProvider.
 */
final class UpdateChecker {

    private static final String API =
            "https://api.github.com/repos/kshishtovsky/rupas/releases/latest";
    private static final long THROTTLE_MS = 12L * 60 * 60 * 1000;
    /** Не секрет, поэтому обычные prefs: EncryptedSharedPreferences открывает Keystore. */
    private static final String PREFS = "rupas_updates";
    private static final String K_LAST_CHECK = "lastCheckMs";
    private static final int CHANGELOG_LIMIT = 1000;

    private UpdateChecker() {
    }

    /** Авто-проверка при старте: молчит, если обновления нет или сеть недоступна. */
    static void checkAuto(Activity a) {
        SharedPreferences p = prefs(a);
        long last = p.getLong(K_LAST_CHECK, 0L);
        if (System.currentTimeMillis() - last < THROTTLE_MS) {
            return;
        }
        // Метка ставится до запроса: неудачная попытка тоже не должна долбить сеть.
        p.edit().putLong(K_LAST_CHECK, System.currentTimeMillis()).apply();
        fetch(a, false);
    }

    /** Ручная проверка: троттлинг игнорируется, результат виден всегда. */
    static void checkManual(Activity a) {
        prefs(a).edit().putLong(K_LAST_CHECK, System.currentTimeMillis()).apply();
        fetch(a, true);
    }

    private static SharedPreferences prefs(Context ctx) {
        return ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private static void fetch(Activity a, boolean reportResult) {
        new Thread(() -> {
            JSONObject release;
            try {
                release = latestRelease();
            } catch (IOException | JSONException e) {
                LogBuffer.add("[update] проверка не удалась: " + e);
                if (reportResult) {
                    ui(a, () -> toast(a, R.string.update_check_failed));
                }
                return;
            }
            String tag = release.optString("tag_name", "");
            int[] latest = parseVersion(tag);
            int[] current = parseVersion(BuildConfig.VERSION_NAME);
            if (latest == null || current == null || compare(latest, current) <= 0) {
                // Невалидный tag_name трактуем как «обновления нет»: чужой тег не повод ставить APK.
                LogBuffer.add("[update] обновления нет: текущая " + BuildConfig.VERSION_NAME
                        + ", последний релиз " + tag);
                if (reportResult) {
                    ui(a, () -> Toast.makeText(a,
                            a.getString(R.string.update_latest, BuildConfig.VERSION_NAME),
                            Toast.LENGTH_LONG).show());
                }
                return;
            }
            ui(a, () -> showUpdateDialog(a, release));
        }).start();
    }

    private static void showUpdateDialog(Activity a, JSONObject release) {
        String apkUrl = apkUrl(release);
        String changelog = release.optString("body", "").trim();
        if (changelog.length() > CHANGELOG_LIMIT) {
            changelog = changelog.substring(0, CHANGELOG_LIMIT) + "…";
        }
        if (changelog.isEmpty()) {
            changelog = a.getString(R.string.update_no_changelog);
        }
        new AlertDialog.Builder(a)
                .setTitle(a.getString(R.string.update_title, release.optString("tag_name", "")))
                .setMessage(changelog)
                .setPositiveButton(R.string.update_now, (d, w) -> {
                    if (apkUrl != null) {
                        download(a, apkUrl);
                    } else {
                        // APK в релизе нет — единственный путь ручной: страница релиза.
                        openPage(a, release.optString("html_url", ""));
                    }
                })
                .setNegativeButton(R.string.update_later, null)
                .show();
    }

    /** URL APK-ассета релиза (CI кладёт Rupas-android-<ver>-<abi>.apk) или null. */
    static String apkUrl(JSONObject release) {
        JSONArray assets = release.optJSONArray("assets");
        for (int i = 0; assets != null && i < assets.length(); i++) {
            JSONObject o = assets.optJSONObject(i);
            String name = o == null ? "" : o.optString("name", "");
            if (name.startsWith("Rupas-android-") && name.endsWith(".apk")) {
                return o.optString("browser_download_url", "");
            }
        }
        return null;
    }

    private static void download(Activity a, String url) {
        ProgressDialog pd = new ProgressDialog(a);
        pd.setProgressStyle(ProgressDialog.STYLE_HORIZONTAL);
        pd.setMax(100);
        pd.setCancelable(false);
        pd.setMessage(a.getString(R.string.update_downloading));
        pd.show();
        new Thread(() -> {
            File dir = new File(a.getCacheDir(), "updates");
            File apk = new File(dir, "rupas-update.apk");
            try {
                if (!dir.exists() && !dir.mkdirs()) {
                    throw new IOException("нет каталога " + dir);
                }
                downloadTo(url, apk, a, pd);
            } catch (Exception e) {
                apk.delete();
                LogBuffer.add("[update] загрузка не удалась: " + e);
                ui(a, () -> {
                    pd.dismiss();
                    toast(a, R.string.update_download_failed);
                });
                return;
            }
            try {
                if (!sameSignature(a, apk)) {
                    apk.delete();
                    LogBuffer.add("[update] подпись скачанного APK не совпадает с установленной");
                    ui(a, () -> {
                        pd.dismiss();
                        toast(a, R.string.update_bad_signature);
                    });
                    return;
                }
            } catch (Exception e) {
                apk.delete();
                LogBuffer.add("[update] подпись не прочиталась: " + e);
                ui(a, () -> {
                    pd.dismiss();
                    toast(a, R.string.update_bad_signature);
                });
                return;
            }
            ui(a, () -> {
                pd.dismiss();
                install(a, apk);
            });
        }).start();
    }

    private static void downloadTo(String url, File out, Activity a, ProgressDialog pd)
            throws IOException {
        HttpURLConnection c = open(url);
        try {
            long total = c.getContentLengthLong(); // -1, если сервер не отдал размер
            int shown = -1;
            try (InputStream in = c.getInputStream();
                 FileOutputStream os = new FileOutputStream(out)) {
                byte[] buf = new byte[8192];
                long done = 0;
                int n;
                while ((n = in.read(buf)) > 0) {
                    os.write(buf, 0, n);
                    done += n;
                    int pct = total > 0 ? (int) (done * 100 / total) : 0;
                    if (pct != shown) {
                        shown = pct;
                        ui(a, () -> pd.setProgress(pct));
                    }
                }
            }
        } finally {
            c.disconnect();
        }
    }

    /** SHA-256 сертификата APK из кэша против установленного приложения. */
    private static boolean sameSignature(Context ctx, File apk) throws Exception {
        PackageManager pm = ctx.getPackageManager();
        Signature[] incoming = signers(
                pm.getPackageArchiveInfo(apk.getAbsolutePath(), PackageManager.GET_SIGNING_CERTIFICATES));
        Signature[] installed = signers(
                pm.getPackageInfo(ctx.getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES));
        return incoming != null && installed != null
                && Arrays.equals(digest(incoming), digest(installed));
    }

    @SuppressWarnings("deprecation") // API 26–27 не знает GET_SIGNING_CERTIFICATES
    private static Signature[] signers(PackageInfo pi) {
        if (pi == null) {
            return null;
        }
        return pi.signingInfo != null ? pi.signingInfo.getApkContentsSigners() : pi.signatures;
    }

    private static byte[] digest(Signature[] sigs) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        for (Signature s : sigs) {
            md.update(s.toByteArray());
        }
        return md.digest();
    }

    private static void install(Activity a, File apk) {
        if (!a.getPackageManager().canRequestPackageInstalls()) {
            // Разрешение на установку из этого источника выдаётся только в системных настройках.
            new AlertDialog.Builder(a)
                    .setMessage(R.string.update_need_install_permission)
                    .setPositiveButton(R.string.update_open_settings, (d, w) -> a.startActivity(
                            new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                                    Uri.parse("package:" + a.getPackageName()))))
                    .setNegativeButton(android.R.string.cancel, null)
                    .show();
            return;
        }
        Uri uri = FileProvider.getUriForFile(a, a.getPackageName() + ".fileprovider", apk);
        a.startActivity(new Intent(Intent.ACTION_VIEW)
                .setDataAndType(uri, "application/vnd.android.package-archive")
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION));
    }

    private static void openPage(Activity a, String url) {
        if (url == null || url.isEmpty()) {
            toast(a, R.string.update_no_apk);
            return;
        }
        a.startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
    }

    private static HttpURLConnection open(String url) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setRequestProperty("Accept", "application/vnd.github+json");
        // GitHub без User-Agent отвечает 403.
        c.setRequestProperty("User-Agent", "Rupas-Android/" + BuildConfig.VERSION_NAME);
        c.setConnectTimeout(10000);
        c.setReadTimeout(15000);
        return c;
    }

    private static JSONObject latestRelease() throws IOException, JSONException {
        HttpURLConnection c = open(API);
        try {
            int code = c.getResponseCode();
            if (code != HttpURLConnection.HTTP_OK) {
                throw new IOException("HTTP " + code);
            }
            try (InputStream in = c.getInputStream()) {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) > 0) {
                    bos.write(buf, 0, n);
                }
                return new JSONObject(bos.toString("UTF-8"));
            }
        } finally {
            c.disconnect();
        }
    }

    /** Числовая major.minor.patch из "v1.2.3"; null — тег не semver (обновление не предлагаем). */
    static int[] parseVersion(String tag) {
        if (tag == null) {
            return null;
        }
        String s = tag.trim();
        if (s.startsWith("v") || s.startsWith("V")) {
            s = s.substring(1);
        }
        String[] parts = s.split("\\.");
        if (parts.length == 0 || parts.length > 3) {
            return null;
        }
        int[] out = new int[3];
        try {
            for (int i = 0; i < parts.length; i++) {
                out[i] = Integer.parseInt(parts[i]);
                if (out[i] < 0) {
                    return null;
                }
            }
        } catch (NumberFormatException e) {
            return null;
        }
        return out;
    }

    /** >0, если a новее b. */
    static int compare(int[] a, int[] b) {
        for (int i = 0; i < 3; i++) {
            if (a[i] != b[i]) {
                return a[i] - b[i];
            }
        }
        return 0;
    }

    /** Диалоги и тосты — только на живую активити: сеть ходит в фоновом потоке. */
    private static void ui(Activity a, Runnable r) {
        a.runOnUiThread(() -> {
            if (!a.isFinishing() && !a.isDestroyed()) {
                r.run();
            }
        });
    }

    private static void toast(Activity a, int res) {
        Toast.makeText(a, res, Toast.LENGTH_LONG).show();
    }
}
