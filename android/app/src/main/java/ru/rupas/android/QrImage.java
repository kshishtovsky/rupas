package ru.rupas.android;

import android.graphics.Bitmap;
import android.graphics.Color;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

import java.util.EnumMap;
import java.util.Map;

/**
 * Растр QR для показа на экране.
 *
 * Масштаб — целое число пикселей на модуль. Дробный масштаб (растянуть
 * получившийся Bitmap на всю ширину) заставляет сглаживать края модулей, и
 * сканер на втором устройстве ломается на неровных границах: на десктопной
 * версии это замерено — при 121 модуле и ширине 370/560/680 px (дробно)
 * jsQR код не находил, при 242/363/484 px (целые px) находил. Поэтому
 * картинка получается чуть уже контейнера, но читается всегда.
 */
final class QrImage {

    /** Тихие поля в модулях: без них сканер не находит угловые маркеры. */
    private static final int MARGIN = 2;

    private QrImage() {
    }

    static Bitmap render(String text, int maxPx) throws WriterException {
        Map<EncodeHintType, Object> hints = new EnumMap<>(EncodeHintType.class);
        hints.put(EncodeHintType.CHARACTER_SET, "UTF-8");
        hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.L);
        hints.put(EncodeHintType.MARGIN, MARGIN);
        // 0x0 → матрица естественного размера, масштабируем сами.
        BitMatrix m = new QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0, hints);
        int modules = Math.max(m.getWidth(), m.getHeight());
        int scale = Math.max(1, maxPx / modules);
        int size = modules * scale;
        int[] px = new int[size * size];
        for (int y = 0; y < size; y++) {
            int row = y / scale;
            for (int x = 0; x < size; x++) {
                px[y * size + x] = m.get(x / scale, row) ? Color.BLACK : Color.WHITE;
            }
        }
        Bitmap bmp = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888);
        bmp.setPixels(px, 0, size, 0, 0, size, size);
        return bmp;
    }
}
