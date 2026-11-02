// Проверка связки qrcode-generator -> jsQR без камеры: собираем матрицу,
// растеризуем её в RGBA (как это делает экран), декодируем обратно.
// Запуск: node cmd/rupas-gui/frontend/dist/qrtest.js <payload-file>
const fs = require("fs");
const qrcode = require("./vendor/qrcode/qrcode.js");
const jsQR = require("./vendor/jsqr/jsQR.js");

const text = fs.readFileSync(process.argv[2], "utf8").trim();
const cell = 4, margin = 4;
const qr = qrcode(0, "L");
qr.addData(text, "Byte");
qr.make();
const n = qr.getModuleCount();
const size = (n + margin * 2) * cell;
const px = new Uint8ClampedArray(size * size * 4).fill(255);
for (let y = 0; y < n; y++) {
  for (let x = 0; x < n; x++) {
    if (!qr.isDark(y, x)) continue;
    for (let dy = 0; dy < cell; dy++) {
      for (let dx = 0; dx < cell; dx++) {
        const o = (((y + margin) * cell + dy) * size + (x + margin) * cell + dx) * 4;
        px[o] = px[o + 1] = px[o + 2] = 0;
      }
    }
  }
}
const got = jsQR(px, size, size);
if (!got) { console.error("FAIL: jsQR не нашёл QR"); process.exit(1); }
if (got.data !== text) { console.error("FAIL: текст не совпал", got.data.length, text.length); process.exit(1); }
console.log(`OK: ${text.length} символов, QR ${n}x${n} модулей, растр ${size}x${size}`);
