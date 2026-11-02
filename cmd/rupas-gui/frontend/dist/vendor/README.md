# Vendored frontend libraries (no build step, no network at runtime)

| dir | file | version | license | used for |
|---|---|---|---|---|
| `qrcode/` | `qrcode.js` | [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) 1.4.4 | MIT | отрисовка QR конфига (`qrcode(0,'L')`, SVG) |
| `jsqr/` | `jsQR.js` | [jsQR](https://github.com/cozmo/jsQR) 1.4.0 | Apache-2.0 | декодирование QR с камеры (`jsQR(data,w,h)`) |

Both are UMD bundles loaded as classic scripts in `index.html` before
`app.js`; they publish the globals `qrcode` and `jsQR`. Replacing them means
keeping those globals.
