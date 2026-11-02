// qr.js — «Поделиться конфигом» и импорт из QR. Логика держится на двух
// глобалах из vendor/: qrcode (qrcode-generator) и jsQR; оба подключены
// классическими скриптами в index.html, чтобы не тащить сборку.
// Полезную нагрузку строит только Go (ExportQR/ImportQR) — здесь её не
// разбирают, поэтому формат живёт в одном месте.

import { ByName as callRaw } from "./vendor/runtime/calls.js";

const FQN = "github.com/kshishtovsky/rupas/internal/guictrl.Controller";
const qrCall = (m, ...a) => callRaw(`${FQN}.${m}`, ...a);

const $id = (id) => document.getElementById(id);

let lastPayload = ""; // для «Скопировать»
let scanStream = null;
let scanTimer = 0;

// drawQR рисует payload в SVG. Целое число пикселей на модуль обязательно:
// при дробном масштабе SVG растеризуется со сглаживанием, и сканер перестаёт
// читать код (замерено: 121 модуль, 370/560/680 px — отказ, 242/363/484 px —
// успех). Поэтому cellSize считается от доступной ширины и задаётся атрибутами
// width/height, а не CSS-растяжением.
function drawQR(text) {
  const box = $id("qrBox");
  box.textContent = "";
  const qr = qrcode(0, "L"); // 0 = версия автоматически, L = самый большой объём
  qr.addData(text, "Byte");
  qr.make();
  const modules = qr.getModuleCount() + 8; // 4 модуля поля с каждой стороны
  const avail = (box.clientWidth || 300) - 2; // минус рамка
  const cell = Math.max(2, Math.floor(avail / modules));
  box.innerHTML = qr.createSvgTag({ cellSize: cell, margin: cell * 4, scalable: false });
}

// Окно растягивается — QR должен расти вместе с ним: крупнее модуль, легче
// считать телефоном.
let resizeTimer = 0;
function onResize() {
  if ($id("qrModal").hidden || !lastPayload) return;
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => drawQR(lastPayload), 150);
}

async function openExport() {
  $id("qrBox").textContent = "Готовлю QR…";
  $id("qrSummary").textContent = "";
  $id("qrTooBig").hidden = true;
  $id("qrModal").hidden = false;
  try {
    const b = await qrCall("ExportQR");
    lastPayload = b.text;
    $id("qrSummary").textContent = b.summary + " · QR " + b.text.length + " симв.";
    if (b.tooBig) {
      // Конфиг больше одного QR: не врём картинкой, которую невозможно считать.
      $id("qrBox").textContent = "";
      $id("qrTooBig").hidden = false;
      $id("qrTooBig").textContent =
        "Конфиг слишком велик для одного QR (" + b.text.length + " симв.). Нажми «Скопировать» и передай текстом.";
    } else {
      drawQR(b.text);
    }
  } catch (e) {
    $id("qrBox").textContent = "";
    $id("qrTooBig").hidden = false;
    $id("qrTooBig").textContent = "⚠ " + (e.message || e);
  }
}

function closeExport() {
  $id("qrModal").hidden = true;
  $id("qrBox").textContent = "";
  lastPayload = "";
}

async function copyPayload() {
  if (!lastPayload) return;
  try {
    await navigator.clipboard.writeText(lastPayload);
    $id("qrSummary").textContent = "Скопировано ✓";
  } catch (e) {
    $id("qrSummary").textContent = "⚠ " + (e.message || e);
  }
}

// ---------- сканирование ----------
function stopScan() {
  if (scanTimer) {
    clearInterval(scanTimer);
    scanTimer = 0;
  }
  if (scanStream) {
    for (const t of scanStream.getTracks()) t.stop();
    scanStream = null;
  }
  $id("scanVideo").srcObject = null;
}

async function openScan() {
  $id("scanModal").hidden = false;
  $id("scanErr").textContent = "";
  $id("scanText").value = "";
  $id("scanHint").hidden = true;
  const video = $id("scanVideo");
  try {
    scanStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: { ideal: "environment" }, width: { ideal: 1280 } },
    });
  } catch (e) {
    // Нет камеры/запрет — падать незачем: текстовое поле уже на экране.
    $id("scanHint").hidden = false;
    $id("scanHint").textContent = "Камера недоступна (" + (e.name || e) + "). Вставь текст из QR ниже.";
    return;
  }
  video.srcObject = scanStream;
  await video.play().catch(() => {});
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  scanTimer = setInterval(() => {
    if (!video.videoWidth) return;
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    ctx.drawImage(video, 0, 0);
    const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const found = jsQR(img.data, img.width, img.height, { inversionAttempts: "dontInvert" });
    if (found && found.data) {
      $id("scanText").value = found.data;
      stopScan();
      applyImport(); // скан сработал — сразу применяем
    }
  }, 200);
}

function closeScan() {
  stopScan();
  $id("scanModal").hidden = true;
  $id("scanErr").textContent = "";
}

async function applyImport() {
  const text = $id("scanText").value.trim();
  if (!text) {
    $id("scanErr").textContent = "Пусто: отсканируй QR или вставь текст.";
    return;
  }
  $id("scanErr").textContent = "Применяю…";
  try {
    const summary = await qrCall("ImportQR", text);
    stopScan();
    $id("scanModal").hidden = true;
    $id("saveHint").textContent = "Импортировано ✓ " + summary;
    // Конфиг заменён целиком: перечитываем состояние, иначе на экране
    // останутся каналы прошлой конфигурации.
    if (typeof window.__rupasReloadSettings === "function") {
      await window.__rupasReloadSettings();
    }
  } catch (e) {
    $id("scanErr").textContent = "⚠ " + (e.message || e);
  }
}

export function initQR() {
  if (typeof qrcode === "undefined" || typeof jsQR === "undefined") {
    // Вендорные скрипты не загрузились — кнопки не показываем, чтобы не
    // обещать функцию, которой нет.
    for (const id of ["btnQrExport", "btnQrImport"]) {
      const el = $id(id);
      if (el) el.disabled = true;
    }
    return;
  }
  $id("btnQrExport").addEventListener("click", openExport);
  window.addEventListener("resize", onResize);
  $id("qrClose").addEventListener("click", closeExport);
  $id("qrCopy").addEventListener("click", copyPayload);
  $id("btnQrImport").addEventListener("click", openScan);
  $id("scanCancel").addEventListener("click", closeScan);
  $id("scanApply").addEventListener("click", applyImport);
}
