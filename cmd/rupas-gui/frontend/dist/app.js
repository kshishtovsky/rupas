// Rupas GUI — frontend logic (no build step: plain ES module).
// Talks to the Go service via the vendored @wailsio/runtime (offline).
import { ByName as callRaw } from "./vendor/runtime/calls.js";
import { On } from "./vendor/runtime/events.js";
import Window from "./vendor/runtime/window.js";
import "./vendor/runtime/drag.js"; // side-effect: installs --wails-draggable handlers

const $ = (id) => document.getElementById(id);
const FQN = "github.com/rupas/rupas/internal/guictrl.Controller";
const call = (method, ...args) => callRaw(`${FQN}.${method}`, ...args);

// ---------- state ----------
let snap = { online: false, state: "" };

// ---------- UI-state mapping (GUI_DESIGN §7) ----------
function uiState(s) {
  if (!s.online) return "off";
  switch (s.state) {
    case "ACTIVE":
    case "ACTIVE_TUNNEL_ONLY": return "on";
    case "PROBING": return "connecting";
    case "DEGRADED": return "error";
    default: return "off";
  }
}
const CAPTIONS = {
  off: "Отключено",
  connecting: "Подключаюсь…",
  on: "Работает",
  error: "Сбой",
};

function fmtRate(bps) {
  if (bps > 1024 * 1024) return (bps / 1024 ** 2).toFixed(1) + " МБ/с";
  if (bps > 1024) return (bps / 1024).toFixed(1).replace(".", ",") + " КБ/с";
  return Math.round(bps) + " Б/с";
}

function fmtSession(sec) {
  if (!sec || sec < 0) sec = 0;
  const h = String(Math.floor(sec / 3600)).padStart(2, "0");
  const m = String(Math.floor((sec % 3600) / 60)).padStart(2, "0");
  const s = String(sec % 60).padStart(2, "0");
  return `${h}:${m}:${s}`;
}

function render(s) {
  snap = s;
  const st = uiState(s);
  const disc = $("powerDisc");
  disc.className = "power-disc " + (st === "off" ? "" : st);
  $("powerCaption").textContent =
    s.online && s.state === "ACTIVE_TUNNEL_ONLY" ? "Работает (только туннель)" : CAPTIONS[st];
  $("powerSub").textContent = st === "error" ? "Нажмите, чтобы переподключить" : "";
  $("sessionTime").textContent =
    s.online && (s.state === "ACTIVE" || s.state === "ACTIVE_TUNNEL_ONLY")
      ? "Сессия " + fmtSession(s.sessionSec) : "";
  const dot = $("dot");
  dot.className = "status-dot " + (st === "off" ? "" : st);
  $("dotText").textContent = CAPTIONS[st];
  // telemetry cards (Android W3 home parity)
  $("cardDown").textContent = s.online ? fmtRate(s.rxRate || 0) : "—";
  $("cardUp").textContent = s.online ? fmtRate(s.txRate || 0) : "—";
  $("cardGateway").innerHTML = !s.online
    ? "—"
    : s.gateway
      ? s.gateway
      : '<span class="chip">напрямую</span>';
  const flows = s.tcpFlows || 0;
  $("cardFlows").textContent = !s.online ? "—" : `${flows} TCP`;
  $("cardHealth").innerHTML = !s.online
    ? "—"
    : s.healthFails > 0
      ? `<span class="chip warn">Сбоев: ${s.healthFails}</span>`
      : '<span class="chip accent">Потерь нет</span>';
}

// ---------- custom caption buttons (frameless window) ----------
$("btnMinimize").addEventListener("click", () => { try { Window.Minimise(); } catch (_) {} });
$("btnClose").addEventListener("click", () => { try { Window.Hide(); } catch (_) {} }); // close = to tray

// ---------- power button ----------
$("powerDisc").addEventListener("click", async () => {
  const st = uiState(snap);
  try {
    if (st === "on") { await call("Off"); }
    else {
      await call("EnsureDaemon");
      await call("On");
    }
  } catch (e) { alert("Ошибка: " + (e.message || e)); }
  refreshSoon();
});

async function refreshSoon() { setTimeout(() => call("Status").then(render), 400); }

// ---------- nav ----------
function showPage(name) {
  document.querySelectorAll(".nav-item").forEach((x) => x.classList.toggle("active", x.dataset.page === name));
  document.querySelectorAll(".page").forEach((x) => x.classList.toggle("active", x.id === "page-" + name));
  if (name === "logs") { loadLogs(); logsTimer = setInterval(loadLogs, 2000); }
  else { clearInterval(logsTimer); logsTimer = null; }
  if (name === "settings") { loadSettings(); rtEnter(); }   // the settings entry shows the rule summary
  if (name === "routing") rtEnter();
}
document.querySelectorAll(".nav-item").forEach((b) => b.addEventListener("click", () => showPage(b.dataset.page)));
let logsTimer = null;

// ---------- logs ----------
async function loadLogs() {
  try {
    const lines = await call("Logs");
    const box = $("logBox");
    box.innerHTML = "";
    if (!lines || !lines.length) {
      box.innerHTML = '<div class="log-empty">Пусто. Включите Rupas.</div>';
    } else {
      for (const l of lines.slice(-300)) {
        const d = document.createElement("div");
        d.className = "log-line";
        d.textContent = l;
        if (l.includes("verdict=")) d.classList.add("hl");
        box.appendChild(d);
      }
      box.scrollTop = box.scrollHeight;
    }
    $("chipLogsCount").textContent = lines ? lines.length : 0;
  } catch (e) {
    $("logBox").innerHTML = '<div class="log-empty">Демон недоступен</div>';
  }
}
$("btnLogsRefresh").addEventListener("click", loadLogs);
$("btnLogsCopy").addEventListener("click", async () => {
  const lines = await call("Logs").catch(() => []);
  await navigator.clipboard.writeText((lines || []).join("\n"));
  $("btnLogsCopy").textContent = "Скопировано";
  setTimeout(() => ($("btnLogsCopy").textContent = "Копировать"), 1200);
});

// ---------- settings: links + channel priorities (Android W3 parity) ----------
let channels = [];
let linksInitialized = false; // populate from storage once; never clobber unsaved edits

async function loadSettings() {
  try {
    const st = await call("LoadState");
    if (!linksInitialized) {
      $("setLinks").value = st.links || "";
      $("setDpi").checked = st.dpi !== false;
      linksInitialized = true;
    }
    $("setAutostart").checked = !!st.autostart;
    await parseLinks(); // re-render the channel list from the CURRENT textarea
  } catch (_) {}
}

async function parseLinks() {
  const blob = $("setLinks").value.trim();
  if (!blob) {
    channels = [];
    $("channelsSection").style.display = "none";
    $("linksHint").textContent = "";
    return;
  }
  try {
    channels = await call("ParseChannels", blob);
    $("linksHint").textContent = "";
  } catch (e) {
    channels = [];
    $("linksHint").textContent = "⚠ " + (e.message || e);
  }
  renderChannels();
}

function renderChannels() {
  const sec = $("channelsSection");
  const list = $("channelList");
  list.innerHTML = "";
  if (!channels.length) { sec.style.display = "none"; return; }
  sec.style.display = "block";
  channels.forEach((ch, i) => {
    const row = document.createElement("div");
    row.className = "channel-row";
    const roleChip =
      ch.role === "unsupported"
        ? `<span class="chip danger">${ch.kind}</span>`
        : `<span class="chip accent">${ch.kind} → ${ch.role === "tcp" ? "основной" : ch.role === "udp" ? "голос/UDP" : "резерв"}</span>`;
    const warn = ch.warning ? `<div class="hint" style="color:var(--warn)">⚠ ${ch.warning}</div>` : "";
    row.innerHTML = `
      <div class="ch-info">
        <div class="ch-name">${ch.name}</div>
        ${roleChip}${warn}
      </div>
      <div class="ch-btns">
        <button class="cap-btn" data-act="up" title="Поднять" ${i === 0 ? "disabled" : ""}>
          <svg viewBox="0 0 12 12"><path d="M2 8l4-4 4 4"/></svg>
        </button>
        <button class="cap-btn" data-act="down" title="Опустить" ${i === channels.length - 1 ? "disabled" : ""}>
          <svg viewBox="0 0 12 12"><path d="M2 4l4 4 4-4"/></svg>
        </button>
      </div>`;
    row.querySelectorAll("button[data-act]").forEach((b) =>
      b.addEventListener("click", () => {
        const j = b.dataset.act === "up" ? i - 1 : i + 1;
        [channels[i], channels[j]] = [channels[j], channels[i]];
        $("setLinks").value = channels.map((c) => c.link).join("\n");
        renderChannels();
      })
    );
    list.appendChild(row);
  });
}

$("btnLinksParse").addEventListener("click", parseLinks);

$("setAutostart").addEventListener("change", async (e) => {
  try {
    await call("SetAutostart", e.target.checked);
  } catch (err) {
    e.target.checked = !e.target.checked;
    $("saveHint").textContent = "⚠ Автозапуск: " + (err.message || err);
  }
});

$("btnRecalibrate").addEventListener("click", async () => {
  if (!confirm("Запустить полную рекалибровку DPI?\nСохранённый t* будет стёрт, обход подберётся заново (1–3 минуты). На это время перехват приостановится.")) return;
  const btn = $("btnRecalibrate");
  btn.disabled = true;
  btn.textContent = "Калибрую…";
  try {
    await call("Recalibrate");
    $("saveHint").textContent = "Рекалибровка запущена — следи за статусом на Главной";
  } catch (e) {
    $("saveHint").textContent = "⚠ " + (e.message || e);
  }
  btn.disabled = false;
  btn.textContent = "Рекалибровать";
});

$("btnSaveSettings").addEventListener("click", async () => {
  $("saveHint").textContent = "Сохраняю…";
  try {
    const warns = await call("SaveLinks", $("setLinks").value);
    $("saveHint").textContent = warns && warns.length
      ? "Сохранено ✓ (пропущено: " + warns.length + ")"
      : "Сохранено ✓ (демон перезагрузит конфиг)";
  } catch (e) {
    $("saveHint").textContent = "⚠ " + (e.message || e);
  }
});

// ---------- wizard (GUI_DESIGN §5) ----------
const WELCOME = 0, PERMS = 1, LINKS = 2, ASSETS = 3, PROBE = 4, DONE = 5;

function wizardStepsEl(step) {
  const w = $("wSteps");
  w.innerHTML = "";
  for (let i = 0; i <= PROBE; i++) {
    const d = document.createElement("i");
    if (i < step) d.className = "done";
    if (i === step) d.className = "cur";
    w.appendChild(d);
  }
}

function setWizardFooter(buttons) {
  const f = $("wFooter");
  f.innerHTML = "";
  for (const b of buttons) {
    const el = document.createElement("button");
    el.className = "btn" + (b.ghost ? " ghost" : "");
    el.textContent = b.label;
    el.disabled = !!b.disabled;
    el.addEventListener("click", b.onClick);
    f.appendChild(el);
  }
}

function showWizardStep(step) {
  wizardStepsEl(step);
  const body = $("wBody");
  switch (step) {
    case WELCOME:
      body.innerHTML = `
        <img src="/logo.png" alt="Rupas" style="width:88px;height:88px;border-radius:999px;object-fit:cover;margin-bottom:24px">
        <h2>Добро пожаловать в Rupas</h2>
        <p>Одна кнопка: трафик Telegram, YouTube и Discord работает без настроек.
        Rupas сам решает, что ускорить локально, а что увести в туннель.</p>`;
      setWizardFooter([{ label: "Начать", onClick: () => showWizardStep(PERMS) }]);
      break;

    case PERMS:
      body.innerHTML = `
        <h2>Разрешения</h2>
        <p>Для перехвата пакетов нужен драйвер WinDivert — демон Rupas запускается
        с правами администратора. Windows покажет диалог UAC.</p>
        <div class="err-box" id="wErr" style="display:none"></div>`;
      setWizardFooter([
        { label: "Запустить сервис", onClick: async () => {
            const err = $("wErr");
            err.style.display = "none";
            try {
              await call("EnsureDaemon");
              showWizardStep(LINKS);
            } catch (e) {
              err.style.display = "block";
              err.textContent = "Не удалось запустить демон: " + (e.message || e) + ". Нажмите «Запустить сервис» ещё раз и подтвердите UAC.";
            }
          } },
      ]);
      break;

    case LINKS:
      body.innerHTML = `
        <h2>Туннель</h2>
        <p>Вставьте ссылки серверов (vless://, hysteria2://) — по одной в строке,
        в порядке перебора. Или нажмите «Пропустить» для режима только DPI-обхода.</p>
        <div class="wizard-form">
          <div class="field">
            <textarea class="textarea" id="wLinks" placeholder="vless://uuid@host:443?security=reality&pbk=…&sni=…#канал 1" spellcheck="false"></textarea>
            <div class="hint" id="wLinksHint"></div>
          </div>
        </div>
        <div class="err-box" id="wErr" style="display:none"></div>`;
      setWizardFooter([
        { label: "Пропустить", ghost: true, onClick: () => showWizardStep(ASSETS) },
        { label: "Далее", onClick: async () => {
            const blob = $("wLinks").value.trim();
            if (!blob) { $("wLinksHint").textContent = "Вставьте ссылки или нажмите «Пропустить»"; return; }
            try {
              await call("ParseChannels", blob);
              const warns = await call("SaveLinks", blob);
              if (warns && warns.length) {
                $("wLinksHint").textContent = "⚠ Часть ссылок пропущена: " + warns.join("; ");
              }
              showWizardStep(ASSETS);
            } catch (e) {
              const err = $("wErr"); err.style.display = "block";
              err.textContent = (e.message || e);
            }
          } },
      ]);
      break;

    case ASSETS:
      body.innerHTML = `
        <h2>Подготовка</h2>
        <p>Скачиваю таблицы GeoIP для маршрутизации по странам…</p>
        <div class="progress"><i id="wBar" style="width:8%"></i></div>
        <ul class="task-list" id="wTasks"></ul>`;
      setWizardFooter([]);
      (async () => {
        const tasks = $("wTasks");
        const addTask = (t) => { const li = document.createElement("li"); li.innerHTML = '<span class="st">•</span>' + t; tasks.appendChild(li); return li; };
        const done = (li) => { li.querySelector(".st").className = "st done"; li.querySelector(".st").textContent = "✓"; };
        const li1 = addTask("Правила маршрутизации");
        $("wBar").style.width = "35%";
        try {
          await call("PrepareAssets");
          done(li1);
        } catch (e) { li1.querySelector(".st").className = "st fail"; li1.querySelector(".st").textContent = "✗"; }
        const li2 = addTask("GeoIP-таблицы");
        $("wBar").style.width = "80%";
        try {
          await call("ReloadConfig");
          done(li2);
        } catch (e) {
          done(li2);
        }
        $("wBar").style.width = "100%";
        setTimeout(() => showWizardStep(PROBE), 500);
      })();
      break;

    case PROBE:
      body.innerHTML = `
        <h2>Первый пробинг</h2>
        <p>Изучаю ваш DPI: подбираю стратегию обхода…</p>
        <div class="progress"><i id="wBar" style="width:5%"></i></div>
        <ul class="task-list" id="wTasks"></ul>`;
      setWizardFooter([]);
      (async () => {
        const bar = $("wBar");
        let t = 5;
        const iv = setInterval(() => { t = Math.min(t + 4, 92); bar.style.width = t + "%"; }, 700);
        try {
          await call("EnsureDaemon");
          await call("On");
          const deadline = Date.now() + 90000;
          while (Date.now() < deadline) {
            const s = await call("Status");
            if (s && s.online && (s.state === "ACTIVE" || s.state === "ACTIVE_TUNNEL_ONLY")) break;
            await new Promise((r) => setTimeout(r, 1000));
          }
        } catch (e) { /* keep going: state will show */ }
        clearInterval(iv);
        bar.style.width = "100%";
        const s = await call("Status");
        if (s && s.online && (s.state === "ACTIVE" || s.state === "ACTIVE_TUNNEL_ONLY")) {
          showWizardStep(DONE);
        } else {
          const body2 = $("wBody");
          body2.querySelector("h2").textContent = "Почти готово";
          body2.querySelector("p").textContent = "Пробинг не завершился успехом (" + ((s && s.state) || "демон не отвечает") + "). Можно продолжить — Rupas будет работать в деградированном режиме и сам перепробирует.";
          setWizardFooter([
            { label: "Повторить", ghost: true, onClick: () => showWizardStep(PROBE) },
            { label: "Продолжить", onClick: () => showWizardStep(DONE) },
          ]);
        }
      })();
      break;

    case DONE:
      call("FinishOnboarding");
      $("wizard").style.display = "none";
      $("mainApp").style.display = "flex";
      call("Status").then(render);
      break;
  }
}

/* ============================================================================
   ROUTING (docs/ROUTING_UI.md §4–§9)
   Rules grouped by the three engine stages + a pinned default, an inline
   editor, the route trace, presets and the dirty save bar. Every engine call
   goes through rtRpc(): a missing binding is a screen state, never a crash.
   ========================================================================== */

const RT_STAGES = [
  { title: "IP-адреса", kinds: ["cidr", "geoip"] },
  { title: "Домены", kinds: ["sni"] },
  { title: "Порты", kinds: ["ports"] },
];
const RT_KINDS = [
  { key: "cidr", label: "IP/CIDR", ph: "91.105.192.0/23" },
  { key: "geoip", label: "Страна", ph: "ru" },
  { key: "sni", label: "Домен", ph: "*.googlevideo.com" },
  { key: "ports", label: "Порт", ph: "50000-65535" },
];
const RT_PROTOS = [
  { key: "", label: "любой" },
  { key: "tcp", label: "tcp" },
  { key: "udp", label: "udp" },
];
const RT_ACTIONS = [
  { key: "DIRECT", cls: "direct", caption: "напрямую, без обхода" },
  { key: "TUNNEL", cls: "tunnel", caption: "через канал" },
  { key: "DESYNC", cls: "dsync", caption: "обход DPI без сервера" },
  { key: "BLOCK", cls: "block", caption: "отбрасывать" },
];
// ids match guictrl.PresetNames(): the list is a local preview, the engine
// applies the canonical preset on «Применить правила».
const RT_PRESETS = [
  { id: "owner", label: "Политика владельца" },
  { id: "ru-direct", label: "RU напрямую, остальное в туннель" },
  { id: "all-tunnel", label: "Всё через туннель" },
  { id: "all-direct", label: "Всё напрямую", danger: true },
];
const RT_RU_DIRECT_CIDRS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"];
const RT_RU_DIRECT_ZONES = ["*.ru", "*.su", "*.xn--p1ai", "*.xn--80adxhks", "*.xn--80asehdb", "*.xn--d1acj3b", "*.xn--90ais"];
const RT_RU_DIRECT_SITES = ["vk.com", "ok.ru", "userapi.com", "yandex.net", "ya.ru"];

const rtState = {
  loaded: false,
  status: "loading",         // loading | empty | error | full
  readError: "",
  engineNote: "",
  rules: [],
  def: { action: "TUNNEL", proto: "" },
  base: null,                // last applied snapshot (dirty is measured against it)
  saving: false,
  saveError: "",
  violations: [],
  rowErrors: {},
  collapsed: [false, false, false],
  sel: null,
  menu: null,
  edit: null,                // { mode, uid, stage, kind, value, proto, action }
  presetOpen: false,
  presetConfirm: null,
  presetId: null,            // a preset is pending: applied by id on save
  test: { state: "idle", trace: null, msg: "" },
  dragUid: null,
};

let rtSeqUid = 0;
const rtUid = () => "r" + ++rtSeqUid;
let rtSeqLoad = 0;
let rtSavedTimer = 0;

/* ---------- small helpers ---------- */
function rtPick(o, ...names) {
  for (const n of names) {
    if (o && o[n] !== undefined && o[n] !== null) return o[n];
  }
  return undefined;
}
function rtEsc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function rtPlural(n, one, few, many) {
  const a = Math.abs(n) % 100, b = a % 10;
  if (a > 10 && a < 20) return many;
  if (b > 1 && b < 5) return few;
  if (b === 1) return one;
  return many;
}
function rtAction(key) {
  return RT_ACTIONS.find((a) => a.key === String(key || "").toUpperCase()) || RT_ACTIONS[0];
}
function rtStageOf(kind) {
  for (let s = 0; s < RT_STAGES.length; s++) if (RT_STAGES[s].kinds.includes(kind)) return s;
  return 0;
}
function rtStageRules(s) {
  return rtState.rules.filter((r) => rtStageOf(r.kind) === s);
}
function rtFind(uid) {
  return rtState.rules.find((r) => r.uid === uid) || null;
}
function rtRuleLabel(r) {
  return (r && (r.human || r.matcher)) || "";
}
function rtMatcherText(r) {
  return r.kind === "geoip" ? "geoip: " + r.matcher : r.matcher;
}
function rtRegroup() {
  rtState.rules = [0, 1, 2].reduce((acc, s) => acc.concat(rtStageRules(s)), []);
}

/* ---------- engine adapter: a missing method is a state ---------- */
async function rtRpc(method, ...args) {
  try {
    const value = await call(method, ...args);
    return { ok: true, value };
  } catch (e) {
    const msg = (e && (e.message || String(e))) || "неизвестная ошибка";
    const missing = (e && (e.name === "ReferenceError")) ||
      /unknown method|not bound|no such method|not found|undefined is not a function/i.test(msg);
    return { ok: false, error: msg, missing };
  }
}

/* ---------- model <-> engine JSON (§10) ---------- */
function rtNormRule(raw, i) {
  if (!raw || typeof raw !== "object") return null;
  const kindRaw = String(rtPick(raw, "kind", "Kind") || "").toLowerCase();
  let kind = ["cidr", "geoip", "sni", "ports"].includes(kindRaw) ? kindRaw : "";
  if (!kind) {
    if (rtPick(raw, "cidr", "CIDR")) kind = "cidr";
    else if (rtPick(raw, "geoip", "GeoIP")) kind = "geoip";
    else if (rtPick(raw, "sni", "SNI")) kind = "sni";
    else if (rtPick(raw, "ports", "Ports")) kind = "ports";
  }
  let matcher = rtPick(raw, "matcher", "Matcher", "value", "Value");
  if (matcher === undefined && kind) matcher = raw[kind];
  const act = String(rtPick(raw, "action", "Action") || "").toUpperCase();
  const proto = String(rtPick(raw, "proto", "Proto", "protocol", "Protocol") || "").toLowerCase();
  const human = String(rtPick(raw, "human", "Human") || "");
  const idx = rtPick(raw, "index", "Index");
  return {
    uid: rtUid(),
    kind,
    matcher: String(matcher == null ? "" : matcher).trim(),
    human,
    action: RT_ACTIONS.some((a) => a.key === act) ? act : "",
    proto: proto === "tcp" || proto === "udp" ? proto : "",
    index: typeof idx === "number" ? idx : i,
  };
}

function rtToJson() {
  const out = rtState.rules.map((r) => {
    const o = {};
    o[r.kind] = r.matcher;
    if (r.proto) o.proto = r.proto;
    o.action = r.action;
    return o;
  });
  const d = { action: rtState.def.action };
  if (rtState.def.proto) d.proto = rtState.def.proto;
  out.push(d);                        // empty matcher = the default rule
  return JSON.stringify(out, null, 2);
}

function rtMakeBase() {
  return {
    byStage: [0, 1, 2].map((s) => rtStageRules(s).map((r) => ({
      kind: r.kind, matcher: r.matcher, proto: r.proto || "", action: r.action,
    }))),
    def: { action: rtState.def.action, proto: rtState.def.proto || "" },
    total: rtState.rules.length,
  };
}

function rtChanges() {
  const base = rtState.base;
  if (!base) return 0;
  let n = 0;
  for (let s = 0; s < 3; s++) {
    const a = base.byStage[s] || [], b = rtStageRules(s);
    const len = Math.max(a.length, b.length);
    for (let i = 0; i < len; i++) {
      const x = a[i], y = b[i];
      if (!x || !y || x.kind !== y.kind || x.matcher !== y.matcher ||
          (x.proto || "") !== (y.proto || "") || x.action !== y.action) n++;
    }
  }
  if ((base.def.action || "") !== (rtState.def.action || "") ||
      (base.def.proto || "") !== (rtState.def.proto || "")) n++;
  return n;
}
const rtDirty = () => rtChanges() > 0;

/* ---------- validation (§5.4, §6 conflict) ---------- */
function rtIsIPv4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  return !!m && m.slice(1).every((x) => +x <= 255);
}
function rtIsCidr(s) {
  const parts = String(s).split("/");
  if (parts.length > 2) return false;
  const ip = parts[0];
  const v4 = rtIsIPv4(ip);
  const v6 = !v4 && ip.includes(":") && /^[0-9a-fA-F:]+$/.test(ip) && ip.split("::").length <= 2;
  if (!v4 && !v6) return false;
  if (parts.length === 2) {
    if (!/^\d{1,3}$/.test(parts[1])) return false;
    if (+parts[1] > (v4 ? 32 : 128)) return false;
  }
  return true;
}
function rtCidrCount(s) {
  const parts = String(s).split("/");
  if (!rtIsIPv4(parts[0])) return null;
  const p = parts.length === 2 ? +parts[1] : 32;
  return Math.pow(2, 32 - p);
}
function rtIsDomainPattern(s) {
  const v = String(s).startsWith("*.") ? String(s).slice(2) : String(s);
  return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(v);
}
function rtParsePortSpan(s) {
  const m = /^(\d{1,5})(?:\s*[-–—:]\s*(\d{1,5}))?$/.exec(String(s).trim());
  if (!m) return null;
  const a = +m[1], b = m[2] ? +m[2] : a;
  if (a < 1 || a > 65535 || b < 1 || b > 65535 || b < a) return null;
  return { a, b };
}
function rtFindPortClash(span, proto, exceptUid) {
  for (const r of rtState.rules) {
    if (r.kind !== "ports" || r.uid === exceptUid) continue;
    if (proto && r.proto && proto !== r.proto) continue;
    const o = rtParsePortSpan(r.matcher);
    if (!o) continue;
    if (span.a <= o.b && o.a <= span.b) return r;
  }
  return null;
}
function rtValidateRule(kind, rawValue, proto, exceptUid) {
  const v = String(rawValue == null ? "" : rawValue).trim();
  if (!v) return { err: "Введите значение" };
  if (kind === "cidr" && !rtIsCidr(v)) return { err: "Неверный CIDR — ожидается адрес вида 91.105.192.0/23" };
  if (kind === "geoip" && !/^[A-Za-z]{2}$/.test(v)) return { err: "Неверный код страны — две латинские буквы, например ru" };
  if (kind === "sni" && !rtIsDomainPattern(v)) return { err: "Неверный домен — например example.com или *.googlevideo.com" };
  if (kind === "ports") {
    const span = rtParsePortSpan(v);
    if (!span) return { err: "Неверный порт — 1–65535 или диапазон вида 50000-65535" };
    const clash = rtFindPortClash(span, proto, exceptUid);
    if (clash) return { conflict: "пересекается с правилом «" + rtRuleLabel(clash) + "» " + clash.matcher };
  }
  return {};
}
function rtDeriveSub(r) {
  if (r.kind === "cidr") {
    const n = rtCidrCount(r.matcher);
    if (n === null) return "";
    return n.toLocaleString("ru-RU") + " " + rtPlural(n, "адрес", "адреса", "адресов");
  }
  if (r.kind === "geoip") return "таблица стран, обновляется раз в 30 дней";
  if (r.kind === "ports") {
    const span = rtParsePortSpan(r.matcher);
    if (!span) return "диапазон портов";
    return span.a === span.b ? "один порт" : "диапазон " + span.a + "–" + span.b;
  }
  if (r.kind === "sni") return r.matcher.startsWith("*.") ? "wildcard · суффикс и все поддомены" : "точное совпадение";
  return "";
}
function rtIsIpQuery(q) {
  return rtIsIPv4(q) || (q.includes(":") && /^[0-9a-fA-F:.]+$/.test(q));
}

/* ---------- rendering ---------- */
function rtRender() {
  const page = $("page-routing");
  page.classList.toggle("is-saving", rtState.saving);
  page.setAttribute("aria-busy", rtState.saving ? "true" : "false");
  rtRenderHead();
  rtRenderList();
  rtRenderDefault();
  rtRenderSaveBar();
  rtRenderPresets();
  rtRenderCheck();
}

function rtSummaryText() {
  const n = rtState.rules.length;
  return n + " " + rtPlural(n, "правило", "правила", "правил") +
    " · по умолчанию " + (rtState.def.action || "TUNNEL");
}

function rtRenderHead() {
  const sum = $("rtSummary"), sub = $("rtEntrySub");
  if (rtState.status === "loading") {
    sum.innerHTML = '<span class="rt-sk rt-sk-sum"></span>';
    sub.textContent = "—";
    return;
  }
  if (rtState.status === "error") {
    sum.textContent = "правила недоступны";
    sub.textContent = "правила недоступны";
    return;
  }
  const txt = rtSummaryText();
  sum.textContent = txt;
  sub.textContent = txt;
}

function rtRowHtml(r) {
  const s = rtStageOf(r.kind);
  const rows = rtStageRules(s);
  const i = rows.findIndex((x) => x.uid === r.uid);
  const act = rtAction(r.action);
  const reason = rtState.rowErrors[r.uid];
  const sub = reason || r.human || rtDeriveSub(r);
  const showProto = r.proto && !(r.human || "").includes("(" + r.proto + ")");
  const aria = [
    rtRuleLabel(r) || r.matcher,
    act.key,
    rtMatcherText(r),
    "правило " + (i + 1) + " из " + rows.length + " в стадии " + RT_STAGES[s].title,
  ].join(", ");
  const cls = ["rt-row"];
  if (rtState.sel === r.uid) cls.push("is-selected");
  if (reason) cls.push("is-error");
  if (rtState.saving) cls.push("is-disabled");
  return '<div class="' + cls.join(" ") + '" role="listitem" tabindex="0" data-uid="' + r.uid +
    '" draggable="' + (rtState.saving ? "false" : "true") + '" aria-label="' + rtEsc(aria) + '">' +
    '<button class="rt-handle" type="button" tabindex="-1" aria-hidden="true" title="Перетащить">' +
    '<svg viewBox="0 0 14 14"><path d="M2 4h10M2 7h10M2 10h10"/></svg></button>' +
    '<div class="rt-row-body"><div class="rt-matcher">' + rtEsc(rtMatcherText(r)) +
    (showProto ? '<span class="rt-proto">' + rtEsc(r.proto) + '</span>' : "") + '</div>' +
    '<div class="rt-row-sub' + (reason ? " is-reason" : "") + '">' + rtEsc(sub) + '</div></div>' +
    '<span class="rt-chip ' + act.cls + '"><i aria-hidden="true"></i>' + act.key + '</span>' +
    '<div class="rt-more"><button class="rt-more-btn" type="button" data-rt="menu" data-uid="' + r.uid +
    '" aria-haspopup="menu" aria-expanded="' + (rtState.menu === r.uid ? "true" : "false") +
    '" aria-label="Действия: ' + rtEsc(rtMatcherText(r)) + '">⋮</button>' +
    (rtState.menu === r.uid ? rtMenuHtml(r) : "") +
    '</div></div>';
}

function rtMenuHtml(r) {
  return '<div class="rt-menu" role="menu">' +
    '<button type="button" role="menuitem" data-rt="edit" data-uid="' + r.uid + '">Изменить</button>' +
    '<button type="button" role="menuitem" data-rt="dup" data-uid="' + r.uid + '">Дублировать</button>' +
    '<button type="button" role="menuitem" class="is-danger" data-rt="del" data-uid="' + r.uid + '">Удалить</button>' +
    '</div>';
}

function rtStageHtml(s) {
  const rows = rtStageRules(s);
  const open = !rtState.collapsed[s];
  let h = '<section class="rt-stage" data-stage="' + s + '">' +
    '<button class="rt-stage-head" type="button" data-rt="toggle-stage" data-stage="' + s +
    '" aria-expanded="' + (open ? "true" : "false") + '" aria-controls="rtList' + s + '">' +
    '<span class="rt-stage-title">' + RT_STAGES[s].title + '</span>' +
    '<span class="rt-stage-count">' + rows.length + '</span>' +
    '<svg class="rt-chev" viewBox="0 0 24 24" aria-hidden="true"><path d="M6 9l6 6 6-6"/></svg>' +
    '</button>';
  if (open) {
    h += '<div class="rt-stage-list" id="rtList' + s + '" role="list">' + rows.map(rtRowHtml).join("") + '</div>';
    if (rtState.edit && rtState.edit.stage === s) h += '<div data-editor-host="1"></div>';
    h += '<button class="rt-add" type="button" data-rt="add" data-stage="' + s + '">Добавить правило</button>';
  }
  return h + '</section>';
}

function rtRenderList() {
  const host = $("rtStages");
  if (rtState.status === "loading") {
    host.innerHTML = '<div class="rt-sk rt-sk-row"></div><div class="rt-sk rt-sk-row"></div>' +
      '<div class="rt-sk rt-sk-row"></div><div class="rt-sk rt-sk-row"></div>';
    return;
  }
  if (rtState.status === "error") {
    host.innerHTML = rtErrorBlock();
    return;
  }
  if (!rtState.rules.length) {
    host.innerHTML = '<div class="rt-empty">' +
      '<div class="rt-empty-text">Правил нет. Весь трафик пойдёт по умолчанию.</div>' +
      '<div class="rt-empty-actions">' +
      '<button class="rt-btn rt-btn-primary" type="button" data-rt="empty-add">Добавить первое правило</button>' +
      '<button class="rt-btn rt-btn-quiet" type="button" data-rt="empty-preset">Загрузить пресет</button>' +
      '</div></div>';
    return;
  }
  let h = "";
  if (rtState.engineNote) h += '<div class="rt-note">' + rtEsc(rtState.engineNote) + '</div>';
  for (let s = 0; s < 3; s++) h += rtStageHtml(s);
  host.innerHTML = h;
  if (rtState.edit) rtMountEditor();
}

function rtErrorBlock() {
  const raw = String(rtState.readError || "").split(/\r?\n/).filter(Boolean)[0] || "";
  return '<div class="rt-error">' +
    '<div class="rt-error-title">Не удалось прочитать правила</div>' +
    (raw ? '<div class="rt-error-raw">' + rtEsc(raw) + '</div>' : "") +
    '<div class="rt-error-actions"><button class="rt-btn rt-btn-quiet" type="button" data-rt="retry">Повторить</button></div>' +
    '</div>';
}

function rtRenderDefault() {
  const zone = $("rtDefaultZone"), card = $("rtDefaultCard");
  if (rtState.status === "loading") {
    zone.innerHTML = '<div class="rt-sk rt-sk-row"></div>';
    card.innerHTML = '<div class="rt-sk rt-sk-sum"></div>';
    return;
  }
  if (rtState.status === "error") {
    zone.innerHTML = "";
    card.innerHTML = '<div class="rt-defcard-sub">неизвестно</div>';
    return;
  }
  const act = rtAction(rtState.def.action);
  const proto = rtState.def.proto ? " · " + rtState.def.proto : "";
  zone.innerHTML = '<div class="rt-default">' +
    '<div class="rt-default-body">' +
    '<div class="rt-default-title">Всё остальное — закреплено</div>' +
    '<div class="rt-default-sub">не удаляется' + rtEsc(proto) + '</div>' +
    '</div><span class="rt-chip ' + act.cls + '"><i aria-hidden="true"></i>' + act.key + '</span></div>';
  card.innerHTML = '<div class="rt-defcard">' +
    '<span class="rt-chip ' + act.cls + '"><i aria-hidden="true"></i>' + act.key + '</span>' +
    '<div class="rt-defcard-sub">весь прочий трафик</div>' +
    (act.key === "DIRECT" ? '<div class="rt-defcard-danger">По умолчанию DIRECT — реальный IP не скрыт.</div>' : "") +
    '</div>';
}

function rtRenderSaveBar() {
  const bar = $("rtSaveBar");
  const errHost = $("rtSaveError");
  const n = rtChanges();
  const show = n > 0 && (rtState.status === "full" || rtState.status === "empty");
  bar.hidden = !show;
  if (!show) $("rtSaveCount").textContent = "";
  if (show) {
    $("rtSaveCount").textContent = n + " " + rtPlural(n, "изменение", "изменения", "изменений");
    const btn = $("rtApply");
    btn.disabled = rtState.saving;
    btn.textContent = rtState.saving ? "Применяю…" : "Применить правила";
    $("rtRevert").disabled = rtState.saving;
  }
  if (rtState.saveError) {
    let h = '<div class="rt-error rt-saveerr">' +
      '<div class="rt-error-title">Не удалось применить правила</div>';
    if (rtState.violations.length) {
      h += '<div class="rt-violations">' + rtState.violations.map((v) =>
        '<button class="rt-violation" type="button" data-rt="violation" data-uid="' + (v.uid || "") + '">' +
        rtEsc(v.text) + '</button>').join("") + '</div>';
    } else {
      h += '<div class="rt-error-raw">' + rtEsc(String(rtState.saveError).split(/\r?\n/)[0]) + '</div>';
    }
    h += '</div>';
    if (errHost.innerHTML !== h) errHost.innerHTML = h;
  } else if (errHost.innerHTML) {
    errHost.innerHTML = "";
  }
}

function rtRenderPresets() {
  const toggle = $("rtPresetsToggle"), list = $("rtPresetsList");
  toggle.setAttribute("aria-expanded", rtState.presetOpen ? "true" : "false");
  list.hidden = !rtState.presetOpen;
  if (!rtState.presetOpen) { list.innerHTML = ""; return; }
  const ownerN = rtState.base ? rtState.base.total : rtState.rules.length;
  let h = RT_PRESETS.map((p) => {
    const label = p.id === "owner" ? p.label + " (" + ownerN + ")" : p.label;
    return '<button class="rt-preset' + (p.danger ? " is-danger" : "") + '" type="button" data-rt="preset" data-preset="' +
      p.id + '"><span>' + rtEsc(label) + '</span></button>';
  }).join("");
  if (rtState.presetConfirm === "all-direct") {
    h += '<div class="rt-preset-confirm">Разрешить весь трафик мимо туннеля? IP будет виден' +
      '<div class="rt-preset-confirm-actions">' +
      '<button class="rt-btn rt-btn-quiet" type="button" data-rt="preset-confirm">Разрешить</button>' +
      '<button class="rt-btn rt-btn-quiet" type="button" data-rt="preset-cancel">Отмена</button>' +
      '</div></div>';
  }
  list.innerHTML = h;
}

function rtRenderCheck() {
  const out = $("rtCheckOut");
  const st = rtState.test;
  if (st.state === "idle") { out.innerHTML = ""; return; }
  if (st.state === "loading") {
    out.innerHTML = '<div class="rt-result"><div class="rt-result-stage">Проверяю…</div></div>';
    return;
  }
  if (st.state === "unavailable") {
    out.innerHTML = '<div class="rt-result">' +
      '<div class="rt-result-note">проверка недоступна: демон не отвечает</div>' +
      (st.msg ? '<div class="rt-error-raw">' + rtEsc(String(st.msg).split(/\r?\n/)[0]) + '</div>' : "") +
      '<button class="rt-btn rt-btn-quiet" type="button" data-rt="test-retry">Повторить</button></div>';
    return;
  }
  const t = st.trace || {};
  const stage = Number(rtPick(t, "stage", "Stage") || 0);
  const givenName = String(rtPick(t, "stageName", "StageName") || "");
  const matcher = String(rtPick(t, "matcher", "Matcher") || "");
  const note = String(rtPick(t, "note", "Note") || "");
  const warn = String(rtPick(t, "warning", "Warning") || "");
  const act = rtAction(rtPick(t, "action", "Action"));
  const isDefault = !matcher || stage === 4 || stage === 0;
  const name = givenName || (stage >= 1 && stage <= 3 ? RT_STAGES[stage - 1].title : "по умолчанию");
  const lines = [];
  lines.push('<div class="rt-result-stage">стадия ' + (isDefault ? "4" : stage) + ' · ' + rtEsc(isDefault ? "по умолчанию" : name) + '</div>');
  if (matcher) lines.push('<div class="rt-result-rule">правило: ' + rtEsc(matcher) + '</div>');
  lines.push('<div class="rt-result-foot"><span class="rt-chip ' + act.cls + '"><i aria-hidden="true"></i>' + act.key + '</span></div>');
  if (isDefault && act.key === "DIRECT") lines.push('<div class="rt-result-danger">IP не скрыт</div>');
  if (note) lines.push('<div class="rt-result-note">' + rtEsc(note) + '</div>');
  if (rtIsIpQuery(st.query || "")) lines.push('<div class="rt-result-note">домены не проверяются для IP</div>');
  // A rule-set remark (e.g. an unreadable geoip table) qualifies EVERY probe:
  // it belongs under the result as a warning, never mixed into the per-query note.
  if (warn) lines.push('<div class="rt-result-warn">' + rtEsc(warn) + ' — часть правил не проверена</div>');
  out.innerHTML = '<div class="rt-result">' + lines.join("") + '</div>';
}

/* ---------- loading ---------- */
async function rtLoad(opts) {
  const keepBase = !!(opts && opts.keepBaseline);
  const seq = ++rtSeqLoad;
  rtState.status = "loading";
  rtState.readError = "";
  rtState.saveError = "";
  rtState.violations = [];
  rtState.rowErrors = {};
  rtRender();

  const res = await rtRpc("LoadRules");
  if (seq !== rtSeqLoad) return;
  if (!res.ok) {
    rtState.status = "error";
    rtState.readError = res.error || "";
    rtState.rules = [];
    rtState.engineNote = "";
    rtRender();
    return;
  }
  const view = res.value || {};
  const raw = Array.isArray(view.rules) ? view.rules
    : Array.isArray(view.Rules) ? view.Rules : [];
  const picked = [];
  let def = null;
  raw.forEach((r, i) => {
    const nr = rtNormRule(r, i);
    if (!nr) return;
    if (!nr.kind) {                                // no matcher at all = the default rule
      if (!def) def = { action: nr.action || "TUNNEL", proto: nr.proto || "" };
      return;
    }
    if (!nr.matcher) return;
    if (!nr.action) nr.action = "DIRECT";
    picked.push(nr);
  });
  const dflt = view.default || view.Default;
  if (dflt && typeof dflt === "object") {
    const d = rtNormRule(dflt, 0);
    if (d) def = { action: d.action || (def && def.action) || "TUNNEL", proto: d.proto || "" };
  }
  const byStage = [[], [], []];
  picked.forEach((r) => byStage[rtStageOf(r.kind)].push(r));
  rtState.rules = byStage[0].concat(byStage[1], byStage[2]);
  rtState.def = def || { action: "TUNNEL", proto: "" };
  rtState.engineNote = String(view.error || view.Error || "");
  rtState.status = rtState.rules.length ? "full" : "empty";
  rtState.loaded = true;
  if (!keepBase) rtState.base = rtMakeBase();
  rtRender();
}

function rtEnter() {
  if (!rtState.loaded && !rtState.requested) {
    rtState.requested = true;
    rtLoad();
  }
}

/* ---------- route trace (§5.5) ---------- */
async function rtTest() {
  const input = $("rtQuery");
  const q = input.value.trim();
  if (!q) {
    rtState.test = { state: "idle", trace: null, msg: "" };
    rtRenderCheck();
    return;
  }
  rtState.test = { state: "loading", trace: null, msg: "", query: q };
  rtRenderCheck();
  const res = await rtRpc("TestRoute", q);
  if (!res.ok) {
    rtState.test = { state: "unavailable", trace: null, msg: res.error, query: q };
    rtRenderCheck();
    return;
  }
  let trace = res.value;
  if (typeof trace === "string") {
    try { trace = JSON.parse(trace); } catch (_) { trace = null; }
  }
  if (!trace || typeof trace !== "object") {
    rtState.test = { state: "unavailable", trace: null, msg: "", query: q };
  } else {
    rtState.test = { state: "ok", trace, msg: "", query: q };
  }
  rtRenderCheck();
}

/* ---------- mutations ---------- */
function rtOpenEditor(stage, rule) {
  rtState.menu = null;
  rtState.presetOpen = false;
  if (rule) {
    rtState.edit = {
      mode: "edit", uid: rule.uid, stage: rtStageOf(rule.kind),
      kind: rule.kind, value: rule.matcher, proto: rule.proto || "", action: rule.action,
    };
  } else {
    const s = stage == null ? 0 : stage;
    rtState.edit = {
      mode: "new", uid: null, stage: s,
      kind: RT_STAGES[s].kinds[0], value: "", proto: "", action: "TUNNEL",
    };
  }
  rtState.collapsed[rtState.edit.stage] = false;
  rtState.edit.focusValue = true;
  rtRenderList();
}
function rtCloseEditor() {
  rtState.edit = null;
  rtRenderList();
}
function rtEditHint() {
  const e = rtState.edit;
  if (!e) return "";
  const parts = [rtAction(e.action).caption];
  if (e.kind === "ports" && !e.proto) parts.push("без протокола правило забирает и QUIC (udp/443)");
  return parts.join(" · ");
}
function rtSegHtml(attr, items, current, extraCls) {
  return '<div class="rt-seg' + (extraCls ? " " + extraCls : "") + '">' + items.map((it) =>
    '<button type="button" data-' + attr + '="' + rtEsc(it.key) + '" aria-pressed="' +
    (it.key === current ? "true" : "false") + '"' + (it.cls ? ' class="a-' + it.cls + '"' : "") + '>' +
    rtEsc(it.label || it.key) + '</button>').join("") + '</div>';
}
function rtEditorHtml() {
  const e = rtState.edit;
  const kind = RT_KINDS.find((k) => k.key === e.kind) || RT_KINDS[0];
  return '<div class="rt-editor" role="group" aria-label="' +
    (e.mode === "new" ? "Новое правило" : "Изменить правило") + '">' +
    '<div class="rt-editor-grid">' +
    '<div><div class="rt-field-label">Вид</div>' + rtSegHtml("kind", RT_KINDS, e.kind) + '</div>' +
    '<div><div class="rt-field-label">Значение</div>' +
    '<input class="rt-value" id="rtEditValue" type="text" spellcheck="false" autocomplete="off" value="' +
    rtEsc(e.value) + '" placeholder="' + rtEsc(kind.ph) + '" aria-label="Значение правила" aria-invalid="false">' +
    '<div class="rt-err" id="rtEditErr" role="alert"></div></div>' +
    '<div class="rt-editor-cols">' +
    '<div><div class="rt-field-label">Протокол</div>' + rtSegHtml("proto", RT_PROTOS, e.proto) + '</div>' +
    '<div><div class="rt-field-label">Действие</div>' + rtSegHtml("action", RT_ACTIONS, e.action, "actions") + '</div>' +
    '</div>' +
    '<div class="rt-editor-foot">' +
    '<div class="rt-editor-hint" id="rtEditHint">' + rtEsc(rtEditHint()) + '</div>' +
    '<button class="rt-btn rt-btn-quiet" type="button" data-rt="edit-cancel">Отмена</button>' +
    '<button class="rt-btn rt-btn-primary" type="button" id="rtEditSave" data-rt="edit-save">' +
    (e.mode === "new" ? "Добавить" : "Сохранить") + '</button>' +
    '</div></div></div>';
}
function rtMountEditor() {
  const host = document.querySelector("#page-routing [data-editor-host]");
  if (!host || !rtState.edit) return;
  host.innerHTML = rtEditorHtml();
  const val = host.querySelector("#rtEditValue");
  if (val) {
    val.addEventListener("input", () => {
      if (!rtState.edit) return;
      rtState.edit.value = val.value;
      rtValidateEditor(false);
    });
    val.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") { ev.preventDefault(); rtSaveEditor(); }
    });
    if (rtState.edit.focusValue) {
      rtState.edit.focusValue = false;
      val.focus();
      val.setSelectionRange(val.value.length, val.value.length);
    }
  }
  rtValidateEditor(false);
}
function rtSyncEditor() {
  const host = document.querySelector("#page-routing [data-editor-host]");
  if (!host || !rtState.edit) return;
  const e = rtState.edit;
  host.querySelectorAll("[data-kind]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.kind === e.kind)));
  host.querySelectorAll("[data-proto]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.proto === e.proto)));
  host.querySelectorAll("[data-action]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.action === e.action)));
  const val = host.querySelector("#rtEditValue");
  if (val) {
    const k = RT_KINDS.find((x) => x.key === e.kind);
    if (k) val.placeholder = k.ph;
  }
  const hint = host.querySelector("#rtEditHint");
  if (hint) hint.textContent = rtEditHint();
  rtValidateEditor(false);
}
function rtValidateEditor(submitted) {
  const e = rtState.edit;
  if (!e) return false;
  const host = document.querySelector("#page-routing [data-editor-host]");
  if (!host) return false;
  const errEl = host.querySelector("#rtEditErr");
  const val = host.querySelector("#rtEditValue");
  const res = rtValidateRule(e.kind, e.value, e.proto, e.mode === "edit" ? e.uid : null);
  const msg = res.err || res.conflict || "";
  const show = !!msg && (submitted || String(e.value).trim() !== "");
  if (errEl) errEl.textContent = show ? msg : "";
  if (val) val.setAttribute("aria-invalid", show ? "true" : "false");
  return !msg;
}
function rtSaveEditor() {
  const e = rtState.edit;
  if (!e) return;
  if (!rtValidateEditor(true)) {
    const val = document.querySelector("#page-routing #rtEditValue");
    if (val) val.focus();
    return;
  }
  const value = String(e.value).trim();
  if (e.mode === "edit") {
    const r = rtFind(e.uid);
    if (r) {
      if (r.kind !== e.kind) r.human = "";
      r.kind = e.kind;
      r.matcher = value;
      r.proto = e.proto;
      r.action = e.action;
    }
  } else {
    rtState.rules.push({
      uid: rtUid(), kind: e.kind, matcher: value, human: "",
      action: e.action, proto: e.proto, index: rtState.rules.length,
    });
  }
  rtRegroup();
  rtClearPreset();
  rtState.edit = null;
  rtState.saveError = "";
  rtState.rowErrors = {};
  rtRender();
}
function rtDeleteUid(uid) {
  const r = rtFind(uid);
  if (!r || rtState.saving) return;
  rtState.rules = rtState.rules.filter((x) => x.uid !== uid);
  rtClearPreset();
  if (rtState.sel === uid) rtState.sel = null;
  rtState.menu = null;
  rtState.saveError = "";
  rtState.rowErrors = {};
  rtRender();
}
function rtDeleteSelected() {
  const r = rtFind(rtState.sel);
  if (!r) return;
  if (!confirm("Удалить правило «" + rtRuleLabel(r) + "»?")) return;
  rtDeleteUid(r.uid);
}
function rtDuplicate(uid) {
  const r = rtFind(uid);
  if (!r) return;
  const copy = Object.assign({}, r, { uid: rtUid(), human: r.human, index: rtState.rules.length });
  const at = rtState.rules.findIndex((x) => x.uid === uid);
  rtState.rules.splice(at + 1, 0, copy);
  rtRegroup();
  rtClearPreset();
  rtState.menu = null;
  rtState.saveError = "";
  rtRender();
}

/* ---------- keyboard order ---------- */
function rtFlatRows() {
  const out = [];
  for (let s = 0; s < 3; s++) {
    if (rtState.collapsed[s]) continue;
    rtStageRules(s).forEach((r) => out.push(r.uid));
  }
  return out;
}
function rtFocusRow(uid) {
  const el = document.querySelector('#page-routing .rt-row[data-uid="' + uid + '"]');
  if (el) el.focus();
}
function rtSelect(uid, focus) {
  rtState.sel = uid;
  rtRenderList();
  if (focus) rtFocusRow(uid);
}
function rtMoveSel(delta) {
  const rows = rtFlatRows();
  if (!rows.length) return;
  let cur = rtState.sel;
  if (!cur) {
    const active = document.activeElement;
    const rowEl = active && active.closest ? active.closest(".rt-row") : null;
    if (rowEl) cur = rowEl.dataset.uid;
  }
  let i = rows.indexOf(cur);
  if (i < 0) i = delta > 0 ? -1 : rows.length;
  const next = Math.min(rows.length - 1, Math.max(0, i + delta));
  rtSelect(rows[next], true);
}
function rtReorderSel(delta) {
  const r = rtFind(rtState.sel);
  if (!r || rtState.saving) return;
  const s = rtStageOf(r.kind);
  const rows = rtStageRules(s);
  const i = rows.indexOf(r);
  const j = i + delta;
  if (i < 0 || j < 0 || j >= rows.length) return;
  const from = rtState.rules.indexOf(r);
  const other = rows[j];
  const to = rtState.rules.indexOf(other);
  rtState.rules.splice(from, 1);
  rtState.rules.splice(to, 0, r);
  rtRegroup();
  rtClearPreset();
  rtRender();
  rtFocusRow(r.uid);
}

/* ---------- presets (§5.6) ---------- */
function rtLocalPreset(id) {
  const mk = (kind, matcher, action, proto) => ({
    uid: rtUid(), kind, matcher, human: "", action, proto: proto || "", index: 0,
  });
  if (id === "owner") {
    const base = rtState.base;
    if (!base) return;
    const keepHuman = new Map(rtState.rules.map((r) => [r.kind + "|" + r.matcher, r.human]));
    const rules = [];
    base.byStage.forEach((arr) => arr.forEach((r) => {
      rules.push({ uid: rtUid(), kind: r.kind, matcher: r.matcher, human: keepHuman.get(r.kind + "|" + r.matcher) || "", action: r.action, proto: r.proto || "", index: 0 });
    }));
    rtState.rules = rules;
    rtState.def = { action: base.def.action, proto: base.def.proto || "" };
  } else if (id === "ru-direct") {
    // Mirrors guictrl.ruDirectRules so the preview matches what the engine writes.
    const rules = [];
    RT_RU_DIRECT_CIDRS.forEach((c) => rules.push(mk("cidr", c, "DIRECT")));
    rules.push(mk("geoip", "ru", "DIRECT"));
    RT_RU_DIRECT_ZONES.forEach((z) => rules.push(mk("sni", z, "DIRECT")));
    RT_RU_DIRECT_SITES.forEach((site) => {
      rules.push(mk("sni", site, "DIRECT"));
      rules.push(mk("sni", "*." + site, "DIRECT"));
    });
    rtState.rules = rules;
    rtState.def = { action: "TUNNEL", proto: "" };
  } else if (id === "all-tunnel") {
    rtState.rules = [];
    rtState.def = { action: "TUNNEL", proto: "" };
  } else if (id === "all-direct") {
    rtState.rules = [];
    rtState.def = { action: "DIRECT", proto: "" };
  }
  rtState.presetId = id;
  rtState.presetOpen = false;
  rtState.presetConfirm = null;
  rtState.edit = null;
  rtState.sel = null;
  rtState.saveError = "";
  rtState.rowErrors = {};
  rtRender();
}

// A preset only replaces the working list (§5.6); it reaches the config on
// «Применить правила», which asks the engine for the canonical preset by id.
function rtPresetApply(id) {
  rtLocalPreset(id);
}

// Every hand edit drops the preset identity so the save path falls back to
// SaveRules with the exact list the user sees.
function rtClearPreset() {
  rtState.presetId = null;
}

function rtPresetClick(id) {
  const p = RT_PRESETS.find((x) => x.id === id);
  if (!p) return;
  if (p.danger && rtState.presetConfirm !== id) {
    rtState.presetConfirm = id;
    rtRenderPresets();
    return;
  }
  rtState.presetConfirm = null;
  rtPresetApply(id);
}

/* ---------- save / revert (§5.7, §6) ---------- */
function rtParseViolations(msg) {
  const lines = String(msg || "").split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  return lines.slice(0, 10).map((text) => {
    const m = /rule\s+(\d+)/i.exec(text);
    const idx = m ? parseInt(m[1], 10) - 1 : -1;
    const rule = idx >= 0 ? rtState.rules[idx] : null;
    return { text, uid: rule ? rule.uid : "" };
  });
}
async function rtApplyRules() {
  if (rtState.saving || !rtDirty()) return;
  rtState.saving = true;
  rtState.saveError = "";
  rtState.violations = [];
  rtState.rowErrors = {};
  rtRender();
  // A pending preset is applied by id so the engine writes its canonical list;
  // anything edited by hand goes through the JSON contract instead.
  const presetId = rtState.presetId;
  let res = null;
  let viaPreset = false;
  if (presetId) {
    const pr = await rtRpc("ApplyPreset", presetId);
    if (pr.ok) { res = pr; viaPreset = true; }
  }
  if (!viaPreset) res = await rtRpc("SaveRules", rtToJson());
  rtState.saving = false;
  if (!res.ok) {
    rtState.saveError = res.error || "ошибка";
    rtState.violations = rtParseViolations(res.error || "");
    rtState.rowErrors = {};
    rtState.violations.forEach((v) => {
      if (v.uid && !rtState.rowErrors[v.uid]) rtState.rowErrors[v.uid] = v.text;
    });
    rtRender();
    const box = $("rtSaveError");
    if (box && box.scrollIntoView) box.scrollIntoView({ block: "nearest" });
    return;
  }
  rtState.presetId = null;
  rtState.edit = null;
  if (viaPreset) {
    await rtLoad();            // the engine owns the preset's exact contents
    rtFlashSaved();
    return;
  }
  rtState.base = rtMakeBase();
  rtState.saveError = "";
  rtState.violations = [];
  rtState.rowErrors = {};
  rtRender();
  rtFlashSaved();
}
function rtRevert() {
  const base = rtState.base;
  if (!base) return;
  const keepHuman = new Map(rtState.rules.map((r) => [r.kind + "|" + r.matcher, r.human]));
  const rules = [];
  base.byStage.forEach((arr) => arr.forEach((r) => rules.push({
    uid: rtUid(), kind: r.kind, matcher: r.matcher,
    human: keepHuman.get(r.kind + "|" + r.matcher) || "",
    action: r.action, proto: r.proto || "", index: 0,
  })));
  rtState.rules = rules;
  rtState.def = { action: base.def.action, proto: base.def.proto || "" };
  rtClearPreset();
  rtState.edit = null;
  rtState.menu = null;
  rtState.saveError = "";
  rtState.violations = [];
  rtState.rowErrors = {};
  rtRender();
}
function rtFlashSaved() {
  const el = $("rtSaved");
  el.classList.remove("is-hiding");
  el.classList.add("is-on");
  clearTimeout(rtSavedTimer);
  rtSavedTimer = setTimeout(() => {
    el.classList.add("is-hiding");
    setTimeout(() => el.classList.remove("is-on", "is-hiding"), 220);
  }, 2000);
}

/* ---------- events ---------- */
function rtOnClick(ev) {
  const t = ev.target instanceof Element ? ev.target : ev.target && ev.target.parentElement;
  if (!t) return;

  const kindBtn = t.closest("[data-kind]");
  if (kindBtn && rtState.edit) { rtState.edit.kind = kindBtn.dataset.kind; rtSyncEditor(); return; }
  const protoBtn = t.closest("[data-proto]");
  if (protoBtn && rtState.edit) { rtState.edit.proto = protoBtn.dataset.proto; rtSyncEditor(); return; }
  const actBtn = t.closest("[data-action]");
  if (actBtn && rtState.edit) { rtState.edit.action = actBtn.dataset.action; rtSyncEditor(); return; }

  const btn = t.closest("[data-rt]");
  if (btn) {
    const act = btn.dataset.rt;
    const uid = btn.dataset.uid || "";
    switch (act) {
      case "toggle-stage": {
        const s = +btn.dataset.stage;
        rtState.collapsed[s] = !rtState.collapsed[s];
        rtRenderList();
        return;
      }
      case "add": rtOpenEditor(+btn.dataset.stage, null); return;
      case "menu": rtState.menu = rtState.menu === uid ? null : uid; rtRenderList(); return;
      case "edit": {
        rtState.menu = null;
        const r = rtFind(uid);
        if (r) rtOpenEditor(null, r); else rtRenderList();
        return;
      }
      case "dup": rtDuplicate(uid); return;
      case "del": {
        rtState.menu = null;
        const r = rtFind(uid);
        if (!r) return;
        if (!confirm("Удалить правило «" + rtRuleLabel(r) + "»?")) { rtRenderList(); return; }
        rtDeleteUid(uid);
        return;
      }
      case "edit-save": rtSaveEditor(); return;
      case "edit-cancel": rtCloseEditor(); return;
      case "empty-add": rtOpenEditor(0, null); return;
      case "empty-preset":
        rtState.presetOpen = true;
        rtRenderPresets();
        $("rtPresetsToggle").focus();
        return;
      case "retry": rtLoad(); return;
      case "test-retry": rtTest(); return;
      case "violation": {
        const v = rtState.violations.find((x) => x.uid === uid);
        if (!v) return;
        rtState.sel = uid;
        rtState.collapsed[rtStageOf((rtFind(uid) || {}).kind || "cidr")] = false;
        rtRenderList();
        rtFocusRow(uid);
        return;
      }
      case "preset": rtPresetClick(btn.dataset.preset); return;
      case "preset-confirm": rtPresetApply(rtState.presetConfirm); return;
      case "preset-cancel": rtState.presetConfirm = null; rtRenderPresets(); return;
      default: return;
    }
  }

  if (t.closest(".rt-handle")) return;                 // drag handle is not a click target
  const row = t.closest(".rt-row");
  if (row) {
    if (rtState.menu) rtState.menu = null;
    rtSelect(row.dataset.uid, true);
    return;
  }
  if (rtState.menu) { rtState.menu = null; rtRenderList(); }
}

function rtOnKey(ev) {
  if (!$("page-routing").classList.contains("active")) return;
  const target = ev.target;
  const typing = target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable);

  if ((ev.ctrlKey || ev.metaKey) && String(ev.key).toLowerCase() === "s") {
    ev.preventDefault();
    if (rtDirty() && !rtState.saving) rtApplyRules();
    return;
  }
  if (ev.key === "Escape") {
    if (rtState.menu) { rtState.menu = null; rtRenderList(); ev.preventDefault(); return; }
    if (rtState.presetConfirm) { rtState.presetConfirm = null; rtRenderPresets(); ev.preventDefault(); return; }
    if (rtState.edit) { ev.preventDefault(); rtCloseEditor(); return; }
    if (rtState.presetOpen) { rtState.presetOpen = false; rtRenderPresets(); $("rtPresetsToggle").focus(); ev.preventDefault(); return; }
    if (typing) { target.blur(); return; }
    if (rtState.sel) { rtState.sel = null; rtRenderList(); ev.preventDefault(); return; }
    if (rtDirty() && !rtState.saving) { ev.preventDefault(); rtRevert(); }
    return;
  }
  if (typing) return;

  switch (ev.key) {
    case "j": ev.preventDefault(); rtMoveSel(1); break;
    case "k": ev.preventDefault(); rtMoveSel(-1); break;
    case "Enter": {
      const r = rtFind(rtState.sel);
      if (r) { ev.preventDefault(); rtOpenEditor(null, r); }
      break;
    }
    case "n":
      ev.preventDefault();
      rtOpenEditor(rtState.sel ? rtStageOf((rtFind(rtState.sel) || {}).kind || "cidr") : 0, null);
      break;
    case "d": ev.preventDefault(); rtDeleteSelected(); break;
    case "ArrowUp": if (ev.altKey) { ev.preventDefault(); rtReorderSel(-1); } break;
    case "ArrowDown": if (ev.altKey) { ev.preventDefault(); rtReorderSel(1); } break;
    default: break;
  }
}

function rtOnDragStart(ev) {
  const row = ev.target instanceof Element ? ev.target.closest(".rt-row") : null;
  if (!row || rtState.saving) { ev.preventDefault(); return; }
  rtState.dragUid = row.dataset.uid;
  row.classList.add("is-dragging");
  try {
    ev.dataTransfer.effectAllowed = "move";
    ev.dataTransfer.setData("text/plain", row.dataset.uid);
  } catch (_) { /* older webview */ }
}
function rtOnDragOver(ev) {
  if (!rtState.dragUid) return;
  const over = ev.target instanceof Element ? ev.target.closest(".rt-row") : null;
  if (!over || over.dataset.uid === rtState.dragUid) return;
  const dragEl = document.querySelector('#page-routing .rt-row[data-uid="' + rtState.dragUid + '"]');
  const dr = rtFind(rtState.dragUid), ov = rtFind(over.dataset.uid);
  if (!dragEl || !dr || !ov) return;
  if (rtStageOf(dr.kind) !== rtStageOf(ov.kind)) return;   // order matters only inside a stage
  ev.preventDefault();
  try { ev.dataTransfer.dropEffect = "move"; } catch (_) {}
  const rect = over.getBoundingClientRect();
  const after = ev.clientY > rect.top + rect.height / 2;
  over.parentNode.insertBefore(dragEl, after ? over.nextSibling : over);
}
function rtCommitDomOrder() {
  const lists = document.querySelectorAll("#page-routing .rt-stage-list");
  if (!lists.length) return;
  const order = [];
  lists.forEach((l) => l.querySelectorAll(".rt-row").forEach((r) => order.push(r.dataset.uid)));
  const map = new Map(rtState.rules.map((r) => [r.uid, r]));
  const next = order.map((uid) => map.get(uid)).filter(Boolean);
  rtState.rules.forEach((r) => { if (!next.includes(r)) next.push(r); });
  rtState.rules = next;
  rtRegroup();
  rtClearPreset();
}
function rtOnDrop(ev) {
  if (!rtState.dragUid) return;
  ev.preventDefault();
  rtCommitDomOrder();
  rtState.dragUid = null;
  rtState.saveError = "";
  rtRender();
}
function rtOnDragEnd() {
  rtState.dragUid = null;
  document.querySelectorAll("#page-routing .rt-row.is-dragging").forEach((r) => r.classList.remove("is-dragging"));
}

/* ---------- init ---------- */
(function rtInit() {
  const page = $("page-routing");
  page.addEventListener("click", rtOnClick);
  page.addEventListener("dragstart", rtOnDragStart);
  page.addEventListener("dragover", rtOnDragOver);
  page.addEventListener("drop", rtOnDrop);
  page.addEventListener("dragend", rtOnDragEnd);
  document.addEventListener("keydown", rtOnKey);

  $("rtCheckGo").addEventListener("click", rtTest);
  $("rtQuery").addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") { ev.preventDefault(); rtTest(); }
  });
  $("rtQuery").addEventListener("input", () => {
    if (!rtState.test || rtState.test.state === "idle") return;
    if (!$("rtQuery").value.trim()) {
      rtState.test = { state: "idle", trace: null, msg: "" };
      rtRenderCheck();
    }
  });
  $("rtApply").addEventListener("click", rtApplyRules);
  $("rtRevert").addEventListener("click", rtRevert);
  $("rtPresetsToggle").addEventListener("click", () => {
    rtState.presetOpen = !rtState.presetOpen;
    if (!rtState.presetOpen) rtState.presetConfirm = null;
    rtRenderPresets();
  });
  $("btnOpenRouting").addEventListener("click", () => showPage("routing"));
  rtRender();
})();

// ---------- boot ----------
(async () => {
  try {
    const onboarded = await call("Onboarded");
    if (onboarded) {
      $("wizard").style.display = "none";
      $("mainApp").style.display = "flex";
      call("Status").then(render);
    } else {
      $("wizard").style.display = "flex";
      showWizardStep(WELCOME);
    }
  } catch (e) {
    $("wizard").style.display = "none";
    $("mainApp").style.display = "flex";
    render({ online: false, state: "" });
  }
  // live snapshot events from Go
  try {
    On("rupas:snapshot", (ev) => render(ev.data));
  } catch (_) { /* polling fallback below */ }
  setInterval(async () => {
    try { render(await call("Status")); } catch (_) {}
  }, 2000);
})();
