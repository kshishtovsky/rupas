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
document.querySelectorAll(".nav-item").forEach((b) =>
  b.addEventListener("click", () => {
    document.querySelectorAll(".nav-item").forEach((x) => x.classList.remove("active"));
    document.querySelectorAll(".page").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
    $("page-" + b.dataset.page).classList.add("active");
    if (b.dataset.page === "logs") { loadLogs(); logsTimer = setInterval(loadLogs, 2000); }
    else { clearInterval(logsTimer); logsTimer = null; }
    if (b.dataset.page === "settings") loadSettings();
  })
);
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
