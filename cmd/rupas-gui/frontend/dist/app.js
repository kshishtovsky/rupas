// Rupas GUI — frontend logic (no build step: plain ES module).
// Talks to the Go service via the vendored @wailsio/runtime (offline).
import { ByName as callRaw } from "./vendor/runtime/calls.js";
import { On } from "./vendor/runtime/events.js";

const $ = (id) => document.getElementById(id);
const FQN = "github.com/rupas/rupas/internal/guictrl.Controller";
const call = (method, ...args) => callRaw(`${FQN}.${method}`, ...args);

// ---------- state ----------
let snap = { online: false, state: "" };
let wizardStep = 0;

// ---------- UI-state mapping (GUI_DESIGN §7) ----------
function uiState(s) {
  if (!s.online) return "off"; // daemon down == button shows off
  switch (s.state) {
    case "ACTIVE":
    case "ACTIVE_TUNNEL_ONLY": return "on";
    case "PROBING": return "connecting";
    case "DEGRADED": return "error";
    default: return "off"; // OFF or unknown
  }
}
const CAPTIONS = {
  off: "Отключено",
  connecting: "Подключаюсь…",
  on: "Работает",
  error: "Сбой",
};

function fmtBytes(n) {
  if (n > 1024 * 1024 * 1024) return (n / 1024 ** 3).toFixed(1) + " ГБ";
  if (n > 1024 * 1024) return (n / 1024 ** 2).toFixed(1) + " МБ";
  if (n > 1024) return (n / 1024).toFixed(1) + " КБ";
  return n + " Б";
}

function render(s) {
  snap = s;
  const st = uiState(s);
  const disc = $("powerDisc");
  disc.className = "power-disc " + (st === "off" ? "" : st);
  $("powerCaption").textContent = s.online && s.state === "ACTIVE_TUNNEL_ONLY" ? "Работает (только туннель)" : CAPTIONS[st];
  $("powerSub").textContent = st === "error" ? "Нажмите, чтобы переподключить" : "";
  const dot = $("dot");
  dot.className = "status-dot " + (st === "off" ? "" : st);
  $("dotText").textContent = CAPTIONS[st];
  // cards
  $("cardTunnel").innerHTML = !s.online ? "—" :
    s.tunnelMode === "tunnel" ? `<small>VLESS</small> работает` :
    s.tunnelMode === "escalated" ? `<span class="chip warn">эскалация</span>` :
    s.tunnelMode === "off" ? "выключен" : "—";
  $("cardTraffic").textContent = !s.online ? "—" : `↓${fmtBytes(s.rxBytes)} ↑${fmtBytes(s.txBytes)}`;
  const flows = s.tcpFlows || 0;
  $("cardFlows").textContent = !s.online ? "—" : `${flows} активных TCP-потоков через туннель`;
}

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
    if (b.dataset.page === "settings") { call("LoadConfig").then(fillSettings).catch(() => {}); call("Autostart").then((v) => ($("setAutostart").checked = !!v)).catch(() => {}); }
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
        // highlight CH-lines (verdict log)
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

// ---------- settings ----------
function fillSettings(cfg) {
  $("setHost").value = cfg.host || "";
  $("setPort").value = cfg.port || "";
  $("setUuid").value = cfg.uuid || "";
  $("setSni").value = cfg.sni || "";
  $("setPbk").value = cfg.pbk || "";
  $("setSid").value = cfg.sid || "";
  $("setDpi").checked = cfg.dpi !== false;
}

function bindEye(eyeId, inputId) {
  $(eyeId).addEventListener("click", () => {
    const i = $(inputId);
    i.type = i.type === "password" ? "text" : "password";
  });
}
bindEye("eyeUuid", "setUuid");
bindEye("eyePbk", "setPbk");

$("btnVlessParse").addEventListener("click", async () => {
  const link = $("setVless").value.trim();
  if (!link) return;
  try {
    const v = await call("ParseVless", link);
    $("setHost").value = v.server || "";
    $("setPort").value = v.port || "";
    $("setUuid").value = v.uuid || "";
    $("setSni").value = v.sni || "";
    $("setPbk").value = v.publicKey || "";
    $("setSid").value = v.shortId || "";
    $("setVless").value = "";
    $("saveHint").textContent = v.warning ? "⚠ " + v.warning : "Ссылка разобрана — проверьте поля и сохраните";
  } catch (e) {
    $("saveHint").textContent = "⚠ " + (e.message || e);
  }
});

$("setAutostart").addEventListener("change", async (e) => {
  try {
    await call("SetAutostart", e.target.checked);
  } catch (err) {
    e.target.checked = !e.target.checked;
    $("saveHint").textContent = "⚠ Автозапуск: " + (err.message || err);
  }
});

$("btnSaveSettings").addEventListener("click", async () => {
  const ep = {
    host: $("setHost").value.trim(),
    port: parseInt($("setPort").value || "0", 10),
    uuid: $("setUuid").value.trim(),
    sni: $("setSni").value.trim(),
    pbk: $("setPbk").value.trim(),
    sid: $("setSid").value.trim(),
    dpi: $("setDpi").checked,
  };
  try {
    await call("SaveConfig", ep);
    $("saveHint").textContent = "Сохранено ✓ (демон перезагрузит конфиг)";
  } catch (e) {
    $("saveHint").textContent = "⚠ " + (e.message || e);
  }
});

// ---------- wizard (GUI_DESIGN §5) ----------
const WELCOME = 0, PERMS = 1, VLESS = 2, ASSETS = 3, PROBE = 4, DONE = 5;

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
  wizardStep = step;
  wizardStepsEl(step);
  const body = $("wBody");
  switch (step) {
    case WELCOME:
      body.innerHTML = `
        <div class="logo" style="width:72px;height:72px;font-size:34px;margin-bottom:24px;border-radius:999px;background:var(--accent);color:var(--accent-ink);display:flex;align-items:center;justify-content:center">R</div>
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
              showWizardStep(VLESS);
            } catch (e) {
              err.style.display = "block";
              err.textContent = "Не удалось запустить демон: " + (e.message || e) + ". Нажмите «Запустить сервис» ещё раз и подтвердите UAC.";
            }
          } },
      ]);
      break;

    case VLESS:
      body.innerHTML = `
        <h2>Туннель</h2>
        <p>Вставьте vless://-ссылку от вашего сервера — или нажмите «Пропустить»,
        чтобы использовать только локальный DPI-обход.</p>
        <div class="wizard-form">
          <div class="field">
            <label>vless://-ссылка</label>
            <textarea class="textarea" id="wVless" placeholder="vless://uuid@host:443?security=reality&pbk=…&sid=…&sni=…#мой сервер" spellcheck="false"></textarea>
            <div class="hint" id="wVlessHint"></div>
          </div>
        </div>
        <div class="err-box" id="wErr" style="display:none"></div>`;
      setWizardFooter([
        { label: "Пропустить", ghost: true, onClick: () => showWizardStep(ASSETS) },
        { label: "Далее", onClick: async () => {
            const link = $("wVless").value.trim();
            if (!link) { $("wVlessHint").textContent = "Вставьте ссылку или нажмите «Пропустить»"; return; }
            try {
              const v = await call("ParseVless", link);
              await call("SaveConfig", { host: v.server, port: v.port, uuid: v.uuid, sni: v.sni, pbk: v.publicKey, sid: v.shortId, dpi: true });
              if (v.warning) $("wVlessHint").textContent = "⚠ " + v.warning + " — ссылка сохранена";
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
          // GeoIP downloads happen on first compile inside the daemon; a reload
          // failure with the daemon offline is non-fatal for onboarding.
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
          // wait for ACTIVE via Status polling
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
    // Service unreachable: show main with off state
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
