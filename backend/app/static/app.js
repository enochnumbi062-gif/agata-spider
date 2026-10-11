import * as THREE from "https://cdn.jsdelivr.net/npm/three@0.170.0/build/three.module.min.js";

const $ = (s) => document.querySelector(s);
const el = (t, p = {}, ...k) => { const n = Object.assign(document.createElement(t), p); n.append(...k); return n; };
const TAU = Math.PI * 2;
const MODULES = [
  ["01", "Global Command Center", "État de l'API, du mode et de la politique de contrôle.", 1],
  ["02", "Asset & IP Explorer", "Inventaire des actifs (échantillon illustratif).", 1],
  ["03", "Security Audit Engine", "Audit de démonstration ou contrôle TCP dans le périmètre autorisé.", 1],
  ["04", "3D Attack Surface", "Relations et chemins confirmés entre actifs.", 1],
  ["05", "AgAtA Intelligence", "Synthèse IA (Gemini) jointe aux audits authentifiés.", 1],
  ["06", "Virtual Lab", "Simulations isolées et reproductibles.", 1],
  ["07", "Report Studio", "Rapport PDF structuré, avec empreinte SHA-256.", 1],
  ["08", "Telegram & Alerts", "Livraison du rapport au chat administrateur.", 1],
  ["09", "Subscription & Licensing", "Licences, quotas et abonnements.", 1],
  ["10", "Zero Trust Center", "Session par jeton et intégrité du journal d'audit.", 1],
  ["11", "Vulnerability Intelligence", "CVE, avis éditeurs et priorisation.", 1],
  ["12", "Communication Hub", "Support et notifications consenties.", 1],
  ["13", "Performance Lab", "Images par seconde et qualité de rendu.", 1],
  ["14", "Compliance Center", "Contrôles et écarts de conformité.", 1],
  ["15", "À propos & gouvernance", "Version, responsabilités et auteur.", 1],
];
const store = {
  get() { try { return sessionStorage.getItem("agata_t") || ""; } catch { return ""; } },
  set(v) { try { v ? sessionStorage.setItem("agata_t", v) : sessionStorage.removeItem("agata_t"); } catch { /* stockage indisponible */ } },
};
let token = store.get(), last = null, status = null, sel = 0;
let focusNode = () => {}, setSurface = () => {};
const perf = { fps: 0, set() {} };
const logEl = $("#feed");

function log(msg, kind = "") {
  logEl.prepend(el("div", { className: "ln " + kind, textContent: `${new Date().toLocaleTimeString("fr-FR")}  ${msg}` }));
  while (logEl.children.length > 40) logEl.lastChild.remove();
}
function say(msg, kind = "") { const m = $("#msg"); m.textContent = msg; m.className = "msg " + kind; log(msg, kind); }
async function api(path, opts = {}) {
  const headers = { ...(opts.body ? { "Content-Type": "application/json" } : {}), ...(token ? { Authorization: "Bearer " + token } : {}) };
  const r = await fetch(path, { ...opts, headers, cache: "no-store" });
  if (!r.ok) {
    let d = r.statusText;
    try { d = (await r.json()).detail || d; } catch { /* corps non JSON */ }
    if (Array.isArray(d)) d = d.map((x) => `${(x.loc || []).slice(1).join(".")} ${x.msg}`).join(" ; ");
    if (r.status === 401) { token = ""; store.set(""); $("#auth").textContent = "non"; }
    const err = new Error(r.status === 401 ? "Jeton absent ou refusé : ouvrez la session dans le module 10." : `${r.status} — ${d}`);
    err.status = r.status; throw err;
  }
  return r;
}
async function refreshStatus() {
  try {
    status = await (await api("/v1/status")).json();
    $("#apiState").textContent = "OK"; $("#mode").textContent = status.mode;
    $("#policy").textContent = status.active_checks_enabled ? "Actif" : "Verrouillé";
    return status;
  } catch { $("#apiState").textContent = "HORS LIGNE"; }
}

const kv = (k, v) => el("div", { className: "kv" }, el("span", { textContent: k }), el("b", { textContent: String(v) }));
const note = (t) => el("p", { className: "mut", textContent: t });
const need = () => { if (!last) throw new Error("Créez d'abord un audit."); };
function btn(label, fn, cls = "") {
  const b = el("button", { className: "action " + cls, textContent: label, type: "button" });
  b.onclick = async () => { b.disabled = true; try { await fn(); } catch (e) { if (e.status === 401) show(9); say(e.message, "bad"); } finally { b.disabled = false; } };
  return b;
}
const hostsView = (hs) => hs.map((h) => el("div", { className: "find " + (h.simulated ? "info" : "low") }, el("b", { textContent: `${h.name} · ${h.ip}` }),
  el("small", { textContent: `MAC ${h.mac ?? "n/a"} · ${h.ports.map((p) => `${p.port}/${p.service} ${p.state}`).join(", ")}` })));
const findingsView = (a) => [kv("Audit", `${a.audit_id.slice(0, 8)} · ${a.status}`), ...hostsView(a.hosts ?? []),
  ...a.findings.map((f) => el("div", { className: "find " + f.severity }, el("b", { textContent: `${f.severity.toUpperCase()} · ${f.title}` }), el("small", { textContent: f.evidence })))];

const VIEWS = {
  "01": () => { const o = el("div"); refreshStatus().then((d) => d && o.replaceChildren(kv("Mode", d.mode), kv("Contrôles actifs", d.active_checks_enabled ? "activés" : "désactivés (fail-closed)"), kv("Jeton API", d.auth_configured ? "configuré" : "absent"), kv("Version", d.version))); return [o, btn("Actualiser", () => show(sel))]; },
  "02": () => { const o = el("div"); api("/v1/assets").then((r) => r.json()).then((d) => { $("#assetCount").textContent = d.items.length; o.replaceChildren(...d.items.map((a) => el("div", { className: "find info" }, el("b", { textContent: `${a.id} · ${a.kind}` }), el("small", { textContent: a.label + (a.simulated ? " — simulé" : "") })))); }).catch((e) => log(e.message, "bad")); return [o, note("Données illustratives : branchez une source de découverte approuvée.")]; },
  "03": () => {
    const out = el("div"), t = el("input", { placeholder: "Cible (IP ou hôte autorisé)", autocomplete: "off", spellcheck: false });
    const p = el("input", { placeholder: "Ports, ex. 8000,8080", value: "8000", inputMode: "numeric" });
    const g = el("input", { placeholder: "ID d'engagement", autocomplete: "off" }), c = el("input", { type: "checkbox" });
    const run = (path, payload) => async () => {
      last = await (await api(path, { method: "POST", body: JSON.stringify(payload()) })).json();
      $("#riskCount").textContent = String(last.findings.length).padStart(2, "0");
      out.replaceChildren(...findingsView(last)); setSurface(last.hosts); say(`Audit ${last.audit_id.slice(0, 8)} — ${last.status}`, "ok");
    };
    return [btn("Créer un audit démo (simulé)", run("/v1/audits/demo", () => ({ target_label: "LAB-DEMO" }))), el("hr"),
      note(status?.active_checks_enabled === false ? "Contrôles actifs verrouillés côté serveur : définissez AGATA_ACTIVE_CHECKS=true, AGATA_ALLOWED_TARGETS et AGATA_ALLOWED_PORTS sur Render." : "Contrôle TCP réel : jeton requis, cible et ports dans la liste blanche."), t, p, g,
      el("label", { className: "chk" }, c, " J'atteste disposer d'une autorisation écrite"),
      btn("Lancer le contrôle TCP", run("/v1/audits/connect-check", () => ({ target: t.value.trim(), ports: p.value.split(",").map((x) => parseInt(x, 10)).filter(Number.isInteger), engagement_id: g.value.trim(), authorization_confirmed: c.checked })), "warn"), out];
  },
  "05": () => [kv("Gemini", status?.gemini_configured ? "configuré" : "non configuré"), note("La synthèse IA est ajoutée aux audits des sessions authentifiées. Elle est consultative et ne constitue pas une preuve.")],
  "07": () => [btn("Télécharger le rapport PDF", async () => { need(); const r = await api(`/v1/audits/${last.audit_id}/report.pdf`); const u = URL.createObjectURL(await r.blob()); el("a", { href: u, download: `AgAtA-SpiDeR-${last.audit_id.slice(0, 8)}.pdf` }).click(); setTimeout(() => URL.revokeObjectURL(u), 5000); say("Rapport PDF téléchargé.", "ok"); }), note("Le PDF contient l'empreinte SHA-256 des constats.")],
  "08": () => [kv("Telegram", status?.telegram_configured ? "configuré" : "non configuré"),
    btn("Envoyer le PDF sur Telegram", async () => { need(); const d = await (await api(`/v1/audits/${last.audit_id}/telegram`, { method: "POST" })).json(); say(d.sent ? "PDF envoyé sur Telegram." : d.reason, d.sent ? "ok" : "bad"); }),
    btn("Tester la notification", async () => { const d = await (await api("/v1/notify/test", { method: "POST" })).json(); say(d.sent ? "Notification envoyée." : d.reason, d.sent ? "ok" : "bad"); }),
    note("Jeton requis. Le bot doit avoir reçu /start depuis le chat administrateur.")],
  "10": () => {
    const i = el("input", { type: "password", placeholder: "Jeton API", autocomplete: "off" });
    return [note("Le jeton reste en mémoire, jamais stocké. Il protège les contrôles actifs, les audits réels, Telegram et l'intégrité."), i,
      btn("Ouvrir la session et vérifier l'intégrité", async () => {
        token = i.value.trim(); i.value = ""; store.set(token);
        try { const d = await (await api("/v1/integrity")).json(); $("#auth").textContent = "oui"; say(`Session ouverte — journal ${d.valid ? "intègre" : "ALTÉRÉ"} (${d.records} enregistrements)`, d.valid ? "ok" : "bad"); }
        catch (e) { token = ""; store.set(""); $("#auth").textContent = "non"; throw e; }
      })];
  },
  "13": () => [kv("Images/s", perf.fps), btn("Qualité réduite", () => perf.set(0.6)), btn("Qualité haute", () => perf.set(1))],
  "15": () => [kv("Version", status?.version ?? "—"), note("Conçu par Dr Enoch Numbi, fondateur de l'écosystème DorkNet, architecte système et chercheur en cybersécurité (Kinshasa, RDC)."), note("Journal d'audit chaîné SHA-256, politique fail-closed, périmètre explicitement autorisé.")],
};

Object.assign(VIEWS, {
  "04": () => {
    const o = el("div");
    const load = async () => { const d = await (await api("/v1/graph")).json(); setSurface(d.hosts); o.replaceChildren(...hostsView(d.hosts)); say(`${d.hosts.length} hôte(s) sur la toile${d.sample ? " (échantillon simulé)" : ""}.`, "ok"); };
    load().catch((e) => say(e.message, "bad"));
    return [o, btn("Actualiser la surface", load), note("Vert : hôte réel · orange : simulé. Points verts : ports ouverts, gris : fermés, ambre : filtrés. La MAC n'est connue que pour un voisin du même réseau local.")];
  },
  "06": () => {
    const s = el("input", { placeholder: "Graine (entier)", value: "42", inputMode: "numeric" }), n = el("input", { placeholder: "Hôtes (1 à 12)", value: "5", inputMode: "numeric" }), out = el("div");
    return [note("Topologie virtuelle reproductible : même graine, même résultat. Aucun paquet n'est envoyé."), s, n,
      btn("Lancer la simulation", async () => {
        last = await (await api("/v1/lab/simulate", { method: "POST", body: JSON.stringify({ seed: parseInt(s.value, 10) || 0, hosts: parseInt(n.value, 10) || 5 }) })).json();
        $("#riskCount").textContent = String(last.findings.length).padStart(2, "0"); setSurface(last.hosts); out.replaceChildren(...findingsView(last));
        say(`Simulation ${last.audit_id.slice(0, 8)} : ${last.hosts.length} hôtes, ${last.findings.length} constats.`, "ok");
      }), out];
  },
  "09": () => {
    const o = el("div");
    api("/v1/license").then((r) => r.json()).then((d) => o.replaceChildren(kv("Plan", d.plan), kv("Audits aujourd'hui", `${d.usage.audits_today} / ${d.limits.daily_audits}`), kv("Requêtes / min", d.limits.requests_per_min), kv("Opérations lourdes / min", d.limits.heavy_per_min), kv("Ports par contrôle", d.limits.ports_per_check))).catch((e) => say(e.message, "bad"));
    return [o, note("Plan et quotas se règlent côté serveur : AGATA_PLAN, AGATA_DAILY_QUOTA, AGATA_RATE_PER_MIN.")];
  },
  "11": () => {
    const q = el("input", { placeholder: "CVE-2021-44228 ou mot-clé (ex. openssl)", autocomplete: "off" }), out = el("div");
    const go = async () => {
      const d = await (await api("/v1/cve?q=" + encodeURIComponent(q.value.trim()))).json();
      out.replaceChildren(...(d.items.length ? d.items.map((v) => el("div", { className: "find " + v.severity }, el("b", { textContent: `${v.id} · ${v.score ?? "?"} ${v.severity.toUpperCase()}` }), el("small", { textContent: `${v.published} — ${v.summary}` }))) : [note("Aucun résultat.")]));
      say(`${d.items.length} résultat(s) NVD.`, "ok");
    };
    return [note("Source : base NVD du NIST, interrogée côté serveur."), q, btn("Rechercher", go), out];
  },
  "12": () => {
    const m = el("input", { placeholder: "Votre message (10 caractères minimum)" }), c = el("input", { placeholder: "Contact (optionnel)", autocomplete: "off" }), k = el("input", { type: "checkbox" }), out = el("div");
    if (token) api("/v1/support").then((r) => r.json()).then((d) => out.replaceChildren(...d.items.map((x) => el("div", { className: "find info" }, el("b", { textContent: `${x.created_at.slice(0, 16)} · ${x.contact || "anonyme"}` }), el("small", { textContent: x.message }))))).catch(() => {});
    return [m, c, el("label", { className: "chk" }, k, " J'accepte d'être recontacté à propos de ce message"),
      btn("Envoyer au support", async () => {
        const d = await (await api("/v1/support", { method: "POST", body: JSON.stringify({ message: m.value.trim(), contact: c.value.trim(), consent: k.checked }) })).json();
        m.value = ""; say(d.telegram_notified ? "Message enregistré et transmis sur Telegram." : "Message enregistré (Telegram non configuré).", "ok");
      }), out];
  },
  "14": () => {
    const out = el("div");
    return [note("Auto-évaluation interne de la configuration, sans valeur de certification. Jeton requis."),
      btn("Lancer l'évaluation", async () => {
        last = await (await api("/v1/compliance/audit", { method: "POST" })).json();
        $("#riskCount").textContent = String(last.findings.length).padStart(2, "0");
        out.replaceChildren(...last.controls.map((c) => el("div", { className: "find " + (c.ok ? "low" : c.severity) }, el("b", { textContent: `${c.ok ? "CONFORME" : "ÉCART"} · ${c.control}` }), el("small", { textContent: c.ok ? "" : c.fix }))));
        say(`Évaluation : ${last.status}.`, last.findings.some((f) => f.severity !== "info") ? "bad" : "ok");
      }), out];
  },
});

function show(i) {
  sel = i;
  $("#msg").textContent = ""; $("#msg").className = "msg";
  const [id, name, desc, live] = MODULES[i];
  $("#dTitle").textContent = `${id} · ${name}`; $("#dDesc").textContent = desc;
  const b = $("#dBadge"); b.textContent = live ? "Actif" : "À venir"; b.className = "badge " + (live ? "on" : "off");
  $("#dBody").replaceChildren(...(VIEWS[id]?.() ?? [note("Module non implémenté dans cette version : aucune donnée n'est simulée ici.")]));
  document.querySelectorAll("#menu button").forEach((x, k) => x.classList.toggle("active", k === i));
  focusNode(i);
}

MODULES.forEach((m, i) => {
  const b = el("button", { type: "button", className: m[3] ? "" : "soon" }, el("i", { textContent: m[0] }), m[1]);
  b.style.setProperty("--dl", `${-i * 0.45}s`); b.onclick = () => { show(i); log("Module : " + m[1]); };
  $("#menu").append(b);
});
$("#min").onclick = () => $("#detail").classList.toggle("min");
addEventListener("pointermove", (e) => {
  const s = $("#stage").style;
  s.setProperty("--ry", ((e.clientX / innerWidth - 0.5) * 7).toFixed(2) + "deg");
  s.setProperty("--rx", ((0.5 - e.clientY / innerHeight) * 6).toFixed(2) + "deg");
}, { passive: true });

function initScene(renderer) {
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const cap = innerWidth < 860 ? 1.5 : 1.8;
  let scale = 1, picked = 0;
  perf.set = (q) => { scale = q; renderer.setPixelRatio(Math.min(devicePixelRatio, cap) * scale); renderer.setSize(innerWidth, innerHeight, false); log(`Qualité ${q < 1 ? "réduite" : "haute"}`); };
  renderer.setPixelRatio(Math.min(devicePixelRatio, cap));
  const scene = new THREE.Scene(); scene.fog = new THREE.FogExp2(0x04070f, 0.035);
  const camera = new THREE.PerspectiveCamera(50, innerWidth / innerHeight, 0.1, 100);
  const rig = new THREE.Group(); scene.add(rig);
  scene.add(new THREE.AmbientLight(0x7fb4d4, 1.1));
  const key = new THREE.PointLight(0x5cecff, 90, 40); key.position.set(4, 5, 9); scene.add(key);
  const rim = new THREE.PointLight(0xff5a87, 60, 40); rim.position.set(-6, -4, 6); scene.add(rim);

  // Toile : 16 rayons, 9 anneaux, 15 nœuds (un par module)
  const R = 6.4, SP = 16, RINGS = 9;
  const P = (a, r) => [Math.cos(a) * r, Math.sin(a) * r, Math.sin(a * 3 + r) * 0.25];
  const spokes = [], rings = [];
  for (let s = 0; s < SP; s++) spokes.push(0, 0, 0, ...P((s / SP) * TAU, R));
  for (let k = 1; k <= RINGS; k++) for (let s = 0; s < SP; s++) rings.push(...P((s / SP) * TAU, (R * k) / RINGS), ...P(((s + 1) / SP) * TAU, (R * k) / RINGS));
  const lines = (arr, color, opacity) => { const g = new THREE.BufferGeometry(); g.setAttribute("position", new THREE.Float32BufferAttribute(arr, 3)); return new THREE.LineSegments(g, new THREE.LineBasicMaterial({ color, transparent: true, opacity, depthWrite: false })); };
  const web = new THREE.Group(), spokeL = lines(spokes, 0x5cecff, 0.55), ringL = lines(rings, 0x2f8fc4, 0.45);
  web.add(spokeL, ringL); rig.add(web);
  const nodes = MODULES.map((m, i) => {
    const [x, y, z] = P((i / SP) * TAU, (R * (4 + (i % 4))) / RINGS), col = m[3] ? 0x5cecff : 0x3b6a8a;
    const g = new THREE.Group(); g.position.set(x, y, z);
    const core = new THREE.Mesh(new THREE.SphereGeometry(0.11, 16, 12), new THREE.MeshBasicMaterial({ color: col }));
    const halo = new THREE.Mesh(new THREE.SphereGeometry(0.26, 16, 12), new THREE.MeshBasicMaterial({ color: col, transparent: true, opacity: 0.14, blending: THREE.AdditiveBlending, depthWrite: false }));
    g.add(core, halo); web.add(g); return { g, core, halo, col, ph: i * 0.7 };
  });

  // Poussière de données
  const N = 450, pp = new Float32Array(N * 3);
  for (let i = 0; i < N; i++) { const r = 3 + Math.random() * 9, a = Math.random() * TAU, b = Math.acos(2 * Math.random() - 1); pp.set([r * Math.sin(b) * Math.cos(a), r * Math.sin(b) * Math.sin(a), r * Math.cos(b) * 0.6], i * 3); }
  const dust = new THREE.Points(new THREE.BufferGeometry().setAttribute("position", new THREE.BufferAttribute(pp, 3)), new THREE.PointsMaterial({ color: 0x8fe9ff, size: 0.045, transparent: true, opacity: 0.7, depthWrite: false, blending: THREE.AdditiveBlending }));
  rig.add(dust);

  // Araignée : corps, yeux, marque, 8 pattes articulées, anneaux orbitaux
  const spider = new THREE.Group(); spider.scale.setScalar(1.15); rig.add(spider);
  const hull = new THREE.MeshStandardMaterial({ color: 0x0c1c30, metalness: 0.55, roughness: 0.35, emissive: 0x0a3a55, emissiveIntensity: 0.9 });
  const neon = new THREE.MeshBasicMaterial({ color: 0x5cecff }), hot = new THREE.MeshBasicMaterial({ color: 0xff5a87 });
  const abd = new THREE.Mesh(new THREE.SphereGeometry(0.62, 36, 28), hull); abd.position.y = -0.95; abd.scale.set(1, 1.3, 0.9);
  const ceph = new THREE.Mesh(new THREE.SphereGeometry(0.42, 28, 20), hull); ceph.position.y = 0.15; ceph.scale.z = 0.85;
  const mark = new THREE.Mesh(new THREE.SphereGeometry(0.2, 16, 12), hot); mark.position.set(0, -0.8, 0.52);
  spider.add(abd, ceph, mark);
  [-0.14, -0.05, 0.05, 0.14].forEach((x) => [0, 1].forEach((row) => { const e = new THREE.Mesh(new THREE.SphereGeometry(row ? 0.035 : 0.05, 8, 8), neon); e.position.set(x * (row ? 1.4 : 1), 0.5 + row * 0.04, 0.3); spider.add(e); }));
  const seg = (len, rad) => { const g = new THREE.CylinderGeometry(rad * 0.65, rad, len, 8); g.rotateZ(-Math.PI / 2); g.translate(len / 2, 0, 0); return new THREE.Mesh(g, hull); };
  const joint = (r) => new THREE.Mesh(new THREE.SphereGeometry(r, 10, 8), neon);
  const legs = [];
  [1, -1].forEach((side) => [58, 20, -22, -58].forEach((deg, j) => {
    const a = side > 0 ? (deg * Math.PI) / 180 : Math.PI - (deg * Math.PI) / 180;
    const base = new THREE.Group(); base.position.set(side * 0.3, 0.15 + (1.5 - j) * 0.15, 0); base.rotation.z = a;
    const lift = new THREE.Group(); lift.rotation.y = -0.3; base.add(lift);
    const knee = new THREE.Group(); knee.position.x = 1.05; const ankle = new THREE.Group(); ankle.position.x = 1.35;
    lift.add(seg(1.05, 0.075), knee); knee.add(joint(0.085), seg(1.35, 0.06), ankle); ankle.add(joint(0.06), seg(0.7, 0.04));
    spider.add(base); legs.push({ base, knee, ankle, a, side, ph: ((j + (side > 0 ? 0 : 1)) % 2) * Math.PI });
  }));
  const orbit = new THREE.Group(); orbit.position.set(0, -0.3, 0); spider.add(orbit);
  [[2.9, 0x5cecff, 0.5], [3.5, 0xff5a87, 0.35], [4.1, 0x2f8fc4, 0.4]].forEach(([r, c, o], i) => { const m = new THREE.Mesh(new THREE.TorusGeometry(r, 0.012, 6, 160), new THREE.MeshBasicMaterial({ color: c, transparent: true, opacity: o })); m.rotation.set(1.1 + i * 0.35, i * 0.6, 0); orbit.add(m); });

  // Surface d'attaque : hôtes (IP, MAC) et ports flottants sur la toile
  const surface = new THREE.Group(); surface.position.z = -0.6; rig.add(surface);
  const spin = [], PORT = { open: 0x37e6a0, closed: 0x6b8299 };
  const label = (lines, w) => {
    const c = document.createElement("canvas"); c.width = 512; c.height = 20 + lines.length * 36;
    const x = c.getContext("2d"); x.fillStyle = "rgba(6,16,30,.8)"; x.fillRect(0, 0, c.width, c.height);
    x.strokeStyle = "#5cecff"; x.strokeRect(1, 1, c.width - 2, c.height - 2); x.font = "bold 26px monospace";
    lines.forEach((l, i) => { x.fillStyle = i ? "#b9d8ee" : "#5cecff"; x.fillText(String(l).slice(0, 30), 14, 36 + i * 36); });
    const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: new THREE.CanvasTexture(c), transparent: true, depthTest: false }));
    s.scale.set(w, (w * c.height) / c.width, 1); s.renderOrder = 5; return s;
  };
  setSurface = (hosts = []) => {
    while (surface.children.length) { const o = surface.children[0]; surface.remove(o); o.traverse((m) => { m.geometry?.dispose(); m.material?.map?.dispose(); m.material?.dispose(); }); }
    spin.length = 0;
    const wide = innerWidth >= 860, rx = wide ? 4.6 : 1.7, ry = wide ? 3.4 : 2.6, cy = wide ? 0 : -1.4, list = hosts.slice(0, 8), pos = {};
    list.forEach((h, j) => {
      const a = (j / list.length) * TAU + 0.35, g = new THREE.Group(), ring = new THREE.Group(), open = h.ports.filter((p) => p.state === "open").map((p) => p.port);
      g.position.set(Math.cos(a) * rx, Math.sin(a) * ry + cy, 0); pos[h.ip] = g.position;
      g.add(new THREE.Mesh(new THREE.OctahedronGeometry(0.24), new THREE.MeshBasicMaterial({ color: h.simulated ? 0xffc266 : 0x37e6a0, wireframe: true })), ring);
      h.ports.slice(0, 8).forEach((p, k, arr) => { const b = (k / arr.length) * TAU, m = new THREE.Mesh(new THREE.SphereGeometry(0.08, 10, 8), new THREE.MeshBasicMaterial({ color: PORT[p.state] ?? 0xffc266 })); m.position.set(Math.cos(b) * 0.65, Math.sin(b) * 0.65, 0); ring.add(m); });
      const l = label([h.name, h.ip, "MAC " + (h.mac ?? "n/a"), open.length ? "ouverts " + open.join(" ") : "aucun port ouvert"], wide ? 2.6 : 2.2);
      l.position.set(0, -1.1, 0.2); g.add(l); spin.push(ring); surface.add(g);
    });
    list.forEach((h) => { if (h.via && pos[h.via] && pos[h.ip]) surface.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints([pos[h.via], pos[h.ip]]), new THREE.LineBasicMaterial({ color: 0xffc266, transparent: true, opacity: 0.6 }))); });
  };

  const pointer = { x: 0, y: 0 }, look = new THREE.Vector3(), lookT = new THREE.Vector3();
  addEventListener("pointermove", (e) => { pointer.x = e.clientX / innerWidth - 0.5; pointer.y = e.clientY / innerHeight - 0.5; }, { passive: true });
  focusNode = (i) => { picked = i; lookT.set(nodes[i].g.position.x * 0.1, nodes[i].g.position.y * 0.1, 0); };
  const fit = () => { const asp = innerWidth / innerHeight; camera.aspect = asp; camera.position.z = asp < 0.9 ? 13.5 : 11; rig.position.y = innerWidth < 860 ? 1.2 : 0; camera.updateProjectionMatrix(); renderer.setSize(innerWidth, innerHeight, false); };
  fit(); addEventListener("resize", fit);
  renderer.domElement.addEventListener("webglcontextlost", (e) => { e.preventDefault(); log("Contexte WebGL perdu — rechargez la page.", "bad"); });

  const clock = new THREE.Clock(); let fpsT = performance.now(), fr = 0, low = 0;
  renderer.setAnimationLoop(() => {
    if (document.hidden) return;
    const t = clock.getElapsedTime() * (reduce ? 0.2 : 1);
    web.rotation.set(Math.sin(t * 0.3) * 0.06, Math.cos(t * 0.25) * 0.06, t * 0.02);
    spokeL.material.opacity = 0.5 + 0.12 * Math.sin(t * 1.5); ringL.material.opacity = 0.42 + 0.08 * Math.sin(t * 1.1 + 1);
    nodes.forEach((n, i) => {
      const on = i === picked, c = on ? 0xff5a87 : n.col;
      n.g.scale.setScalar(on ? 1.7 + 0.3 * Math.sin(t * 6) : 1 + 0.15 * Math.sin(t * 2 + n.ph));
      n.core.material.color.setHex(c); n.halo.material.color.setHex(c);
    });
    spider.position.set(Math.sin(t * 0.35) * 1.1, Math.cos(t * 0.27) * 0.7, 0.8); spider.rotation.z = Math.sin(t * 0.5) * 0.18;
    abd.scale.y = 1.3 + 0.03 * Math.sin(t * 2.2);
    const pl = 0.85 + 0.15 * Math.sin(t * 3); mark.scale.set(0.7 * pl, 1.1 * pl, 0.22);
    for (const L of legs) {
      const s = Math.sin(t * 2.6 + L.ph);
      L.base.rotation.z = L.a - L.side * 0.1 * s;
      L.knee.rotation.z = -L.side * (0.9 + 0.25 * Math.max(0, Math.sin(t * 2.6 + L.ph + 1.4)));
      L.ankle.rotation.z = -L.side * (0.4 + 0.12 * s);
    }
    orbit.rotation.set(Math.sin(t * 0.4) * 0.3, 0, t * 0.25);
    spin.forEach((g, i) => { g.rotation.z = t * (0.7 + i * 0.08); }); surface.position.y = Math.sin(t * 0.6) * 0.12;
    dust.rotation.set(Math.sin(t * 0.1) * 0.05, t * 0.015, 0);
    camera.position.x += (pointer.x * 1.6 - camera.position.x) * 0.04; camera.position.y += (-pointer.y * 1.0 - camera.position.y) * 0.04;
    look.lerp(lookT, 0.04); camera.lookAt(look); key.position.x = 4 + Math.sin(t * 0.7) * 2;
    renderer.render(scene, camera);
    fr++; const now = performance.now();
    if (now - fpsT >= 1000) {
      perf.fps = Math.round((fr * 1000) / (now - fpsT)); $("#fps").textContent = perf.fps; fr = 0; fpsT = now;
      low = perf.fps < 28 ? low + 1 : 0;
      if (low >= 3 && scale > 0.6) { perf.set(Math.max(0.6, scale - 0.2)); low = 0; }
    }
  });
}

let renderer = null;
try { renderer = new THREE.WebGLRenderer({ canvas: $("#scene"), antialias: true, alpha: true, powerPreference: "high-performance" }); }
catch { document.body.classList.add("no-webgl"); log("WebGL indisponible : interface 2D uniquement.", "bad"); }
if (renderer) initScene(renderer);
if (token) $("#auth").textContent = "oui";
show(0); refreshStatus(); api("/v1/graph").then((r) => r.json()).then((d) => setSurface(d.hosts)).catch(() => {});
setInterval(refreshStatus, 30000);
log("Interface prête.");
