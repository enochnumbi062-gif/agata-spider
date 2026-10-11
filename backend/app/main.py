"""AgAtA-SpiDeR API — audit de sécurité autorisé, durci pour un déploiement public (Render)."""
import asyncio
import hashlib
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import auditlog, config, lab, security
from .compliance import evaluate
from .integrations import cve_search, gemini_summary, telegram_send_document, telegram_send_text
from .policy import resolve_pinned, validate_connect_check
from .reporting import create_pdf
from .schemas import ConnectCheckRequest, DemoAuditRequest, Finding, SimRequest, SupportRequest

STATIC = Path(__file__).parent / "static"
AI_OFF = {"enabled": False, "summary": "Analyse IA non exécutée (session non authentifiée ou service non configuré).", "recommendations": []}
AI_DOWN = {"enabled": False, "summary": "Service IA indisponible ; audit conservé sans analyse IA.", "recommendations": []}
RL = [Depends(security.rate_limit)]
AUTH = [Depends(security.rate_limit), Depends(security.require_token)]
HEAVY = [Depends(security.heavy_limit), Depends(security.require_token)]
PUBLIC_MODES = ("demo", "simulation")


@asynccontextmanager
async def lifespan(_: FastAPI):
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    auditlog.append_event({"event": "startup", "version": config.VERSION, "mode": config.MODE})
    yield


app = FastAPI(title="AgAtA-SpiDeR API", version=config.VERSION, lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)
if config.CORS_ORIGINS:
    app.add_middleware(CORSMiddleware, allow_origins=config.CORS_ORIGINS, allow_credentials=False,
                       allow_methods=["GET", "POST"], allow_headers=["Content-Type", "Authorization"])


@app.middleware("http")
async def harden(request: Request, call_next):
    try:
        too_big = int(request.headers.get("content-length") or 0) > 16_384
    except ValueError:
        too_big = True
    if too_big:
        return JSONResponse({"detail": "Payload too large"}, status_code=413)
    response = await call_next(request)
    for k, v in security.HEADERS.items():
        response.headers.setdefault(k, v)
    if request.url.path.startswith(("/v1", "/health")):
        response.headers["Cache-Control"] = "no-store"
    return response


async def tcp_connect(ip: str, port: int, timeout: float = 1.5) -> dict:
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        w.close()
        try:
            await w.wait_closed()
        except OSError:
            pass
        return {"port": port, "state": "open", "evidence": "TCP connection succeeded"}
    except ConnectionRefusedError:
        return {"port": port, "state": "closed", "evidence": "Connection refused"}
    except TimeoutError:
        return {"port": port, "state": "filtered_or_timeout", "evidence": "Connection timed out"}
    except OSError as e:
        return {"port": port, "state": "error", "evidence": f"Socket error: {type(e).__name__}"}


async def _finish(audit: dict, with_ai: bool) -> dict:
    if await asyncio.to_thread(auditlog.count_audits_since, auditlog.utc_now()[:10]) >= config.DAILY_QUOTA:
        raise HTTPException(429, "Quota quotidien d'audits atteint pour ce plan")
    audit["findings_hash_sha256"] = auditlog.canonical_hash(audit["findings"])
    audit["ai"] = AI_OFF
    if with_ai:
        try:
            audit["ai"] = await gemini_summary(audit["findings"])
        except Exception:
            audit["ai"] = AI_DOWN
    await asyncio.to_thread(auditlog.save_audit, audit)
    auditlog.append_event({"event": "audit_created", "audit_id": audit["audit_id"], "mode": audit["mode"],
                           "record_sha256": auditlog.canonical_hash(audit)})
    return audit


def _audit_or_404(audit_id: uuid.UUID, request: Request) -> dict:
    audit = auditlog.load_audit(str(audit_id))
    if not audit:
        raise HTTPException(404, "Audit not found")
    if audit.get("mode") not in PUBLIC_MODES:
        security.require_token(request)
    return audit


@app.get("/health")
def health():
    return {"status": "ok", "version": config.VERSION}


@app.get("/v1/status", dependencies=RL)
def status():
    return {"version": config.VERSION, "mode": config.MODE, "active_checks_enabled": config.ACTIVE_CHECKS,
            "auth_configured": bool(config.API_TOKEN), "gemini_configured": bool(config.GEMINI_API_KEY),
            "telegram_configured": bool(config.TELEGRAM_BOT_TOKEN and config.TELEGRAM_ADMIN_CHAT_ID)}


def _asset(h: dict) -> dict:
    op = ",".join(str(p["port"]) for p in h["ports"] if p["state"] == "open") or "aucun"
    return {"id": h["name"], "kind": "hôte", "simulated": bool(h.get("simulated")),
            "label": f"{h['ip']} · MAC {h.get('mac') or 'n/a'} · ouverts : {op}"}


@app.get("/v1/assets", dependencies=RL)
def assets(request: Request):
    hosts = lab.simulate(1, 3)[0]
    if security.has_valid_token(request):
        hosts = [h for a in auditlog.list_audits(25) for h in a.get("hosts", []) if not h.get("simulated")] + hosts
    return {"items": [_asset(h) for h in hosts], "note": "Hôtes réels issus de vos audits (session ouverte) + échantillon simulé."}


@app.get("/v1/integrity", dependencies=AUTH)
async def integrity():
    return await asyncio.to_thread(auditlog.verify_chain)


@app.get("/v1/audits", dependencies=AUTH)
def list_audits():
    keys = ("audit_id", "created_at", "mode", "status", "target_label", "target")
    return {"items": [{k: a.get(k) for k in keys} | {"findings": len(a.get("findings", []))}
                      for a in auditlog.list_audits(25)]}


@app.post("/v1/audits/demo", dependencies=[Depends(security.heavy_limit)])
async def demo_audit(req: DemoAuditRequest, request: Request):
    findings = [
        Finding(title="Revue des en-têtes de sécurité", severity="medium",
                description="Constat illustratif : vérifier Content-Security-Policy et les en-têtes associés.",
                evidence="SIMULÉ — aucune requête envoyée à une cible.", simulated=True,
                recommendation="Valider les en-têtes selon un plan de test approuvé."),
        Finding(title="Revue de la configuration TLS", severity="low",
                description="Constat illustratif : vérifier versions de protocole et suites de chiffrement.",
                evidence="SIMULÉ — aucune poignée de main TLS effectuée.", simulated=True,
                recommendation="Appliquer les profils TLS approuvés et les guides éditeurs à jour.")]
    audit = {"audit_id": str(uuid.uuid4()), "created_at": auditlog.utc_now(), "mode": "demo",
             "target_label": req.target_label, "status": "completed_simulated",
             "findings": [f.model_dump() for f in findings], "hosts": lab.simulate(1, 3)[0]}
    return await _finish(audit, security.has_valid_token(request))


@app.post("/v1/audits/connect-check", dependencies=HEAVY)
async def connect_check(req: ConnectCheckRequest, request: Request):
    ip = security.client_ip(request)
    try:
        target = validate_connect_check(req.target, req.ports, req.engagement_id, req.authorization_confirmed)
        addrs = await asyncio.to_thread(resolve_pinned, target)
    except PermissionError as e:
        auditlog.append_event({"event": "active_check_denied", "reason": str(e), "target": req.target[:253], "client": ip})
        raise HTTPException(403, str(e))
    except (ValueError, OSError):
        raise HTTPException(400, "Invalid or unresolvable target")
    sem = asyncio.Semaphore(5)

    async def one(port: int) -> dict:
        async with sem:
            return await tcp_connect(addrs[0], port)

    try:
        results = await asyncio.wait_for(asyncio.gather(*[one(p) for p in req.ports]), timeout=10)
    except TimeoutError:
        raise HTTPException(504, "Check timed out")
    findings = [Finding(title=f"Port TCP {r['port']} : {r['state']}", severity="info",
                        description="Résultat d'un contrôle de connexion TCP uniquement ; il n'identifie aucune vulnérabilité.",
                        evidence=r["evidence"],
                        recommendation="Confirmer le propriétaire du service et comparer l'exposition à la politique approuvée.")
                for r in results]
    host = {"ip": addrs[0], "name": target, "mac": await asyncio.to_thread(lab.mac_for, addrs[0]), "via": None,
            "simulated": False, "ports": [{"port": r["port"], "state": r["state"], "service": lab.SERVICES.get(r["port"], "tcp")}
                                          for r in results]}
    audit = {"audit_id": str(uuid.uuid4()), "created_at": auditlog.utc_now(), "mode": config.MODE, "target": target,
             "resolved": addrs[:4], "engagement_id": req.engagement_id, "status": "completed",
             "findings": [f.model_dump() for f in findings], "hosts": [host]}
    return await _finish(audit, True)


@app.get("/v1/audits/{audit_id}", dependencies=RL)
def get_audit(audit_id: uuid.UUID, request: Request):
    return _audit_or_404(audit_id, request)


@app.get("/v1/audits/{audit_id}/report.pdf", dependencies=RL)
async def get_report(audit_id: uuid.UUID, request: Request):
    audit = await asyncio.to_thread(_audit_or_404, audit_id, request)
    pdf = await asyncio.to_thread(create_pdf, audit)
    digest = hashlib.sha256(pdf).hexdigest()
    auditlog.append_event({"event": "report_generated", "audit_id": str(audit_id), "sha256": digest})
    return Response(pdf, media_type="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="AgAtA-SpiDeR-{str(audit_id)[:8]}.pdf"', "X-Report-SHA256": digest})


@app.post("/v1/audits/{audit_id}/telegram", dependencies=HEAVY)
async def send_to_telegram(audit_id: uuid.UUID, request: Request):
    audit = await asyncio.to_thread(_audit_or_404, audit_id, request)
    pdf = await asyncio.to_thread(create_pdf, audit)
    try:
        sent = await telegram_send_document(pdf, f"AgAtA-SpiDeR-{str(audit_id)[:8]}.pdf",
                                            f"Audit {str(audit_id)[:8]} — {audit['status']}")
    except Exception as e:
        auditlog.append_event({"event": "telegram_delivery_failed", "audit_id": str(audit_id)})
        raise HTTPException(502, str(e) if isinstance(e, RuntimeError) else "Telegram injoignable")
    auditlog.append_event({"event": "telegram_delivery", "audit_id": str(audit_id), "sent": sent})
    return {"sent": sent, "reason": None if sent else "Identifiants Telegram non configurés"}


@app.post("/v1/lab/simulate", dependencies=[Depends(security.heavy_limit)])
async def lab_simulate(req: SimRequest, request: Request):
    hosts, findings = lab.simulate(req.seed, req.hosts)
    findings = findings or [Finding(title="Aucun service sensible exposé", severity="info",
                                    description="La topologie simulée n'expose aucun service à risque connu.",
                                    evidence=f"SIMULÉ (graine {req.seed}).", simulated=True).model_dump()]
    audit = {"audit_id": str(uuid.uuid4()), "created_at": auditlog.utc_now(), "mode": "simulation",
             "target_label": f"Lab graine {req.seed}", "seed": req.seed, "status": "completed_simulated",
             "findings": findings, "hosts": hosts}
    return await _finish(audit, security.has_valid_token(request))


@app.get("/v1/graph", dependencies=RL)
def graph(request: Request):
    authed = security.has_valid_token(request)
    seen, out = set(), []
    for a in auditlog.list_audits(25):
        if authed or a.get("mode") in PUBLIC_MODES:
            for h in a.get("hosts", []):
                if h["ip"] not in seen:
                    seen.add(h["ip"])
                    out.append(h)
    if not out:
        return {"hosts": lab.simulate(1, 3)[0], "sample": True, "authenticated": authed}
    return {"hosts": out[:16], "sample": False, "authenticated": authed}


@app.get("/v1/license", dependencies=RL)
def license_info():
    return {"plan": config.PLAN, "limits": {"daily_audits": config.DAILY_QUOTA, "requests_per_min": config.RATE_PER_MIN,
                                            "heavy_per_min": config.HEAVY_PER_MIN, "ports_per_check": 10},
            "usage": {"audits_today": auditlog.count_audits_since(auditlog.utc_now()[:10])}}


@app.get("/v1/cve", dependencies=[Depends(security.heavy_limit)])
async def cve(q: str = Query(min_length=2, max_length=80, pattern=r"^[\w .:\-/+]+$")):
    try:
        return {"items": await cve_search(q.strip())}
    except Exception:
        raise HTTPException(502, "Source NVD indisponible ou limitée ; réessayez dans une minute")


@app.post("/v1/support", dependencies=[Depends(security.heavy_limit)])
async def support(req: SupportRequest):
    if not req.consent:
        raise HTTPException(422, "Le consentement est requis pour être recontacté")
    await asyncio.to_thread(auditlog.save_message, {"created_at": auditlog.utc_now(), "message": req.message, "contact": req.contact})
    auditlog.append_event({"event": "support_message"})
    try:
        notified = await telegram_send_text("Support AgAtA-SpiDeR\n" + req.message + (f"\nContact : {req.contact}" if req.contact else ""))
    except Exception:
        notified = False
    return {"stored": True, "telegram_notified": notified}


@app.get("/v1/support", dependencies=AUTH)
def support_list():
    return {"items": auditlog.list_messages(25)}


@app.post("/v1/notify/test", dependencies=HEAVY)
async def notify_test():
    try:
        sent = await telegram_send_text("AgAtA-SpiDeR : test de notification réussi.")
    except RuntimeError as e:
        raise HTTPException(502, str(e))
    except Exception:
        raise HTTPException(502, "Telegram injoignable")
    return {"sent": sent, "reason": None if sent else "Identifiants Telegram non configurés sur le serveur"}


@app.post("/v1/compliance/audit", dependencies=HEAVY)
async def compliance_audit(request: Request):
    https = request.headers.get("x-forwarded-proto") == "https" or request.url.scheme == "https"
    controls = await asyncio.to_thread(evaluate, https)
    bad = [c for c in controls if not c["ok"]]
    findings = [Finding(title=c["control"], severity=c["severity"], evidence="Contrôle calculé sur la configuration en cours.",
                        description="Écart détecté par l'auto-évaluation interne (ne constitue pas une certification).",
                        recommendation=c["fix"]).model_dump() for c in bad]
    findings = findings or [Finding(title="Aucun écart détecté", severity="info", evidence="Tous les contrôles internes sont conformes.",
                                    description="Auto-évaluation interne, ne constitue pas une certification.").model_dump()]
    audit = {"audit_id": str(uuid.uuid4()), "created_at": auditlog.utc_now(), "mode": "compliance",
             "target_label": "Déploiement AgAtA-SpiDeR", "status": f"{len(controls) - len(bad)}/{len(controls)} contrôles conformes",
             "findings": findings, "controls": controls}
    return await _finish(audit, False)


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})


app.mount("/static", StaticFiles(directory=STATIC), name="static")
