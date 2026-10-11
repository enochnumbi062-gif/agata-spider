"""Auto-évaluation de la posture de sécurité du déploiement (contrôles calculés en direct)."""
from . import auditlog, config


def evaluate(https: bool) -> list[dict]:
    chain = auditlog.verify_chain()
    rows = [
        ("Jeton API robuste (32 caractères ou plus)", len(config.API_TOKEN) >= 32, "high", "Générer un jeton aléatoire d'au moins 32 caractères."),
        ("Mode enterprise actif", config.MODE == "enterprise", "medium", "Définir AGATA_MODE=enterprise."),
        ("Transport HTTPS", https, "high", "Servir l'application uniquement en HTTPS."),
        ("Contrôles actifs verrouillés ou périmètre restreint", (not config.ACTIVE_CHECKS) or ("0.0.0.0/0" not in config.ALLOWED_TARGETS and bool(config.ALLOWED_TARGETS)), "high", "Limiter AGATA_ALLOWED_TARGETS aux actifs que vous possédez."),
        ("Liste blanche de ports restreinte (20 ports max)", len(config.ALLOWED_PORTS) <= 20, "medium", "Réduire AGATA_ALLOWED_PORTS."),
        ("Journal d'audit intègre (chaîne SHA-256)", chain["valid"], "critical", "Enquêter : le journal a été altéré."),
        ("Limitation de débit configurée", config.RATE_PER_MIN > 0 and config.HEAVY_PER_MIN > 0, "medium", "Définir AGATA_RATE_PER_MIN et AGATA_HEAVY_PER_MIN."),
        ("Proxy inverse déclaré (IP client fiables)", config.PROXY_HOPS >= 1, "low", "Définir AGATA_PROXY_HOPS=1 derrière Render."),
        ("Notifications Telegram configurées", bool(config.TELEGRAM_BOT_TOKEN and config.TELEGRAM_ADMIN_CHAT_ID), "low", "Renseigner TELEGRAM_BOT_TOKEN et TELEGRAM_ADMIN_CHAT_ID."),
        ("Analyse IA configurée", bool(config.GEMINI_API_KEY), "low", "Renseigner GEMINI_API_KEY."),
    ]
    return [{"control": n, "ok": bool(ok), "severity": s, "fix": fix} for n, ok, s, fix in rows]
