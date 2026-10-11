"""Laboratoire virtuel déterministe et utilitaires réseau (aucun paquet envoyé)."""
import random

SERVICES = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 80: "http", 443: "https", 3306: "mysql",
            3389: "rdp", 5432: "postgresql", 6379: "redis", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt"}
RISK = {21: ("high", "FTP en clair"), 23: ("high", "Telnet en clair"), 3306: ("high", "MySQL exposé"),
        5432: ("high", "PostgreSQL exposé"), 6379: ("high", "Redis exposé"), 3389: ("medium", "RDP exposé"),
        80: ("low", "HTTP sans TLS")}


def mac_for(ip: str) -> str | None:
    """MAC via la table ARP locale : connue uniquement pour un voisin du même segment réseau (L2)."""
    try:
        with open("/proc/net/arp", encoding="utf-8") as f:
            for line in f.read().splitlines()[1:]:
                p = line.split()
                if len(p) >= 4 and p[0] == ip and p[3] != "00:00:00:00:00:00":
                    return p[3]
    except OSError:
        pass
    return None


def simulate(seed: int, n: int) -> tuple[list[dict], list[dict]]:
    """Même graine, même topologie. Plage TEST-NET-2 (198.51.100.0/24) et MAC localement administrées."""
    rnd = random.Random(seed)
    hosts = []
    for i in range(n):
        ports = [{"port": p, "state": rnd.choice(["open", "open", "closed", "filtered"]), "service": SERVICES[p]}
                 for p in sorted(rnd.sample(list(SERVICES), rnd.randint(2, 4)))]
        hosts.append({"ip": f"198.51.100.{10 + i}", "name": "lab-gw" if i == 0 else f"lab-{i:02d}",
                      "mac": "02:00:5e:" + ":".join(f"{rnd.randrange(256):02x}" for _ in range(3)),
                      "via": None if i == 0 else "198.51.100.10", "simulated": True, "ports": ports})
    findings = []
    for h in hosts:
        for p in h["ports"]:
            if p["state"] == "open" and p["port"] in RISK:
                sev, title = RISK[p["port"]]
                findings.append({"title": f"{title} — {h['ip']}:{p['port']}", "severity": sev,
                                 "description": "Constat de laboratoire simulé : service sensible joignable dans la topologie virtuelle.",
                                 "evidence": f"SIMULÉ (graine {seed}) — aucun paquet envoyé.", "simulated": True,
                                 "recommendation": "Restreindre l'accès par pare-feu et imposer chiffrement et authentification forte."})
    return hosts, findings
