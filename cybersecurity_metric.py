#!/usr/bin/env python3
"""
Métrica única de Ciberseguridad (NIST CSF / MSPI)

Consolida todos los módulos del Panel TUI en un ÚNICO puntaje 0-100 que
representa el estado global de ciberseguridad de la organización.

Uso:
    python cybersecurity_metric.py            # salida visual (gauge + desglose)
    python cybersecurity_metric.py --json    # salida JSON (para Prometheus/Grafana/SIEM)
    python cybersecurity_metric.py --demo     # simula un entorno totalmente protegido (score 100)
"""

import argparse
import json
import platform
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass
import shutil
import socket
import subprocess
import urllib.request
import urllib.error
from datetime import datetime, timedelta
from pathlib import Path

IS_WINDOWS = platform.system() == "Windows"


# ---------- helpers ----------

def run_cmd(cmd, timeout=8):
    """Ejecuta un comando y devuelve (rc, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout or "", r.stderr or ""
    except FileNotFoundError:
        return 127, "", "command not found"
    except subprocess.TimeoutExpired:
        return 126, "", "timeout"
    except Exception as e:
        return 1, "", str(e)


def has(cmd_name):
    return shutil.which(cmd_name) is not None


def tcp_port_open(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def http_get(url, timeout=5):
    """Devuelve (status_code, headers_dict) o (None, {}) si falla."""
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers) if e.headers else {}
    except Exception:
        return None, {}


# ---------- checks ----------

class Check:
    def __init__(self, cid, name, category, weight, fn):
        self.cid = cid
        self.name = name
        self.category = category
        self.weight = weight
        self.fn = fn
        self.passed = False
        self.detail = ""

    def run(self, demo=False):
        if demo:
            self.passed = True
            self.detail = "simulado (modo demo)"
            return
        try:
            ok, detail = self.fn()
        except Exception as e:
            ok, detail = False, f"error: {e}"
        self.passed = bool(ok)
        self.detail = detail


def c_db():
    if tcp_port_open("localhost", 5432):
        return True, "PostgreSQL:5432 accesible"
    return False, "PostgreSQL:5432 no responde"


def c_waf_http():
    status, _ = http_get("http://localhost/")
    if status in (200, 301, 302, 308, 403):
        return True, f"HTTP WAF responde ({status})"
    return False, f"HTTP WAF no disponible (status={status})"


def c_https_port():
    if tcp_port_open("localhost", 443):
        return True, "Puerto HTTPS 443 en escucha"
    return False, "Puerto HTTPS 443 no detectado"


def c_net_ifaces():
    if IS_WINDOWS:
        rc, out, _ = run_cmd(["ipconfig"])
    else:
        rc, out, _ = run_cmd(["ip", "-br", "addr", "show"])
    if rc == 0 and out.strip():
        return True, "Interfaces de red enumeradas"
    return False, "No se pudieron enumerar interfaces"


def c_listening_ports():
    if IS_WINDOWS:
        rc, out, _ = run_cmd(["netstat", "-an"])
    elif has("ss"):
        rc, out, _ = run_cmd(["ss", "-tulpn"])
    elif has("netstat"):
        rc, out, _ = run_cmd(["netstat", "-tulpn"])
    else:
        return False, "ss/netstat no disponibles"
    if rc == 0 and out.strip():
        return True, "Puertos en escucha capturados"
    return False, "No se capturaron puertos"


def c_firewall():
    if IS_WINDOWS:
        rc, out, _ = run_cmd(["netsh", "advfirewall", "show", "allprofiles"])
        if rc == 0:
            return True, "Firewall de Windows consultado"
        return False, "Firewall no consultable"
    if has("iptables"):
        rc, out, _ = run_cmd(["iptables", "-L", "-n"])
        if rc == 0:
            return True, "Reglas iptables presentes"
        return False, "iptables sin reglas/acceso"
    return False, "iptables no disponible"


def c_caddy_installed():
    if has("caddy"):
        return True, "Binario caddy encontrado"
    # buscar servicio
    if not IS_WINDOWS:
        rc, out, _ = run_cmd(["systemctl", "is-active", "caddy"])
        if rc == 0:
            return True, "Servicio caddy activo"
    return False, "Caddy no instalado/activo"


def c_hsts_csp():
    status, headers = http_get("http://localhost/")
    if status is None:
        return False, "Sin respuesta del WAF"
    low = {k.lower(): v for k, v in headers.items()}
    ok_hsts = "strict-transport-security" in low
    ok_csp = "content-security-policy" in low
    if ok_hsts and ok_csp:
        return True, "Cabeceras HSTS y CSP presentes"
    missing = []
    if not ok_hsts:
        missing.append("HSTS")
    if not ok_csp:
        missing.append("CSP")
    return False, "Faltan cabeceras: " + ", ".join(missing)


def c_caddy_config():
    cfg = Path("/etc/caddy/Caddyfile")
    if cfg.exists():
        try:
            txt = cfg.read_text(errors="ignore")
            if "header" in txt.lower() or "respond" in txt.lower():
                return True, "Caddyfile con reglas de filtrado"
            return False, "Caddyfile sin reglas de filtrado"
        except Exception as e:
            return False, f"No se pudo leer Caddyfile: {e}"
    return False, "Caddyfile no encontrado"


def c_fail2ban_running():
    if IS_WINDOWS:
        return False, "Fail2ban no aplica en Windows"
    if has("fail2ban-client"):
        rc, out, _ = run_cmd(["fail2ban-client", "status"])
        if rc == 0:
            return True, "Fail2ban activo"
    # fallback systemctl
    rc, out, _ = run_cmd(["systemctl", "is-active", "fail2ban"])
    if rc == 0:
        return True, "Servicio fail2ban activo"
    return False, "Fail2ban no activo"


def c_tcpdump():
    if has("tcpdump"):
        return True, "tcpdump disponible"
    return False, "tcpdump no disponible"


def c_fail2ban_jail():
    if IS_WINDOWS:
        return False, "Fail2ban no aplica en Windows"
    if has("fail2ban-client"):
        rc, out, _ = run_cmd(["fail2ban-client", "status", "caddy-waf"])
        if rc == 0 and "caddy-waf" in out:
            return True, "Jail caddy-waf activo"
    return False, "Jail caddy-waf inactivo"


def c_iptables_drop():
    if IS_WINDOWS:
        return False, "iptables no aplica en Windows"
    if has("iptables"):
        rc, out, _ = run_cmd(["iptables", "-L", "-n"])
        if rc == 0 and ("DROP" in out or "REJECT" in out):
            return True, "Reglas DROP/REJECT presentes"
        return False, "Sin reglas DROP/REJECT"
    return False, "iptables no disponible"


def c_backup_exists():
    bdir = Path("/var/backups/soar_lite")
    if not bdir.exists():
        return False, "Directorio de backups inexistente"
    backups = sorted(bdir.glob("backup_soar_*.tar.gz"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not backups:
        return False, "Sin respaldos generados"
    age = datetime.now() - datetime.fromtimestamp(backups[0].stat().st_mtime)
    if age <= timedelta(days=7):
        return True, f"Respaldo reciente ({backups[0].name})"
    return False, f"Último respaldo antiguo ({age.days} días)"


def c_backup_integrity():
    bdir = Path("/var/backups/soar_lite")
    if not bdir.exists():
        return False, "Directorio de backups inexistente"
    backups = sorted(bdir.glob("backup_soar_*.tar.gz"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not backups:
        return False, "Sin respaldos para verificar"
    latest = backups[0]
    sha_file = Path(str(latest) + ".sha256")
    if not sha_file.exists():
        return False, "Falta archivo .sha256"
    # verify using sha256sum if available
    if has("sha256sum"):
        rc, out, _ = run_cmd(["sha256sum", "-c", str(sha_file)], timeout=30)
        if rc == 0:
            return True, "Integridad SHA256 verificada"
        return False, "Fallo de integridad SHA256"
    return False, "sha256sum no disponible"


def c_pg_service():
    if IS_WINDOWS:
        return False, "systemctl no disponible en Windows"
    rc, _, _ = run_cmd(["systemctl", "is-active", "postgresql"])
    if rc == 0:
        return True, "Servicio PostgreSQL activo"
    return False, "Servicio PostgreSQL inactivo"


def c_docker_service():
    if has("docker"):
        if IS_WINDOWS:
            return True, "Docker disponible"
        rc, _, _ = run_cmd(["systemctl", "is-active", "docker"])
        if rc == 0:
            return True, "Servicio Docker activo"
        return True, "Docker disponible"
    return False, "Docker no disponible"


def c_container(name):
    if not has("docker"):
        return False, "docker no disponible"
    rc, out, _ = run_cmd(["docker", "ps", "--format", "{{.Names}}"])
    if rc == 0 and name in [x.strip() for x in out.splitlines()]:
        return True, f"Contenedor {name} activo"
    return False, f"Contenedor {name} no encontrado"


def c_disk():
    try:
        usage = shutil.disk_usage("/")
        pct = usage.used / usage.total * 100
        if pct < 90:
            return True, f"Disco {pct:.1f}% usado"
        return False, f"Disco {pct:.1f}% usado (>90%)"
    except Exception as e:
        return False, f"No se pudo leer disco: {e}"


def c_critical_ports():
    ports = [80, 443, 5432, 8001]
    open_ports = [p for p in ports if tcp_port_open("localhost", p)]
    if len(open_ports) == len(ports):
        return True, "Puertos críticos 80/443/5432/8001 abiertos"
    missing = [p for p in ports if p not in open_ports]
    return False, "Puertos cerrados: " + ", ".join(str(p) for p in missing)


CHECKS = [
    # (id, name, category, weight, fn)
    ("GOV-DB", "Conexión Base de Datos (PostgreSQL)", "Govern", 5, c_db),
    ("GOV-PG", "Servicio PostgreSQL activo", "Govern", 5, c_pg_service),
    ("GOV-DOCKER", "Servicio Docker activo", "Govern", 5, c_docker_service),
    ("GOV-PGCTR", "Contenedor postgres activo", "Govern", 5, lambda: c_container("docker-postgres-1")),
    ("GOV-DISK", "Espacio en disco <90%", "Govern", 5, c_disk),
    ("ID-IFACE", "Interfaces de red", "Identify", 5, c_net_ifaces),
    ("ID-PORTS", "Puertos en escucha", "Identify", 5, c_listening_ports),
    ("ID-FW", "Reglas de firewall", "Identify", 5, c_firewall),
    ("ID-CRITPORTS", "Puertos críticos 80/443/5432/8001", "Identify", 5, c_critical_ports),
    ("PR-CADDYCTR", "Contenedor Caddy activo", "Protect", 5, lambda: c_container("caddy")),
    ("PR-HTTP", "Respuesta HTTP del WAF", "Protect", 5, c_waf_http),
    ("PR-HTTPS", "Puerto HTTPS 443 en escucha", "Protect", 5, c_https_port),
    ("PR-HDR", "Cabeceras HSTS + CSP", "Protect", 5, c_hsts_csp),
    ("PR-APICTR", "Contenedor API activo", "Protect", 5, lambda: c_container("docker-api-1")),
    ("DE-TCPD", "tcpdump disponible", "Detect", 4, c_tcpdump),
    ("DE-F2B", "Fail2ban activo", "Detect", 3, c_fail2ban_running),
    ("DE-SENTRY", "Contenedor sentry-resend activo", "Detect", 3, lambda: c_container("sentry-resend")),
    ("RS-JAIL", "Jail caddy-waf activo", "Respond", 5, c_fail2ban_jail),
    ("RS-IPT", "Reglas DROP/REJECT", "Respond", 5, c_iptables_drop),
    ("RC-BACKUP", "Respaldo reciente", "Recover", 5, c_backup_exists),
    ("RC-SHA", "Integridad SHA256", "Recover", 5, c_backup_integrity),
]


def compute(demo=False):
    checks = [Check(cid, name, cat, w, fn) for (cid, name, cat, w, fn) in CHECKS]
    for ch in checks:
        ch.run(demo=demo)
    total_weight = sum(c.weight for c in checks)
    earned = sum(c.weight for c in checks if c.passed)
    score = round((earned / total_weight) * 100) if total_weight else 0

    # category breakdown
    cats = {}
    for c in checks:
        if c.category not in cats:
            cats[c.category] = {"earned": 0, "total": 0, "passed": 0, "count": 0}
        cats[c.category]["total"] += c.weight
        cats[c.category]["count"] += 1
        if c.passed:
            cats[c.category]["earned"] += c.weight
            cats[c.category]["passed"] += 1
    for cat, v in cats.items():
        v["score"] = round((v["earned"] / v["total"]) * 100) if v["total"] else 0

    status = (
        "EXCELENTE" if score >= 80 else
        "ACEPTABLE" if score >= 60 else
        "RIESGO" if score >= 40 else
        "CRITICO"
    )

    return {
        "score": score,
        "status": status,
        "earned": earned,
        "total": total_weight,
        "timestamp": datetime.now().isoformat(),
        "platform": platform.system(),
        "categories": cats,
        "checks": [
            {
                "id": c.cid,
                "name": c.name,
                "category": c.category,
                "weight": c.weight,
                "passed": c.passed,
                "detail": c.detail,
            }
            for c in checks
        ],
    }


# ---------- visualization ----------

COLORS = {
    "EXCELENTE": "\033[92m",  # green
    "ACEPTABLE": "\033[93m",  # yellow
    "RIESGO": "\033[91m",     # red-ish (orange not standard)
    "CRITICO": "\033[91m",    # red
}
RESET = "\033[0m"
BOLD = "\033[1m"


def bar(pct, width=30):
    filled = round(width * pct / 100)
    return "█" * filled + "░" * (width - filled)


def render_visual(result):
    score = result["score"]
    status = result["status"]
    color = COLORS.get(status, "")
    print()
    print(f"{BOLD}╔══════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}║  MÉTRICA ÚNICA DE CIBERSEGURIDAD (NIST/MSPI) ║{RESET}")
    print(f"{BOLD}╠══════════════════════════════════════════════╣{RESET}")
    print(f"{BOLD}║{RESET}  Score global: {color}{BOLD}{score:>3}/100{RESET}   Estado: {color}{BOLD}{status}{RESET}  {'':>6}{BOLD}║{RESET}")
    print(f"{BOLD}║{RESET}  {bar(score)}  {score:>3}%  {BOLD}║{RESET}")
    print(f"{BOLD}╠══════════════════════════════════════════════╣{RESET}")
    print(f"{BOLD}║  Desglose por función NIST CSF               ║{RESET}")
    print(f"{BOLD}╠══════════════════════════════════════════════╣{RESET}")
    for cat, v in result["categories"].items():
        c = COLORS.get("EXCELENTE" if v["score"] >= 80 else "ACEPTABLE" if v["score"] >= 60 else "RIESGO" if v["score"] >= 40 else "CRITICO", "")
        print(f"{BOLD}║{RESET}  {cat:<10} {bar(v['score'], 20)} {v['score']:>3}%  ({v['passed']}/{v['count']}) {c}{RESET}")
    print(f"{BOLD}╠══════════════════════════════════════════════╣{RESET}")
    print(f"{BOLD}║  Checks individuales                         ║{RESET}")
    print(f"{BOLD}╠══════════════════════════════════════════════╣{RESET}")
    for ch in result["checks"]:
        mark = "\033[92m✓\033[0m" if ch["passed"] else "\033[91m✗\033[0m"
        print(f"{BOLD}║{RESET}  {mark} {ch['id']:<10} {ch['name'][:30]:<30} +{ch['weight']:>2} {BOLD}║{RESET}")
    print(f"{BOLD}╚══════════════════════════════════════════════╝{RESET}")
    print(f"  Plataforma: {result['platform']}  |  {result['timestamp']}")
    print()


def render_html(result):
    score = result["score"]
    status = result["status"]
    color = {"EXCELENTE": "#22c55e", "ACEPTABLE": "#eab308", "RIESGO": "#f97316", "CRITICO": "#ef4444"}.get(status, "#6b7280")
    # circular gauge via SVG
    circumference = 2 * 3.14159 * 90
    offset = circumference * (1 - score / 100)
    cats_html = "".join(
        f"<tr><td>{cat}</td><td>{v['score']}%</td><td>{v['passed']}/{v['count']}</td></tr>"
        for cat, v in result["categories"].items()
    )
    checks_html = "".join(
        f"<li class='{'ok' if c['passed'] else 'fail'}'>{'✓' if c['passed'] else '✗'} {c['id']} — {c['name']} (+{c['weight']})</li>"
        for c in result["checks"]
    )
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Métrica Única de Ciberseguridad</title>
<style>
  body {{ font-family: system-ui, sans-serif; background:#0d1117; color:#e6edf3; margin:0; padding:40px; }}
  .card {{ max-width:640px; margin:0 auto; background:#161b22; border:1px solid #30363d; border-radius:16px; padding:32px; text-align:center; }}
  h1 {{ font-size:20px; margin:0 0 24px; color:#58a6ff; }}
  .gauge {{ position:relative; width:220px; height:220px; margin:0 auto 16px; }}
  svg {{ transform:rotate(-90deg); }}
  .score {{ position:absolute; inset:0; display:flex; flex-direction:column; align-items:center; justify-content:center; }}
  .score .num {{ font-size:56px; font-weight:700; color:{color}; }}
  .score .lbl {{ font-size:14px; color:#8b949e; }}
  .status {{ font-size:22px; font-weight:700; color:{color}; margin:8px 0 24px; }}
  table {{ width:100%; border-collapse:collapse; margin:16px 0; }}
  th,td {{ padding:8px; border-bottom:1px solid #30363d; text-align:left; }}
  th {{ color:#8b949e; font-size:12px; text-transform:uppercase; }}
  ul {{ list-style:none; padding:0; text-align:left; }}
  li {{ padding:4px 0; font-size:13px; }}
  .ok {{ color:#22c55e; }}
  .fail {{ color:#ef4444; }}
  .foot {{ color:#8b949e; font-size:12px; margin-top:16px; }}
</style>
</head>
<body>
  <div class="card">
    <h1>🛡️ Métrica Única de Ciberseguridad (NIST CSF / MSPI)</h1>
    <div class="gauge">
      <svg width="220" height="220">
        <circle cx="110" cy="110" r="90" stroke="#30363d" stroke-width="14" fill="none"/>
        <circle cx="110" cy="110" r="90" stroke="{color}" stroke-width="14" fill="none"
          stroke-dasharray="{circumference}" stroke-dashoffset="{offset}" stroke-linecap="round"/>
      </svg>
      <div class="score">
        <div class="num">{score}</div>
        <div class="lbl">/100</div>
      </div>
    </div>
    <div class="status">{status}</div>
    <table>
      <thead><tr><th>Función NIST</th><th>Score</th><th>Checks</th></tr></thead>
      <tbody>{cats_html}</tbody>
    </table>
    <ul>{checks_html}</ul>
    <div class="foot">Plataforma: {result['platform']} · {result['timestamp']}</div>
  </div>
</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser(description="Métrica única de ciberseguridad NIST/MSPI")
    parser.add_argument("--json", action="store_true", help="Salida en JSON")
    parser.add_argument("--demo", action="store_true", help="Simula entorno totalmente protegido")
    parser.add_argument("--html", metavar="PATH", help="Genera un dashboard HTML de una sola métrica en PATH")
    args = parser.parse_args()

    result = compute(demo=args.demo)

    if args.html:
        html = render_html(result)
        Path(args.html).write_text(html, encoding="utf-8")
        print(f"Dashboard HTML generado: {args.html}")
    elif args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        render_visual(result)


if __name__ == "__main__":
    main()