#!/bin/bash
# check_readiness.sh — Verifica cada control y calcula el score resultante (0-100)
# Ejecutar en el servidor Ubuntu: sudo ./check_readiness.sh

SCORE=0
TOTAL=100
PASS=0
FAIL=0

ok()   { echo "  [OK]   $1"; SCORE=$((SCORE+$2)); PASS=$((PASS+1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

echo "===== VERIFICACIÓN DE READINESS — NIST/MSPI ====="
echo

echo "[Govern]"
tcp_port_open() { nc -z -w3 "$1" "$2" >/dev/null 2>&1; }

if tcp_port_open localhost 5432; then ok "PostgreSQL puerto 5432 abierto" 5; else fail "PostgreSQL puerto 5432 cerrado" ; fi
if systemctl is-active --quiet postgresql 2>/dev/null; then ok "Servicio PostgreSQL activo" 5; else fail "Servicio PostgreSQL inactivo"; fi
if systemctl is-active --quiet docker 2>/dev/null; then ok "Servicio Docker activo" 5; else fail "Servicio Docker inactivo"; fi
if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx 'docker-postgres-1'; then ok "Contenedor docker-postgres-1 activo" 5; else fail "Contenedor docker-postgres-1 inactivo"; fi
DISK_PCT=$(df / | awk 'NR==2{gsub("%",""); print $5}')
if [ "${DISK_PCT:-100}" -lt 90 ]; then ok "Disco ${DISK_PCT}% (<90%)" 5; else fail "Disco ${DISK_PCT}% (>=90%)"; fi

echo
echo "[Identify]"
if ip -br addr show >/dev/null 2>&1 && [ -n "$(ip -br addr show 2>/dev/null)" ]; then ok "Interfaces de red enumeradas" 5; else fail "Interfaces de red no disponibles"; fi
if (command -v ss >/dev/null && ss -tulpn 2>/dev/null | grep -q .) || (command -v netstat >/dev/null && netstat -tulpn 2>/dev/null | grep -q .); then ok "Puertos en escucha capturados" 5; else fail "Puertos en escucha no capturados"; fi
if command -v iptables >/dev/null && iptables -L -n 2>/dev/null | grep -q .; then ok "Reglas de firewall presentes" 5; else fail "Sin reglas de firewall"; fi
CRIT_OPEN=0
for p in 80 443 5432 8001; do
  if nc -z -w3 localhost "$p" >/dev/null 2>&1; then CRIT_OPEN=$((CRIT_OPEN+1)); fi
done
if [ "$CRIT_OPEN" -eq 4 ]; then ok "Puertos críticos 80/443/5432/8001 abiertos ($CRIT_OPEN/4)" 5; else fail "Puertos críticos abiertos: $CRIT_OPEN/4"; fi

echo
echo "[Protect]"
if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx 'caddy'; then ok "Contenedor caddy activo" 5; else fail "Contenedor caddy inactivo"; fi
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost 2>/dev/null || echo "000")
case "$HTTP_STATUS" in 200|301|302|308|403) ok "HTTP WAF responde ($HTTP_STATUS)" 5;; *) fail "HTTP WAF no disponible (status=$HTTP_STATUS)";; esac
if nc -z -w3 localhost 443 >/dev/null 2>&1; then ok "Puerto HTTPS 443 en escucha" 5; else fail "Puerto HTTPS 443 cerrado"; fi
HDRS=$(curl -sI http://localhost 2>/dev/null)
if echo "$HDRS" | grep -qi 'strict-transport-security' && echo "$HDRS" | grep -qi 'content-security-policy'; then ok "Cabeceras HSTS + CSP presentes" 5; else fail "Faltan cabeceras HSTS/CSP"; fi
if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx 'docker-api-1'; then ok "Contenedor docker-api-1 activo" 5; else fail "Contenedor docker-api-1 inactivo"; fi

echo
echo "[Detect]"
if command -v tcpdump >/dev/null 2>&1; then ok "tcpdump disponible" 4; else fail "tcpdump no disponible"; fi
if systemctl is-active --quiet fail2ban 2>/dev/null || fail2ban-client status >/dev/null 2>&1; then ok "Fail2ban activo" 3; else fail "Fail2ban inactivo"; fi
if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx 'sentry-resend'; then ok "Contenedor sentry-resend activo" 3; else fail "Contenedor sentry-resend inactivo"; fi

echo
echo "[Respond]"
if fail2ban-client status caddy-waf 2>/dev/null | grep -q 'caddy-waf'; then ok "Jail caddy-waf activo" 5; else fail "Jail caddy-waf inactivo"; fi
if iptables -L -n 2>/dev/null | grep -qiE 'DROP|REJECT'; then ok "Reglas DROP/REJECT presentes" 5; else fail "Sin reglas DROP/REJECT"; fi

echo
echo "[Recover]"
if ls /var/backups/soar_lite/backup_soar_*.tar.gz >/dev/null 2>&1; then
  LATEST=$(ls -t /var/backups/soar_lite/backup_soar_*.tar.gz | head -1)
  AGE_DAYS=$(( ( $(date +%s) - $(stat -c %Y "$LATEST") ) / 86400 ))
  if [ "$AGE_DAYS" -le 7 ]; then ok "Respaldo reciente ($AGE_DAYS días)" 5; else fail "Respaldo antiguo ($AGE_DAYS días)"; fi
else
  fail "Sin respaldos generados"
fi
LATEST=$(ls -t /var/backups/soar_lite/backup_soar_*.tar.gz 2>/dev/null | head -1)
if [ -n "$LATEST" ] && [ -f "$LATEST.sha256" ]; then
  if (cd /var/backups/soar_lite && sha256sum -c "$(basename "$LATEST").sha256" >/dev/null 2>&1); then ok "Integridad SHA256 verificada" 5; else fail "Fallo de integridad SHA256"; fi
else
  fail "Falta archivo .sha256"
fi

echo
echo "===== RESULTADO ====="
echo "Score: $SCORE / $TOTAL"
echo "Checks OK: $PASS | Checks FAIL: $FAIL"
if [ "$SCORE" -eq 100 ]; then
  echo "Estado: EXCELENTE (100/100) ✅"
else
  echo "Estado: CRÍTICO/RIESGO — faltan $((TOTAL-SCORE)) puntos para el 100/100"
fi