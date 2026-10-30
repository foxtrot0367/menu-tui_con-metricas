#!/bin/bash
set -e

DB_HOST="localhost"
DB_PORT="5432"

echo "=== INICIANDO AUTODIAGNÓSTICO SOAR-LITE ==="

# ==================================================
# 1. Verificar netcat
# ==================================================

if ! command -v nc >/dev/null 2>&1; then
    echo "[FAIL] netcat (nc) no está instalado."
    exit 1
fi

# ==================================================
# 2. Verificar PostgreSQL
# ==================================================

if nc -z -w5 "$DB_HOST" "$DB_PORT" >/dev/null 2>&1; then
    echo "[OK] Conexión a Base de Datos de Métricas: EXITOSA"
else
    echo "[FAIL] Falla de conexión a PostgreSQL"
fi

# ==================================================
# 3. Verificar HTTP
# ==================================================

HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost || true)

case "$HTTP_STATUS" in
    200|301|302|308|403)
        echo "[OK] Servicio Web / WAF respondiendo (HTTP $HTTP_STATUS)"
        ;;
    *)
        echo "[WARN] Código HTTP inesperado: $HTTP_STATUS"
        ;;
esac

# ==================================================
# 4. Verificar HTTPS
# ==================================================

if ss -tln | grep -q ':443 '; then
    echo "[OK] Puerto HTTPS 443 en escucha"
else
    echo "[WARN] Puerto HTTPS 443 no detectado"
fi

# ==================================================
# 5. Verificar Caddy
# ==================================================

if docker ps --format '{{.Names}}' | grep -q '^caddy$'; then
    echo "[OK] Contenedor Caddy activo"
else
    echo "[WARN] Contenedor Caddy no encontrado"
fi

# ==================================================
# 6. Verificar PostgreSQL Service
# ==================================================

if systemctl is-active --quiet postgresql; then
    echo "[OK] Servicio PostgreSQL activo"
else
    echo "[WARN] Servicio PostgreSQL inactivo"
fi

# ==================================================
# 7. Verificar Docker
# ==================================================

if systemctl is-active --quiet docker; then
    echo "[OK] Servicio Docker activo"
else
    echo "[WARN] Servicio Docker inactivo"
fi

# ==================================================
# 8. Contenedores activos
# ==================================================

echo
echo "=== CONTENEDORES ACTIVOS ==="

docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" || true

# ==================================================
# 9. Puertos críticos
# ==================================================

echo
echo "=== PUERTOS EN ESCUCHA ==="

ss -tulpn | grep -E ':80|:443|:5432|:8001' || \
echo "[WARN] No se detectaron puertos críticos"

# ==================================================
# 10. Uso de disco
# ==================================================

echo
echo "=== ESPACIO EN DISCO ==="

df -h /

# ==================================================
# 11. Uso de memoria
# ==================================================

echo
echo "=== MEMORIA RAM ==="

free -h

# ==================================================
# 12. Carga del sistema
# ==================================================

echo
echo "=== CARGA DEL SISTEMA ==="

uptime

# ==================================================
# 13. Estado de contenedores críticos
# ==================================================

echo
echo "=== SERVICIOS SOAR-LITE ==="

for SERVICE in caddy docker-postgres-1 docker-api-1 sentry-resend vulnerablespace
do
    if docker ps --format '{{.Names}}' | grep -q "^${SERVICE}$"; then
        echo "[OK] $SERVICE activo"
    else
        echo "[WARN] $SERVICE no encontrado"
    fi
done

echo
echo "=== DIAGNÓSTICO FINALIZADO ==="