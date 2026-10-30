# 🛡️ Módulo Textual de Gestión y Administración de Ciberseguridad (NIST CSF / MSPI)

Sistema de interfaz táctica en terminal (**TUI - Terminal User Interface**) desarrollado en **Python** con la librería **Textual**. Permite administrar, auditar y ejecutar operaciones de ciberseguridad alineadas con las funciones del marco **NIST CSF** y el modelo **MSPI**.

---

## 📋 Mapeo de Módulos y Marcos de Seguridad

| Script / Módulo | Función NIST CSF | Descripción Operativa |
| --- | --- | --- |
| `deploy_caddy_waf.sh` | **PROTEGER (Protect)** | Despliega servidor Caddy WAF con reglas de filtrado de User-Agents maliciosos, Query Injection y cabeceras HSTS/CSP. |
| `red_inspection_audit.sh` | **IDENTIFICAR / DETECTAR** | Audita interfaces de red, puertos TCP/UDP en escucha, reglas de `iptables` y captura tráfico con `tcpdump`. |
| `setup_fail2ban.sh` | **DETECTAR / RESPONDER** | Configura Fail2ban con reglas en `iptables` para el bloqueo dinámico de IPs atacantes tras detectar errores en Caddy WAF. |
| `backup_system.sh` | **RECUPERAR (Recover)** | Genera respaldos comprimidos de configuraciones (`/etc/caddy`, `/etc/fail2ban`) y valida firmas hash **SHA-256**. |
| `log_storage_management.sh` | **GOBERNAR / RECUPERAR** | Rotación, compresión, firmado de logs de auditoría para SIEM y purga de archivos antiguos (>30 días). |
| `autodiagnostico.sh` | **GOBERNAR (Govern)** | Evalúa la salud operativa del sistema comprobando la conexión a la Base de Datos (PostgreSQL:5432) y la respuesta del WAF. |
| `caddy_alerts.sh` | **DETECTAR (Detect)** | Monitoreo en tiempo real de logs de Caddy con alertas inmediatas y bloqueo automático de IPs maliciosas. |

---

## 🚀 Despliegue en Servidor DigitalOcean (Ubuntu 24.04)

### Paso 1: Copiar el proyecto al servidor

Desde tu **Windows** (PowerShell o Git Bash):

```bash
scp -r "C:\Users\USUARIO\Desktop\ciberseguridad_tui" root@<IP_DEL_DROPLET>:/
```

> **Nota:** `rsync` no funcionó correctamente. Usa `scp` que sí funcionó.

---

### Paso 2: Conectarse al servidor

```bash
ssh root@<IP_DEL_DROPLET>
```

---

### Paso 3: Actualizar el sistema

```bash
apt update && apt upgrade -y
```

---

### Paso 4: Instalar dependencias de Python

```bash
apt install -y python3 python3-pip python3-venv
```

---

### Paso 5: Crear entorno virtual e instalar dependencias

```bash
cd /opt/ciberseguridad_tui
python3 -m venv .venv
source .venv/bin/activate
pip install textual rich
```

---

### Paso 6: Dar permisos de ejecución a los scripts

```bash
chmod +x *.sh
```

---

### Paso 7: Instalar servicios (opcional pero recomendado)

**PostgreSQL** (para métricas):
```bash
apt install -y postgresql
systemctl enable postgresql
systemctl start postgresql
```

**Caddy WAF** (para protección web):
```bash
sudo ./deploy_caddy_waf.sh
```

**Fail2ban** (para bloqueo de IPs):
```bash
sudo ./setup_fail2ban.sh
```

---

### Paso 8: Iniciar la TUI

```bash
sudo .venv/bin/python3 ciberseguridad_tui.py
```

---

## ⌨️ Controles y Teclas de Acceso Rápido

* **Ratón:** Haz clic directamente sobre el botón **"Ejecutar Script"** en cualquiera de las tarjetas laterales.
* **`D`**: Dispara automáticamente el **Autodiagnóstico de Sistema y BD** (`autodiagnostico.sh`).
* **`C`**: Limpia los logs acumulados en la consola en pantalla.
* **`Q`**: Cierra y sale de la aplicación TUI.

---

## 🔔 Sistema de Alertas Inmediatas

Para monitorear los logs de Caddy en tiempo real y recibir alertas inmediatas:

```bash
sudo ./caddy_alerts.sh
```

Las alertas se guardan en `/var/log/caddy_alerts.log` y las IPs maliciosas se bloquean automáticamente con `iptables` tras 5 intentos.

---

## 📊 Métrica Única de Ciberseguridad

Para visualizar todo el panel en **una sola métrica** (puntaje 0-100):

```bash
python cybersecurity_metric.py            # gauge + desglose en terminal
python cybersecurity_metric.py --json     # salida JSON (SIEM/Prometheus/Grafana)
python cybersecurity_metric.py --demo     # simula entorno totalmente protegido
python cybersecurity_metric.py --html metric_dashboard.html
```

La métrica agrega los 21 controles NIST CSF/MSPI en un único score global
con desglose por función (Govern, Identify, Protect, Detect, Respond, Recover).

Para verificar qué falta para llegar a 100/100 en el servidor:
```bash
sudo ./check_readiness.sh
```

## 📁 Estructura del Proyecto

```text
ciberseguridad_tui/
├── ciberseguridad_tui.py       # Aplicación principal Textual (TUI)
├── deploy_caddy_waf.sh         # Script 1: Despliegue de WAF y cabeceras
├── red_inspection_audit.sh     # Script 2: Auditoría de red e inspección
├── setup_fail2ban.sh           # Script 3: Configuración de Fail2ban
├── backup_system.sh            # Script 4: Copias de seguridad y firmas SHA256
├── log_storage_management.sh   # Script 5: Gestión de retención de logs
├── autodiagnostico.sh          # Script 6: Comprobación de salud de BD y WAF
├── caddy_alerts.sh             # Script 7: Alertas inmediatas de Caddy WAF
└── README.md                   # Documentación del proyecto
```
