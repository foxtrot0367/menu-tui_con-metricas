#!/usr/bin/env python3
"""
Módulo Textual (TUI) para la Gestión y Administración de Ciberseguridad (NIST / MSPI)
Uso: python ciberseguridad_tui.py
"""

import asyncio
import os
import platform
import sys
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, ScrollableContainer
from textual.widgets import Header, Footer, Button, Static, RichLog, TabbedContent, TabPane

try:
    from cybersecurity_metric import compute as compute_metric
except Exception:
    compute_metric = None

# Mapeo de scripts con sus archivos y descripciones NIST/MSPI
SCRIPTS_CONFIG = {
    "waf": {
        "name": "1. Despliegue Caddy WAF",
        "script": "deploy_caddy_waf.sh",
        "nist": "PROTEGER (Protect)",
        "desc": "Instala Caddy, aplica reglas de filtrado WAF, limita métodos HTTP y fuerza HSTS/CSP."
    },
    "audit": {
        "name": "2. Auditoría de Red",
        "script": "red_inspection_audit.sh",
        "nist": "IDENTIFICAR / DETECTAR",
        "desc": "Mapea interfaces IP, puertos TCP/UDP en escucha, reglas iptables y muestrea tráfico."
    },
    "fail2ban": {
        "name": "3. Setup Fail2ban",
        "script": "setup_fail2ban.sh",
        "nist": "DETECTAR / RESPONDER",
        "desc": "Aplica bloqueo dinámico de IPs tras detectar errores recurrentes en logs de Caddy."
    },
    "backup": {
        "name": "4. Respaldo de Sistema",
        "script": "backup_system.sh",
        "nist": "RECUPERAR (Recover)",
        "desc": "Comprime /etc/caddy, /etc/fail2ban, /var/log/caddy y genera firma SHA256."
    },
    "logs": {
        "name": "5. Gestión de Logs",
        "script": "log_storage_management.sh",
        "nist": "GOBERNAR / RECUPERAR",
        "desc": "Rotación, compresión, firmado SHA256 de evidencias y purga automática (>30 días)."
    },
    "diag": {
        "name": "6. Autodiagnóstico",
        "script": "autodiagnostico.sh",
        "nist": "GOBERNAR (Govern)",
        "desc": "Comprueba disponibilidad de la Base de Datos (puerto 5432) y respuesta HTTP del WAF."
    },
    "readiness": {
        "name": "7. Verificación Readiness 100/100",
        "script": "check_readiness.sh",
        "nist": "GOBERNAR (Govern)",
        "desc": "Verifica los 21 controles y calcula el score. Muestra qué falta para llegar a 100/100."
    }
}


class ScriptCard(Static):
    """Componente para mostrar cada tarjeta de script con su botón de ejecución."""

    def __init__(self, script_key: str, config: dict, **kwargs):
        super().__init__(**kwargs)
        self.script_key = script_key
        self.config = config

    def compose(self) -> ComposeResult:
        yield Static(f"[bold yellow]{self.config['name']}[/bold yellow]", classes="card-title")
        yield Static(f"[bold cyan]NIST:[/bold cyan] {self.config['nist']}", classes="card-nist")
        yield Static(self.config['desc'], classes="card-desc")
        yield Button("Ejecutar Script", id=f"btn_{self.script_key}", variant="primary")


class CybersecurityTUI(App):
    """Aplicación Textual TUI para Administración de Ciberseguridad NIST/MSPI."""

    CSS = """
    Screen {
        background: $surface-darken-3;
    }

    #sidebar {
        width: 38%;
        height: 100%;
        border-right: heavy $accent;
        padding: 1;
        background: $surface-darken-2;
    }

    #main-panel {
        width: 62%;
        height: 100%;
        padding: 1;
    }

    ScriptCard {
        background: $surface;
        border: solid $accent-lighten-2;
        margin-bottom: 1;
        padding: 1;
        height: auto;
    }

    .card-title {
        text-style: bold;
    }

    .card-nist {
        margin-bottom: 1;
    }

    .card-desc {
        color: $text-muted;
        margin-bottom: 1;
    }

    RichLog {
        background: #0d1117;
        color: #00ff66;
        border: solid $accent;
        height: 100%;
    }

    #status-bar {
        height: 3;
        content-align: center middle;
        background: $primary-darken-2;
        color: $text;
        text-style: bold;
        border: solid $primary;
        margin-bottom: 1;
    }
    """

    TITLE = "Panel TUI de Ciberseguridad NIST/MSPI"
    SUB_TITLE = "Gestión Operativa de Scripts y Controles Tácticos"

    BINDINGS = [
        ("q", "quit", "Salir"),
        ("c", "clear_log", "Limpiar Consola"),
        ("d", "run_all_diag", "Ejecutar Diagnóstico")
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Static("[bold green]📜 MÓDULOS DE CONTROL OPERATIVO[/bold green]\n", id="sidebar-header")
                with ScrollableContainer():
                    for key, cfg in SCRIPTS_CONFIG.items():
                        yield ScriptCard(key, cfg)
            
            with Vertical(id="main-panel"):
                yield Static("Estado: Listo para recibir instrucciones.", id="status-bar")
                with TabbedContent():
                    with TabPane("Consola de Salida / Logs"):
                        yield RichLog(id="console_log", highlight=True, markup=True)
                    with TabPane("Matriz de Marco NIST CSF"):
                        yield Static(self._build_nist_matrix())
                    with TabPane("Métrica Única"):
                        yield Static("Calculando métrica...", id="metric-view")
                        yield Button("Actualizar Métrica", id="btn_metric", variant="success")
                    with TabPane("Readiness 100/100"):
                        yield RichLog(id="readiness_log", highlight=True, markup=True)
                        yield Button("Ejecutar Verificación Readiness", id="btn_readiness", variant="primary")
        yield Footer()

    def _build_nist_matrix(self) -> str:
        return """
[bold yellow]MATRIZ DE COBERTURA NIST CSF / MSPI[/bold yellow]

[bold cyan]1. GOBERNAR (Govern):[/bold cyan]
  • Autodiagnóstico de estado operacional (PostgreSQL & HTTP Status).
  • Gestión de retención de políticas y logs de auditoría.

[bold cyan]2. IDENTIFICAR (Identify):[/bold cyan]
  • Auditoría de interfaz de red, puertos en escucha (`ss`/`netstat`) y firewall (`iptables`).

[bold cyan]3. PROTEGER (Protect):[/bold cyan]
  • Servidor Caddy WAF con mitigación de User-Agents maliciosos, Query Injection y cabeceras HSTS/CSP.

[bold cyan]4. DETECTAR (Detect):[/bold cyan]
  • Captura de tráfico con `tcpdump`.
  • Filtrado de respuestas 400/403/405 en logs de acceso de Caddy.

[bold cyan]5. RESPONDER (Respond):[/bold cyan]
  • Integración de Fail2ban con reglas `iptables-multiport` para baneo automático de IPs atacantes.

[bold cyan]6. RECUPERAR (Recover):[/bold cyan]
  • Creación de respaldos comprimidos de configuración con generación y validación de firma SHA256.
        """

    def on_mount(self) -> None:
        try:
            self.refresh_metric()
        except Exception:
            pass
        try:
            if compute_metric is not None:
                r = compute_metric()
                self.query_one("#status-bar", Static).update(
                    f"[bold]Score: {r['score']}/100 ({r['status']})[/bold] — Listo para recibir instrucciones."
                )
        except Exception:
            pass
        # Auto-refresh del score cada 15 segundos
        try:
            self.set_interval(15, self._auto_refresh_score)
        except Exception:
            pass

    def _auto_refresh_score(self) -> None:
        if compute_metric is None:
            return
        try:
            r = compute_metric()
            # Solo actualizar si no hay una ejecución en curso (barra no contiene "Ejecutando")
            status = self.query_one("#status-bar", Static)
            current = str(status.renderable) if hasattr(status, "renderable") else ""
            if "Ejecutando" in current or "⏳" in current:
                return
            status.update(f"[bold]Score: {r['score']}/100 ({r['status']})[/bold]")
            # Refrescar también la pestaña de métrica
            try:
                self.refresh_metric()
            except Exception:
                pass
        except Exception:
            pass

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "btn_metric":
            self.refresh_metric()
            return
        if button_id == "btn_readiness":
            await self.run_readiness_task()
            return
        if button_id.startswith("btn_"):
            script_key = button_id.replace("btn_", "")
            if script_key in SCRIPTS_CONFIG:
                await self.execute_script_task(script_key)

    async def run_readiness_task(self) -> None:
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "check_readiness.sh")
        log = self.query_one("#readiness_log", RichLog)
        status = self.query_one("#status-bar", Static)
        log.clear()
        status.update("[bold yellow]⏳ Ejecutando: Verificación Readiness 100/100...[/bold yellow]")
        is_windows = platform.system() == "Windows"
        if is_windows:
            cmd = ["cmd.exe", "/c", f"echo [WINDOWS ENV] Simulando ejecución de check_readiness.sh & type \"{script_path}\""]
        else:
            cmd = ["bash", script_path]
        try:
            process = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                log.write(line.decode('utf-8', errors='replace').rstrip())
            stderr_data = await process.stderr.read()
            if stderr_data:
                log.write(f"[bold red][STDERR][/bold red]\n{stderr_data.decode('utf-8', errors='replace')}")
            await process.wait()
            if process.returncode == 0:
                try:
                    if compute_metric is not None:
                        r = compute_metric()
                        status.update(f"[bold green]✔ Readiness verificado — Score: {r['score']}/100 ({r['status']})[/bold green]")
                    else:
                        status.update("[bold green]✔ Readiness verificado[/bold green]")
                except Exception:
                    status.update("[bold green]✔ Readiness verificado[/bold green]")
            else:
                status.update(f"[bold red]❌ Error ({process.returncode})[/bold red]")
        except Exception as e:
            log.write(f"[bold red][EXCEPCIÓN] {str(e)}[/bold red]")
            status.update("[bold red]❌ Excepción[/bold red]")

    def refresh_metric(self) -> None:
        view = self.query_one("#metric-view", Static)
        if compute_metric is None:
            view.update("[red]No se pudo importar cybersecurity_metric.py[/red]")
            return
        try:
            result = compute_metric()
            lines = [
                f"[bold]Score global: {result['score']}/100 — {result['status']}[/bold]",
                "",
            ]
            for cat, v in result["categories"].items():
                bar = "█" * (v["score"] // 5) + "░" * (20 - v["score"] // 5)
                lines.append(f"{cat:<10} {bar} {v['score']}% ({v['passed']}/{v['count']})")
            lines.append("")
            for ch in result["checks"]:
                mark = "[green]✓[/green]" if ch["passed"] else "[red]✗[/red]"
                lines.append(f"{mark} {ch['id']:<10} {ch['name']} (+{ch['weight']})")
            view.update("\n".join(lines))
            try:
                self.query_one("#status-bar", Static).update(
                    f"[bold]Score: {result['score']}/100 ({result['status']})[/bold]"
                )
            except Exception:
                pass
        except Exception as e:
            view.update(f"[red]Error calculando métrica: {e}[/red]")

    async def execute_script_task(self, script_key: str):
        config = SCRIPTS_CONFIG[script_key]
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), config["script"])
        log = self.query_one("#console_log", RichLog)
        status = self.query_one("#status-bar", Static)

        status.update(f"[bold yellow]⏳ Ejecutando: {config['name']}...[/bold yellow]")
        log.write(f"\n[bold magenta]====================================================[/bold magenta]")
        log.write(f"[bold cyan][+] INICIANDO PROCESO:[/bold cyan] {config['name']}")
        log.write(f"[bold cyan][+] MARCO NIST/MSPI:[/bold cyan] {config['nist']}")
        log.write(f"[bold cyan][+] SCRIPT:[/bold cyan] {config['script']}")
        log.write(f"[bold magenta]====================================================[/bold magenta]\n")

        is_windows = platform.system() == "Windows"

        if is_windows:
            cmd = ["cmd.exe", "/c", f"echo [WINDOWS ENV] Simulando ejecución de {config['script']} & type \"{script_path}\""]
        else:
            cmd = ["bash", script_path]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                log.write(line.decode('utf-8', errors='replace').rstrip())

            stderr_data = await process.stderr.read()
            if stderr_data:
                log.write(f"[bold red][STDERR][/bold red]\n{stderr_data.decode('utf-8', errors='replace')}")

            await process.wait()

            if process.returncode == 0:
                log.write(f"\n[bold green][✓] {config['name']} procesado correctamente.[/bold green]")
                score_txt = ""
                if compute_metric is not None:
                    try:
                        r = compute_metric()
                        score_txt = f" — Score: {r['score']}/100 ({r['status']})"
                    except Exception:
                        pass
                status.update(f"[bold green]✔ Finalizado: {config['name']}{score_txt}[/bold green]")
            else:
                log.write(f"\n[bold red][✗] Código de retorno: {process.returncode}[/bold red]")
                status.update(f"[bold red]❌ Error en ejecución ({process.returncode})[/bold red]")

        except Exception as e:
            log.write(f"[bold red][EXCEPCIÓN] Error en subproceso: {str(e)}[/bold red]")
            status.update("[bold red]❌ Excepción ocurrida[/bold red]")

    def action_clear_log(self) -> None:
        """Acción para limpiar la pantalla de logs (Tecla 'c')."""
        log = self.query_one("#console_log", RichLog)
        log.clear()
        score_txt = ""
        if compute_metric is not None:
            try:
                r = compute_metric()
                score_txt = f" | Score: {r['score']}/100"
            except Exception:
                pass
        self.query_one("#status-bar", Static).update(f"Consola de logs limpiada.{score_txt}")

    async def action_run_all_diag(self) -> None:
        """Acción rápida para ejecutar el autodiagnóstico (Tecla 'd')."""
        await self.execute_script_task("diag")


if __name__ == "__main__":
    app = CybersecurityTUI()
    app.run()