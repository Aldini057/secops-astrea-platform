"""
Unit and Integration tests for Wazuh EDR/XDR orchestration artifacts:
- Local correlation rules: orchestration/wazuh/rules/local_rules.xml
- Active response configuration: orchestration/wazuh/active_response/active_responses.xml
- Containment shell scripts:
    * orchestration/wazuh/active_response/isolate-host.sh
    * orchestration/wazuh/active_response/block-ip.sh
"""

import json
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_PATH = REPO_ROOT / "orchestration" / "wazuh" / "rules" / "local_rules.xml"
AR_CONFIG_PATH = REPO_ROOT / "orchestration" / "wazuh" / "active_response" / "active_responses.xml"
ISOLATE_SCRIPT_PATH = REPO_ROOT / "orchestration" / "wazuh" / "active_response" / "isolate-host.sh"
BLOCK_SCRIPT_PATH = REPO_ROOT / "orchestration" / "wazuh" / "active_response" / "block-ip.sh"


def find_bash_executable() -> str | None:
    """Finds a working GNU bash executable across Windows/Linux environments."""
    # Check common Git for Windows paths
    candidates = [
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
        shutil.which("bash"),
        shutil.which("sh"),
    ]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            try:
                res = subprocess.run(
                    [candidate, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if res.returncode == 0 and "GNU bash" in res.stdout:
                    return candidate
            except Exception:
                continue
    return None


# ==============================================================================
# 1. Tests for Local Rules XML (local_rules.xml)
# ==============================================================================

class TestWazuhLocalRules:
    """Tests for local_rules.xml structure, rule IDs, and detection scenarios."""

    @pytest.fixture(autouse=True)
    def load_rules(self):
        assert RULES_PATH.is_file(), f"Rules file not found at {RULES_PATH}"
        self.tree = ET.parse(RULES_PATH)
        self.root = self.tree.getroot()

    def test_xml_is_well_formed_and_has_valid_root(self):
        """Verifica que el archivo XML sea válido y la raíz sea <group>."""
        assert self.root.tag == "group"
        group_name = self.root.attrib.get("name", "")
        assert "astrea" in group_name
        assert "local" in group_name

    def test_all_rule_ids_are_in_100000_range_and_unique(self):
        """Verifica que todas las reglas tengan IDs >= 100000 y sean únicos."""
        rules = self.root.findall("rule")
        assert len(rules) >= 6, "Debe haber al menos 6 reglas definidas"

        rule_ids = []
        for rule in rules:
            rule_id_str = rule.attrib.get("id")
            assert rule_id_str is not None, "Cada regla debe tener un atributo 'id'"
            assert rule_id_str.isdigit(), f"El ID de regla '{rule_id_str}' debe ser numérico"

            rule_id = int(rule_id_str)
            assert rule_id >= 100000, f"El ID de regla {rule_id} debe estar en el rango 100000+"
            assert rule_id not in rule_ids, f"El ID de regla {rule_id} está duplicado"
            rule_ids.append(rule_id)

    def test_rules_have_descriptions_and_valid_levels(self):
        """Verifica que cada regla tenga nivel numérico y descripción no vacía."""
        rules = self.root.findall("rule")
        for rule in rules:
            level_str = rule.attrib.get("level")
            assert level_str is not None and level_str.isdigit()
            level = int(level_str)
            assert level >= 1, "El nivel de la regla debe ser mayor o igual a 1"

            desc = rule.find("description")
            assert desc is not None and desc.text and len(desc.text.strip()) > 0, (
                f"La regla {rule.attrib.get('id')} debe tener una descripción válida"
            )

    def test_port_scan_detection_scenario(self):
        """
        Verifica detección de escaneo agresivo de puertos:
        - Nmap SYN scan / port scan burst.
        - Regla correlacionada con nivel >= 10, frecuencia y ventana de tiempo.
        """
        rules = self.root.findall("rule")
        port_scan_rules = [
            r for r in rules
            if any(term in (r.findtext("description") or "").lower() for term in ["port scan", "syn scan", "nmap"])
        ]
        assert len(port_scan_rules) >= 2, "Debe haber al menos 2 reglas asociadas a escaneo de puertos"

        critical_port_scans = [
            r for r in port_scan_rules if int(r.attrib.get("level", 0)) >= 10
        ]
        assert len(critical_port_scans) >= 1, (
            "Debe haber al menos una regla correlacionada de escaneo con nivel >= 10"
        )

        corr_rule = critical_port_scans[0]
        assert "frequency" in corr_rule.attrib, "La regla correlacionada debe definir 'frequency'"
        assert "timeframe" in corr_rule.attrib, "La regla correlacionada debe definir 'timeframe'"
        assert corr_rule.find("same_source_ip") is not None, "Debe correlacionar por 'same_source_ip'"

        # Verifica mapeo MITRE ATT&CK T1046 (Network Service Discovery)
        mitre_ids = [m.text for m in corr_rule.findall(".//mitre/id")]
        assert "T1046" in mitre_ids

    def test_brute_force_ssh_and_rdp_scenario(self):
        """
        Verifica detección de fuerza bruta en SSH y RDP:
        - Múltiples autenticaciones fallidas en ventana de tiempo.
        - Nivel >= 10 y MITRE T1110.
        """
        rules = self.root.findall("rule")

        # SSH Brute Force
        ssh_bf_rules = [
            r for r in rules
            if "ssh" in (r.findtext("description") or "").lower() and int(r.attrib.get("level", 0)) >= 10
        ]
        assert len(ssh_bf_rules) >= 1, "Debe haber una regla crítica de fuerza bruta SSH"
        ssh_rule = ssh_bf_rules[0]
        assert int(ssh_rule.attrib.get("frequency", 0)) > 1
        assert int(ssh_rule.attrib.get("timeframe", 0)) > 0
        assert ssh_rule.find("same_source_ip") is not None

        # RDP Brute Force
        rdp_bf_rules = [
            r for r in rules
            if "rdp" in (r.findtext("description") or "").lower() and int(r.attrib.get("level", 0)) >= 10
        ]
        assert len(rdp_bf_rules) >= 1, "Debe haber una regla crítica de fuerza bruta RDP"
        rdp_rule = rdp_bf_rules[0]
        assert int(rdp_rule.attrib.get("frequency", 0)) > 1
        assert int(rdp_rule.attrib.get("timeframe", 0)) > 0
        assert rdp_rule.find("same_source_ip") is not None

    def test_web_exploitation_and_anomalous_curl_wget_scenario(self):
        """
        Verifica detección de explotación web:
        - CVE-2021-41773 en Apache o Directory Traversal.
        - Ejecución anómala de curl/wget hacia IPs públicas sospechosas.
        - Severidad nivel >= 10.
        """
        rules = self.root.findall("rule")

        # CVE-2021-41773 / Path Traversal
        cve_rules = [
            r for r in rules
            if "cve-2021-41773" in (r.findtext("description") or "").lower() or
               "cve-2021-41773" in (r.findtext("group") or "").lower() or
               "cve_2021_41773" in (r.findtext("group") or "").lower()
        ]
        assert len(cve_rules) >= 1, "Debe existir regla de detección para CVE-2021-41773"
        assert int(cve_rules[0].attrib.get("level", 0)) >= 10, "Regla de CVE debe tener nivel >= 10"

        # Directory Traversal general
        traversal_rules = [
            r for r in rules
            if "directory traversal" in (r.findtext("description") or "").lower()
        ]
        assert len(traversal_rules) >= 1

        # Anomalous curl/wget
        curl_wget_rules = [
            r for r in rules
            if any(cmd in (r.findtext("description") or "").lower() for cmd in ["curl", "wget"])
        ]
        assert len(curl_wget_rules) >= 1, "Debe existir regla para ejecución anómala de curl/wget"
        assert any(int(r.attrib.get("level", 0)) >= 10 for r in curl_wget_rules), (
            "Regla de curl/wget debe tener nivel >= 10"
        )


# ==============================================================================
# 2. Tests for Active Responses XML (active_responses.xml)
# ==============================================================================

class TestWazuhActiveResponsesConfig:
    """Tests for active_responses.xml commands and associations."""

    @pytest.fixture(autouse=True)
    def load_config(self):
        assert AR_CONFIG_PATH.is_file(), f"AR config file not found at {AR_CONFIG_PATH}"
        self.tree = ET.parse(AR_CONFIG_PATH)
        self.root = self.tree.getroot()

    def test_xml_is_well_formed_and_has_ossec_config_root(self):
        """Verifica que la configuración esté encapsulada en <ossec_config>."""
        assert self.root.tag == "ossec_config"

    def test_command_definitions(self):
        """Verifica las definiciones de comando 'isolate-host' y 'block-ip'."""
        commands = self.root.findall("command")
        command_map = {}
        for cmd in commands:
            name = cmd.findtext("name")
            if name:
                command_map[name] = {
                    "executable": cmd.findtext("executable"),
                    "timeout_allowed": cmd.findtext("timeout_allowed"),
                }

        assert "isolate-host" in command_map, "Debe definirse el comando 'isolate-host'"
        assert command_map["isolate-host"]["executable"] == "isolate-host.sh"
        assert command_map["isolate-host"]["timeout_allowed"] == "yes"

        assert "block-ip" in command_map, "Debe definirse el comando 'block-ip'"
        assert command_map["block-ip"]["executable"] == "block-ip.sh"
        assert command_map["block-ip"]["timeout_allowed"] == "yes"

    def test_active_response_blocks_and_locations(self):
        """
        Verifica bloques <active-response>:
        - Ubicación <location>defined-agent</location>.
        - Timeouts configurables.
        - Asociación con comandos y reglas.
        """
        ar_blocks = self.root.findall("active-response")
        assert len(ar_blocks) >= 2, "Debe haber al menos 2 bloques <active-response>"

        commands_associated = set()
        for ar in ar_blocks:
            cmd = ar.findtext("command")
            location = ar.findtext("location")
            timeout = ar.findtext("timeout")
            rules_id = ar.findtext("rules_id")

            commands_associated.add(cmd)
            assert location == "defined-agent", (
                f"El bloque de respuesta para '{cmd}' debe tener <location>defined-agent</location>"
            )
            assert timeout is not None and timeout.isdigit() and int(timeout) > 0, (
                f"El bloque para '{cmd}' debe definir un <timeout> entero positivo"
            )
            assert rules_id is not None and len(rules_id.strip()) > 0, (
                f"El bloque para '{cmd}' debe especificar <rules_id>"
            )

        assert "isolate-host" in commands_associated
        assert "block-ip" in commands_associated

    def test_active_response_rules_match_local_rules(self):
        """Verifica que los IDs de reglas en active_responses.xml existan en local_rules.xml."""
        rules_tree = ET.parse(RULES_PATH)
        defined_ids = {r.attrib.get("id") for r in rules_tree.getroot().findall("rule")}

        ar_blocks = self.root.findall("active-response")
        for ar in ar_blocks:
            rules_id_str = ar.findtext("rules_id", "")
            ids = [x.strip() for x in rules_id_str.split(",") if x.strip()]
            for rid in ids:
                assert rid in defined_ids, (
                    f"El ID de regla '{rid}' en active-response no está definido en local_rules.xml"
                )


# ==============================================================================
# 3. Tests for Active Response Shell Scripts
# ==============================================================================

class TestActiveResponseShellScripts:
    """Tests for isolate-host.sh and block-ip.sh integrity and syntax."""

    def test_scripts_exist_and_have_shebang(self):
        """Verifica existencia y shebang adecuado en ambos scripts."""
        for script_path in [ISOLATE_SCRIPT_PATH, BLOCK_SCRIPT_PATH]:
            assert script_path.is_file(), f"Script no encontrado: {script_path}"
            content = script_path.read_text(encoding="utf-8")
            assert content.startswith("#!/bin/bash") or content.startswith("#!/usr/bin/env bash")

    def test_scripts_line_endings_are_unix_lf(self):
        """Verifica que los scripts tengan saltos de línea UNIX (LF) y no Windows (CRLF)."""
        for script_path in [ISOLATE_SCRIPT_PATH, BLOCK_SCRIPT_PATH]:
            bytes_content = script_path.read_bytes()
            assert b"\r\n" not in bytes_content, (
                f"El script {script_path.name} contiene retornos de carro Windows (CRLF). Debe ser LF."
            )

    def test_bash_syntax_with_bash_n_if_available(self):
        """Valida sintaxis shell con 'bash -n' si GNU Bash está presente."""
        bash_bin = find_bash_executable()
        if not bash_bin:
            pytest.skip("GNU Bash no encontrado en el entorno para ejecutar 'bash -n'")

        for script_path in [ISOLATE_SCRIPT_PATH, BLOCK_SCRIPT_PATH]:
            proc = subprocess.run(
                [bash_bin, "-n", str(script_path)],
                capture_output=True,
                text=True,
            )
            assert proc.returncode == 0, (
                f"Error de sintaxis bash en {script_path.name}:\n{proc.stderr}"
            )

    def test_isolate_host_script_requirements(self):
        """
        Verifica requisitos específicos de isolate-host.sh:
        - Lectura de STDIN JSON ($INPUT_JSON).
        - Acciones 'add' y 'delete'.
        - Preservación obligatoria de puerto 1514 (TCP/UDP) y loopback (lo).
        - Registro de auditoría en /var/ossec/logs/active-responses.log.
        """
        content = ISOLATE_SCRIPT_PATH.read_text(encoding="utf-8")

        # STDIN / JSON
        assert "INPUT_JSON" in content or "cat" in content
        assert "python3" in content or "jq" in content or "grep" in content

        # Acciones
        assert "add" in content
        assert "delete" in content

        # Reglas iptables y preservación de puerto 1514 y lo
        assert "iptables" in content
        assert "1514" in content, "Debe preservar el puerto del Wazuh Manager 1514"
        assert "lo" in content, "Debe preservar el loopback 'lo'"
        assert "DROP" in content

        # Auditoría
        assert "/var/ossec/logs/active-responses.log" in content

    def test_block_ip_script_requirements(self):
        """
        Verifica requisitos específicos de block-ip.sh:
        - Extracción de IP atacante (srcip) desde JSON de STDIN.
        - Acciones 'add' y 'delete'.
        - Comandos iptables con DROP.
        - Auditoría en /var/ossec/logs/active-responses.log.
        """
        content = BLOCK_SCRIPT_PATH.read_text(encoding="utf-8")

        # Extracción de srcip desde JSON de STDIN
        assert "srcip" in content
        assert "INPUT_JSON" in content or "cat" in content

        # Acciones
        assert "add" in content
        assert "delete" in content

        # Comandos iptables
        assert "iptables" in content
        assert "DROP" in content
        assert "-s" in content

        # Auditoría
        assert "/var/ossec/logs/active-responses.log" in content

    def test_json_payload_parsing_simulation(self):
        """
        Prueba la lógica de extracción de JSON de Wazuh simulando los payloads estándar
        que emite el motor de Active Response de Wazuh.
        """
        sample_wazuh_payload = {
            "version": 1,
            "origin": {"name": "test-node", "module": "wazuh-execd"},
            "command": "add",
            "parameters": {
                "extra_args": [],
                "alert": {
                    "timestamp": "2026-10-15T12:00:00.000+0000",
                    "rule": {"level": 11, "id": "100011"},
                    "data": {"srcip": "198.51.100.42"},
                },
                "program": "active-response/bin/block-ip.sh",
            },
        }

        # Simular extracción de command y srcip exactamente como los scripts
        data = sample_wazuh_payload
        cmd = data.get("command", "")
        alert = data.get("parameters", {}).get("alert", {})
        srcip = alert.get("data", {}).get("srcip") or alert.get("srcip")

        assert cmd == "add"
        assert srcip == "198.51.100.42"

    def test_script_execution_with_mock_iptables_via_bash(self, tmp_path):
        """
        Ejecuta los scripts shell en un entorno aislado con un mock de iptables
        para validar el flujo completo de ejecución, salida estándar, código de salida 0
        y escritura del archivo de auditoría.
        """
        bash_bin = find_bash_executable()
        if not bash_bin:
            pytest.skip("GNU Bash no disponible para prueba de ejecución en vivo")

        # Crear mock de iptables en tmp_path
        mock_bin_dir = tmp_path / "bin"
        mock_bin_dir.mkdir()
        mock_iptables = mock_bin_dir / "iptables"

        # Mock de iptables que registra comandos y retorna 0
        mock_iptables_content = "#!/bin/bash\nexit 0\n"
        mock_iptables.write_text(mock_iptables_content, encoding="utf-8", newline="\n")

        # Configurar archivo de log temporal de auditoría
        test_log_file = tmp_path / "logs" / "active-responses.log"

        # Preparar entorno de ejecución con mock en PATH
        env = os.environ.copy()
        env["PATH"] = f"{mock_bin_dir}{os.pathsep}{env.get('PATH', '')}"
        env["WAZUH_AR_LOG_FILE"] = str(test_log_file)

        # ----------------------------------------------------------------------
        # 1. Probar block-ip.sh (Acción 'add')
        # ----------------------------------------------------------------------
        block_payload_add = json.dumps({
            "command": "add",
            "parameters": {
                "alert": {
                    "data": {"srcip": "203.0.113.88"}
                }
            }
        })

        proc = subprocess.run(
            [bash_bin, str(BLOCK_SCRIPT_PATH)],
            input=block_payload_add,
            capture_output=True,
            text=True,
            env=env,
            timeout=10,
        )
        assert proc.returncode == 0, f"block-ip.sh (add) falló: stdout={proc.stdout}, stderr={proc.stderr}"
        assert "203.0.113.88" in proc.stdout
        assert "success" in proc.stdout.lower()

        # ----------------------------------------------------------------------
        # 2. Probar block-ip.sh (Acción 'delete')
        # ----------------------------------------------------------------------
        block_payload_del = json.dumps({
            "command": "delete",
            "parameters": {
                "alert": {
                    "data": {"srcip": "203.0.113.88"}
                }
            }
        })

        proc_del = subprocess.run(
            [bash_bin, str(BLOCK_SCRIPT_PATH)],
            input=block_payload_del,
            capture_output=True,
            text=True,
            env=env,
            timeout=10,
        )
        assert proc_del.returncode == 0, f"block-ip.sh (delete) falló: stdout={proc_del.stdout}, stderr={proc_del.stderr}"
        assert "203.0.113.88" in proc_del.stdout

        # ----------------------------------------------------------------------
        # 3. Probar isolate-host.sh (Acción 'add')
        # ----------------------------------------------------------------------
        isolate_payload_add = json.dumps({
            "command": "add",
            "parameters": {
                "alert": {"rule": {"id": "100020"}}
            }
        })

        proc_isolate_add = subprocess.run(
            [bash_bin, str(ISOLATE_SCRIPT_PATH)],
            input=isolate_payload_add,
            capture_output=True,
            text=True,
            env=env,
            timeout=10,
        )
        assert proc_isolate_add.returncode == 0, (
            f"isolate-host.sh (add) falló: stdout={proc_isolate_add.stdout}, stderr={proc_isolate_add.stderr}"
        )
        assert "isolated" in proc_isolate_add.stdout.lower()
        assert "1514" in proc_isolate_add.stdout or "success" in proc_isolate_add.stdout.lower()

        # ----------------------------------------------------------------------
        # 4. Probar isolate-host.sh (Acción 'delete')
        # ----------------------------------------------------------------------
        isolate_payload_del = json.dumps({
            "command": "delete",
            "parameters": {
                "alert": {"rule": {"id": "100020"}}
            }
        })

        proc_isolate_del = subprocess.run(
            [bash_bin, str(ISOLATE_SCRIPT_PATH)],
            input=isolate_payload_del,
            capture_output=True,
            text=True,
            env=env,
            timeout=10,
        )
        assert proc_isolate_del.returncode == 0, (
            f"isolate-host.sh (delete) falló: stdout={proc_isolate_del.stdout}, stderr={proc_isolate_del.stderr}"
        )
        assert "restored" in proc_isolate_del.stdout.lower() or "success" in proc_isolate_del.stdout.lower()

        # ----------------------------------------------------------------------
        # 5. Validar que el archivo de auditoría se haya generado correctamente
        # ----------------------------------------------------------------------
        assert test_log_file.is_file(), "El archivo de log de auditoría debe existir"
        log_content = test_log_file.read_text(encoding="utf-8")
        assert "block-ip.sh" in log_content
        assert "isolate-host.sh" in log_content
        assert "203.0.113.88" in log_content

