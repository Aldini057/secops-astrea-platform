"""
SecOps Astrea Platform - SOC Overview & Incident Deep Dive.
Provides granular inspection of security incidents, composite risk scoring,
attacker/target telemetry, and Wazuh Active Response JSON payload auditing.
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

# Setup sys.path to resolve internal imports
_current_dir = Path(__file__).resolve().parent
_app_dir = _current_dir.parent
_dashboard_dir = _app_dir.parent
_services_dir = _dashboard_dir.parent
_repo_root = _services_dir.parent

for _p in [str(_repo_root), str(_services_dir), str(_dashboard_dir), str(_app_dir)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from app.db_connector import get_incident_by_id, get_recent_incidents
except ImportError:
    from db_connector import get_incident_by_id, get_recent_incidents

st.set_page_config(
    page_title="SOC Overview - SecOps Astrea",
    page_icon="🎯",
    layout="wide",
)

st.title("🎯 SOC Overview — Análisis Detallado de Incidentes")
st.markdown(
    "Inspección forense y de triage para analistas L2/L3. "
    "Auditoría de vectores de ataque, **Risk Score compuesto** y ejecución de **Respuesta Activa (Wazuh EDR)**."
)
st.write("")

# ============================================================================
# 1. Filtros y Buscador por IP / Regla
# ============================================================================
with st.container():
    search_col1, search_col2, search_col3 = st.columns([2, 1, 1])

    with search_col1:
        search_query = st.text_input(
            "🔍 Buscador rápido",
            placeholder="Buscar por IP (Origen/Destino), ID de Regla o Nombre de Alerta...",
            help="Filtra incidentes por coincidencia en IPs, Reglas SIEM/EDR o títulos de alerta.",
        )

    with search_col2:
        status_filter = st.selectbox(
            "Filtrar por Estado",
            options=["Todos", "NEW", "CONTAINED_AUTOMATICALLY", "RESOLVED", "ENRICHED", "FALSE_POSITIVE"],
            index=0,
        )

    with search_col3:
        severity_filter = st.selectbox(
            "Filtrar por Severidad",
            options=["Todas", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
            index=0,
        )

# Obtener incidentes
df_incidents = get_recent_incidents(
    limit=200,
    status=None if status_filter == "Todos" else status_filter,
    severity=None if severity_filter == "Todas" else severity_filter,
)

# Aplicar búsqueda textual si se proporcionó término
if search_query and not df_incidents.empty:
    q = search_query.strip().lower()
    mask = (
        df_incidents["src_ip"].astype(str).str.lower().str.contains(q)
        | df_incidents["dst_ip"].astype(str).str.lower().str.contains(q)
        | df_incidents["rule_id"].astype(str).str.lower().str.contains(q)
        | df_incidents["alert_name"].astype(str).str.lower().str.contains(q)
        | df_incidents["hostname"].astype(str).str.lower().str.contains(q)
    )
    df_incidents = df_incidents[mask]

st.divider()

# ============================================================================
# 2. Selector de Incidente
# ============================================================================
if df_incidents.empty:
    st.info("ℹ️ Sin datos para mostrar. No se encontraron incidentes que coincidan con los criterios de búsqueda.")
else:
    # Construcción de opciones descriptivas para el dropdown
    incident_options = {}
    for _, row in df_incidents.iterrows():
        inc_id = str(row["incident_id"])
        short_id = inc_id[:8]
        alert = row.get("alert_name", "Alerta Desconocida")
        src = row.get("src_ip", "N/A")
        host = row.get("hostname", "N/A")
        sev = row.get("severity", "MEDIUM")
        label = f"[{sev}] [{short_id}] {alert} — ({src} ➔ {host})"
        incident_options[label] = inc_id

    selected_label = st.selectbox(
        "📌 Selecciona un Incidente para Investigar:",
        options=list(incident_options.keys()),
        index=0,
    )

    selected_id = incident_options[selected_label]
    incident_data = get_incident_by_id(selected_id)

    if not incident_data:
        st.warning("⚠️ No se pudo cargar el detalle completo del incidente seleccionado.")
    else:
        st.write("")
        # Encabezado del Incidente
        header_col1, header_col2, header_col3 = st.columns([3, 1, 1])
        with header_col1:
            st.markdown(f"### {incident_data.get('alert_name', 'Incidente de Seguridad')}")
            st.caption(f"**ID Único (UUID):** `{incident_data.get('incident_id')}` | **Regla:** `{incident_data.get('rule_id', 'N/A')}`")

        with header_col2:
            st.markdown("**Fuente de Detección:**")
            source = incident_data.get("source_detection", "HYBRID")
            st.markdown(f"🏷️ `{source}`")

        with header_col3:
            st.markdown("**Estado:**")
            st.markdown(f"📌 `{incident_data.get('status', 'NEW')}`")

        st.write("")

        # --------------------------------------------------------------------
        # 2.1 Telemetría y Vectores de Red
        # --------------------------------------------------------------------
        t_col1, t_col2, t_col3 = st.columns(3)

        with t_col1:
            st.markdown("#### 🌐 Vector de Red (Atacante)")
            st.markdown(f"- **IP Origen:** `{incident_data.get('src_ip') or 'N/A'}`")
            st.markdown(f"- **País Origen:** `{incident_data.get('src_country') or 'Desconocido'}`")
            rep_score = incident_data.get("src_reputation_score")
            rep_text = f"{rep_score}/100" if rep_score is not None else "N/A"
            st.markdown(f"- **Reputación CTI (AbuseIPDB/OTX):** `{rep_text}`")
            st.markdown(f"- **IP Destino:** `{incident_data.get('dst_ip') or 'N/A'}`")
            st.markdown(f"- **Puerto Destino:** `{incident_data.get('dst_port') or 'N/A'}`")

        with t_col2:
            st.markdown("#### 💻 Endpoint Objetivo (Wazuh)")
            st.markdown(f"- **Agent ID:** `{incident_data.get('agent_id') or 'N/A'}`")
            st.markdown(f"- **Hostname:** `{incident_data.get('hostname') or 'N/A'}`")
            os_info = f"{incident_data.get('os_name') or ''} {incident_data.get('os_version') or ''}".strip()
            st.markdown(f"- **Sistema Operativo:** `{os_info or 'N/A'}`")
            st.markdown(f"- **Estado Agente:** `{incident_data.get('agent_status') or 'active'}`")

        with t_col3:
            st.markdown("#### 🛡️ Contexto de Vulnerabilidad (NVD)")
            st.markdown(f"- **Software Afectado:** `{incident_data.get('affected_software') or 'N/A'}`")
            cve = incident_data.get("associated_cve")
            if cve:
                st.markdown(f"- **CVE Asociado:** [{cve}](https://nvd.nist.gov/vuln/detail/{cve})")
            else:
                st.markdown("- **CVE Asociado:** `Ninguno`")
            cvss = incident_data.get("cvss_score")
            st.markdown(f"- **CVSS v3.1 Score:** `{cvss if cvss is not None else 'N/A'}`")
            st.markdown(f"- **Severidad CVE:** `{incident_data.get('cve_severity') or 'N/A'}`")
            has_exploit = incident_data.get("has_active_exploit")
            exploit_badge = "🔴 SÍ (Activo)" if has_exploit else "🟢 No detectado"
            st.markdown(f"- **Exploit en la Red:** {exploit_badge}")

        st.divider()

        # --------------------------------------------------------------------
        # 2.2 Visualización del Risk Score Compuesto
        # --------------------------------------------------------------------
        st.subheader("⚖️ Evaluación del Risk Score Compuesto")
        st.markdown(
            "Fórmula de correlación SOC: "
            r"$$\text{Risk Score} = (\text{CTI Score} \times 0.4) + (\text{CVSS} \times 0.6 \times 10)$$"
        )

        r_col1, r_col2 = st.columns([1, 1])

        risk_score = float(incident_data.get("calculated_risk_score") or 0.0)

        with r_col1:
            # Medidor Gauge de Plotly
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=risk_score,
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': f"Risk Score ({incident_data.get('severity', 'MEDIUM')})", 'font': {'color': "#ffffff", 'size': 18}},
                gauge={
                    'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#a0aec0"},
                    'bar': {'color': "#00d2ff", 'thickness': 0.25},
                    'bgcolor': "#1a1e24",
                    'borderwidth': 2,
                    'bordercolor': "#2d3748",
                    'steps': [
                        {'range': [0, 40], 'color': '#20C997'},
                        {'range': [40, 70], 'color': '#FFC107'},
                        {'range': [70, 85], 'color': '#FD7E14'},
                        {'range': [85, 100], 'color': '#DC3545'},
                    ],
                    'threshold': {
                        'line': {'color': "white", 'width': 4},
                        'thickness': 0.75,
                        'value': risk_score,
                    },
                },
            ))
            fig_gauge.update_layout(
                height=260,
                margin=dict(t=30, b=10, l=30, r=30),
                paper_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#ffffff"),
            )
            st.plotly_chart(fig_gauge, use_container_width=True)

        with r_col2:
            st.markdown("##### Desglose Ponderado de Componentes:")
            cti_score_val = float(incident_data.get("src_reputation_score") or 0.0)
            cvss_score_val = float(incident_data.get("cvss_score") or 0.0)

            cti_contrib = cti_score_val * 0.4
            cvss_contrib = cvss_score_val * 0.6 * 10.0

            st.markdown(
                f"""
                - **Componente CTI (40%):**
                  - Score Reputacional IP: `{cti_score_val:.1f} / 100`
                  - Contribución: **`+{cti_contrib:.1f} pts`**
                - **Componente NVD / CVSS (60%):**
                  - Score CVSS v3.1: `{cvss_score_val:.1f} / 10.0`
                  - Contribución: **`+{cvss_contrib:.1f} pts`**
                - **Score Compuesto Final:** **`{risk_score:.1f} / 100`**
                """
            )
            if risk_score >= 80:
                st.error("🚨 **Nivel Crítico (P1):** Amenaza inminente. Protocolo de aislamiento EDR y bloqueo perimetral recomendado.")
            elif risk_score >= 60:
                st.warning("⚠️ **Nivel Alto:** Actividad sospechosa de alta probabilidad. Requiere contención inmediata.")
            else:
                st.info("ℹ️ **Nivel Moderado / Bajo:** Evento catalogado para monitoreo y correlación heurística.")

        st.divider()

        # --------------------------------------------------------------------
        # 2.3 Visor de Respuesta Activa (Wazuh EDR)
        # --------------------------------------------------------------------
        st.subheader("⚡ Respuesta Activa (Wazuh EDR & SOAR)")

        resp_action = incident_data.get("active_response_executed") or "NONE"
        resp_status = incident_data.get("active_response_status") or "SKIPPED"
        payload = incident_data.get("response_payload")

        ar_col1, ar_col2, ar_col3 = st.columns(3)
        with ar_col1:
            st.metric("Comando EDR Ejecutado", resp_action)
        with ar_col2:
            st.metric("Estado de Ejecución", resp_status)
        with ar_col3:
            res_time = incident_data.get("resolved_at") or incident_data.get("detected_at")
            st.metric("Timestamp Acción", str(res_time)[:19] if res_time else "N/A")

        st.markdown("##### 📄 Payload de Respuesta Activa (JSON):")
        if payload:
            st.json(payload)
        else:
            st.info("ℹ️ No hay payload de respuesta activa registrado para este incidente (Acción omitida o NONE).")
