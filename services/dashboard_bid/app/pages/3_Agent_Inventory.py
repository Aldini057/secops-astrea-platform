"""
SecOps Astrea Platform - Agent Inventory & EDR Fleet Telemetry.
Manages the fleet of endpoints monitored by Wazuh EDR, displaying connection status,
operating systems, network addresses, and active isolation controls.
"""

import sys
from pathlib import Path
from typing import Any, Dict

import pandas as pd
import plotly.express as px
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
    from app.db_connector import get_agents_status, get_recent_incidents
except ImportError:
    from db_connector import get_agents_status, get_recent_incidents

st.set_page_config(
    page_title="Agent Inventory - SecOps Astrea",
    page_icon="🖥️",
    layout="wide",
)

st.title("🖥️ Agent Inventory — Parque de Endpoints Wazuh EDR")
st.markdown(
    "Control centralizado de endpoints monitoreados por **Wazuh Agent**. "
    "Supervisión de conectividad, telemetría de sistemas y estado de **aislamiento de red (EDR)**."
)
st.write("")

# Cargar inventario de agentes
df_agents = get_agents_status()

# ============================================================================
# 1. Filtros y Búsqueda
# ============================================================================
col_s1, col_s2 = st.columns([3, 1])

with col_s1:
    search_agent = st.text_input(
        "🔍 Buscar Agente",
        placeholder="Buscar por Hostname, Dirección IP o Agent ID...",
        help="Filtra hosts por coincidencia de texto.",
    )

with col_s2:
    status_filter = st.selectbox(
        "Filtrar por Estado",
        options=["Todos", "active", "isolated", "disconnected"],
        index=0,
    )

# Filtrado dinámico
if not df_agents.empty:
    if status_filter != "Todos":
        df_agents = df_agents[df_agents["status"].str.lower() == status_filter.lower()]

    if search_agent:
        q = search_agent.strip().lower()
        mask = (
            df_agents["hostname"].astype(str).str.lower().str.contains(q)
            | df_agents["ip_address"].astype(str).str.lower().str.contains(q)
            | df_agents["agent_id"].astype(str).str.lower().str.contains(q)
            | df_agents["os_name"].astype(str).str.lower().str.contains(q)
        )
        df_agents = df_agents[mask]

st.divider()

# ============================================================================
# 2. Métricas de la Flota EDR
# ============================================================================
total_agents = len(df_agents)
active_count = len(df_agents[df_agents["status"].str.lower() == "active"]) if not df_agents.empty else 0
isolated_count = len(df_agents[df_agents["status"].str.lower() == "isolated"]) if not df_agents.empty else 0
disconnected_count = len(df_agents[df_agents["status"].str.lower() == "disconnected"]) if not df_agents.empty else 0

m1, m2, m3, m4 = st.columns(4)

with m1:
    st.metric("Total Endpoints", total_agents)
with m2:
    st.metric("Agentes Activos", active_count, delta="Online", delta_color="normal")
with m3:
    st.metric(
        "Hosts Aislados (EDR)",
        isolated_count,
        delta="En cuarentena" if isolated_count > 0 else "0",
        delta_color="inverse" if isolated_count > 0 else "off",
    )
with m4:
    st.metric(
        "Desconectados",
        disconnected_count,
        delta="Sin keepalive" if disconnected_count > 0 else "0",
        delta_color="inverse" if disconnected_count > 0 else "normal",
    )

st.write("")

# ============================================================================
# 3. Gráficos de Flota: SO y Estado
# ============================================================================
g_col1, g_col2 = st.columns(2)

with g_col1:
    st.subheader("🐧 Distribución por Sistema Operativo")
    if not df_agents.empty and "os_name" in df_agents.columns:
        os_counts = df_agents["os_name"].fillna("Desconocido").value_counts().reset_index()
        os_counts.columns = ["os_name", "count"]

        fig_os = px.bar(
            os_counts,
            x="os_name",
            y="count",
            color="os_name",
            text="count",
            labels={"os_name": "Sistema Operativo", "count": "Endpoints"},
        )
        fig_os.update_layout(
            margin=dict(t=20, b=20, l=20, r=20),
            height=280,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e2e8f0"),
            showlegend=False,
            xaxis=dict(showgrid=False),
            yaxis=dict(showgrid=True, gridcolor="#2d3748"),
        )
        st.plotly_chart(fig_os, use_container_width=True)
    else:
        st.info("ℹ️ Sin datos de sistemas operativos para graficar.")

with g_col2:
    st.subheader("📶 Estado de Conectividad")
    if not df_agents.empty and "status" in df_agents.columns:
        st_counts = df_agents["status"].value_counts().reset_index()
        st_counts.columns = ["status", "count"]

        color_map = {
            "active": "#198754",
            "isolated": "#DC3545",
            "disconnected": "#6C757D",
            "pending": "#FFC107",
        }

        fig_st = px.pie(
            st_counts,
            values="count",
            names="status",
            hole=0.55,
            color="status",
            color_discrete_map=color_map,
        )
        fig_st.update_layout(
            margin=dict(t=20, b=20, l=20, r=20),
            height=280,
            paper_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e2e8f0"),
            legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5),
        )
        st.plotly_chart(fig_st, use_container_width=True)
    else:
        st.info("ℹ️ Sin datos de estados de conectividad.")

st.divider()

# ============================================================================
# 4. Tabla de la Flota de Agentes
# ============================================================================
st.subheader("📋 Inventario de Hosts Registrados")

if df_agents.empty:
    st.info("ℹ️ Sin datos para mostrar. No hay agentes registrados en el inventario.")
else:
    table_df = df_agents.copy()

    if "last_keepalive" in table_df.columns:
        table_df["Último Keepalive"] = table_df["last_keepalive"].dt.strftime("%Y-%m-%d %H:%M:%S")

    st.dataframe(
        table_df[[
            "agent_id",
            "hostname",
            "ip_address",
            "os_name",
            "os_version",
            "status",
            "total_incidents",
            "active_incidents",
            "Último Keepalive",
        ]],
        use_container_width=True,
        hide_index=True,
        column_config={
            "agent_id": st.column_config.TextColumn("Agent ID", width="small"),
            "hostname": st.column_config.TextColumn("Hostname", width="medium"),
            "ip_address": st.column_config.TextColumn("Dirección IP", width="medium"),
            "os_name": st.column_config.TextColumn("SO", width="small"),
            "os_version": st.column_config.TextColumn("Versión SO", width="small"),
            "status": st.column_config.TextColumn("Estado", width="small"),
            "total_incidents": st.column_config.NumberColumn("Total Alertas", width="small"),
            "active_incidents": st.column_config.NumberColumn("Alertas Activas", width="small"),
            "Último Keepalive": st.column_config.TextColumn("Último Keepalive", width="medium"),
        },
    )

    st.write("")
    st.markdown("### 🔎 Inspección Forense de Endpoint")

    inspect_col1, inspect_col2 = st.columns([3, 1])

    with inspect_col1:
        # Selector de agente para inspección
        agent_options = {
            f"[{row['agent_id']}] {row['hostname']} ({row['ip_address']}) — Estado: {row['status']}": row['agent_id']
            for _, row in table_df.iterrows()
        }
        selected_agent_label = st.selectbox(
            "Seleccionar host para inspeccionar telemetría:",
            options=list(agent_options.keys()),
            index=0,
        )
        selected_agent_id = agent_options[selected_agent_label]

    with inspect_col2:
        st.write("")
        st.write("")
        inspect_clicked = st.button("🔍 Inspeccionar Host", use_container_width=True)

    if selected_agent_id:
        agent_row = table_df[table_df["agent_id"] == selected_agent_id].iloc[0]

        with st.container():
            st.markdown(f"#### Detalle del Host: `{agent_row['hostname']}` (Agent `{agent_row['agent_id']}`)")

            # Banner de Estado EDR
            agent_status_val = str(agent_row.get("status", "active")).lower()
            if agent_status_val == "isolated":
                st.error(
                    "🚨 **HOST AISLADO DE LA RED POR ACCIÓN EDR (ACTIVE RESPONSE)**\n\n"
                    "El tráfico de red ha sido restringido automáticamente para contener la propagación lateral del incidente.",
                    icon="🔒",
                )
            elif agent_status_val == "active":
                st.success(
                    "🟢 **Host Operativo y Protegido**: El agente se comunica activamente con el cluster de Wazuh Manager.",
                    icon="✅",
                )
            else:
                st.warning(
                    f"⚠️ **Estado del Host:** `{agent_status_val.upper()}`. Podría existir interrupción de conectividad.",
                    icon="⚠️",
                )

            # Información general del host
            det_c1, det_c2, det_c3 = st.columns(3)
            with det_c1:
                st.markdown(f"- **Dirección IP:** `{agent_row.get('ip_address')}`")
                st.markdown(f"- **Hostname:** `{agent_row.get('hostname')}`")
            with det_c2:
                st.markdown(f"- **Sistema Operativo:** `{agent_row.get('os_name') or 'N/A'}`")
                st.markdown(f"- **Versión del Kernel/SO:** `{agent_row.get('os_version') or 'N/A'}`")
            with det_c3:
                st.markdown(f"- **Último Keepalive:** `{agent_row.get('Último Keepalive')}`")
                st.markdown(f"- **Total Incidentes Detectados:** `{agent_row.get('total_incidents', 0)}`")

            # Incidentes vinculados a este agente
            st.markdown("##### 🚨 Historial de Incidentes en este Endpoint:")
            df_agent_incidents = get_recent_incidents(limit=20)
            if not df_agent_incidents.empty and "agent_id" in df_agent_incidents.columns:
                target_incidents = df_agent_incidents[df_agent_incidents["agent_id"] == selected_agent_id]
                if not target_incidents.empty:
                    st.dataframe(
                        target_incidents[[
                            "detected_at",
                            "alert_name",
                            "severity",
                            "calculated_risk_score",
                            "status",
                            "active_response_executed",
                        ]],
                        use_container_width=True,
                        hide_index=True,
                    )
                else:
                    st.info("ℹ️ No se registran incidentes activos para este agente.")
            else:
                st.info("ℹ️ Sin incidentes registrados.")
