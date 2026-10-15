"""
SecOps Astrea Platform - SOC Command Center (Single Pane of Glass).
Streamlit analytical dashboard for cybersecurity operations and incident triage.
Integrates telemetry from Splunk, Wazuh EDR, and n8n SOAR.
"""

import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Setup sys.path to enable imports across directory configurations
_current_dir = Path(__file__).resolve().parent
_dashboard_dir = _current_dir.parent
_services_dir = _dashboard_dir.parent
_repo_root = _services_dir.parent

for _p in [str(_repo_root), str(_services_dir), str(_dashboard_dir), str(_current_dir)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from app.db_connector import (
        get_connection_status,
        get_hourly_incident_trends,
        get_kpis,
        get_recent_incidents,
    )
except ImportError:
    from db_connector import (
        get_connection_status,
        get_hourly_incident_trends,
        get_kpis,
        get_recent_incidents,
    )

# ============================================================================
# 1. Configuración de Página Streamlit
# ============================================================================
st.set_page_config(
    page_title="SecOps Astrea Platform - SOC Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Estilos CSS personalizados para estética SOC oscura y profesional
st.markdown("""
<style>
    /* Estilos generales y métricas */
    .metric-card {
        background-color: #1a1e24;
        border: 1px solid #2d3748;
        border-radius: 8px;
        padding: 18px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
    }
    .metric-value {
        font-size: 2rem;
        font-weight: 700;
        color: #f7fafc;
        margin-top: 4px;
    }
    .metric-label {
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #a0aec0;
    }
    .badge-critical {
        background-color: #dc3545;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
    }
    .badge-contained {
        background-color: #198754;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
    }
    .badge-new {
        background-color: #0d6efd;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
    }
    .badge-resolved {
        background-color: #6c757d;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)


# ============================================================================
# 2. Barra Lateral (Sidebar): Conexión, Auto-Refresco y Filtros Globales
# ============================================================================
with st.sidebar:
    st.markdown("## 🛡️ **SecOps Astrea**")
    st.caption("SOC Command Center & EDR Integration")
    st.divider()

    # Estado de la Conexión a la Base de Datos
    st.markdown("### 🔌 Estado de Conexión")
    db_status = get_connection_status()
    if db_status.get("connected"):
        st.success(
            f"**Online**: `{db_status['host']}:{db_status['port']}`\n\n"
            f"Base de datos: `{db_status['database']}`",
            icon="🟢",
        )
    else:
        st.error(
            f"**Offline**: No se pudo conectar a PostgreSQL.\n\n"
            f"Host: `{db_status['host']}:{db_status['port']}`\n\n"
            f"Detalle: {db_status.get('error', 'Error de red')}",
            icon="🔴",
        )

    st.divider()

    # Control de Refresco
    st.markdown("### 🔄 Auto-Refresco")
    refresh_rate = st.selectbox(
        "Frecuencia de actualización",
        options=["Manual", "10 segundos", "30 segundos", "60 segundos"],
        index=0,
    )

    if st.button("🔄 Refrescar Datos Ahora", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

    st.caption(f"Última lectura: {datetime.now().strftime('%H:%M:%S')}")
    st.divider()

    # Filtros Globales
    st.markdown("### ⚙️ Filtros Globales")
    filter_status = st.selectbox(
        "Estado del Incidente",
        options=["Todos", "NEW", "CONTAINED_AUTOMATICALLY", "RESOLVED", "ENRICHED", "FALSE_POSITIVE"],
        index=0,
    )

    filter_severity = st.selectbox(
        "Severidad",
        options=["Todas", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
        index=0,
    )

    filter_source = st.selectbox(
        "Fuente de Detección",
        options=["Todas", "SPLUNK", "WAZUH_MANAGER", "HYBRID"],
        index=0,
    )

    limit_incidents = st.slider(
        "Límite de Incidentes Recientes",
        min_value=10,
        max_value=500,
        value=100,
        step=10,
    )

    st.divider()
    st.markdown(
        """
        <div style="font-size: 0.8rem; color: #888;">
        <b>SecOps Astrea v1.0.0</b><br/>
        Integración SIEM + EDR + SOAR
        </div>
        """,
        unsafe_allow_html=True,
    )


# ============================================================================
# 3. Vista Principal: Home / Dashboard
# ============================================================================

# Encabezado principal
st.title("🛡️ SecOps Astrea Platform — SOC Command Center")
st.markdown(
    "Consola unificada de monitoreo en tiempo real (**Single Pane of Glass**). "
    "Supervisión de alertas de Splunk, detección de intrusiones en Wazuh y respuesta EDR activa."
)
st.write("")

# ----------------------------------------------------------------------------
# 3.1 Tarjetas de Métricas Principales (KPIs)
# ----------------------------------------------------------------------------
kpis = get_kpis()

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        label="🚨 Incidentes Totales",
        value=kpis.get("total_incidents", 0),
        help="Conteo total de incidentes y alertas registrados en la plataforma.",
    )

with col2:
    crit_count = kpis.get("critical_active", 0)
    st.metric(
        label="🔥 P1 Críticos Activos",
        value=crit_count,
        delta=f"{crit_count} requieren triage" if crit_count > 0 else "Sin alertas P1 activas",
        delta_color="inverse" if crit_count > 0 else "normal",
        help="Incidentes activos con Risk Score >= 75 o CVE Crítico no resueltos.",
    )

with col3:
    isolated_count = kpis.get("isolated_agents", 0)
    st.metric(
        label="🔒 Agentes Aislados (EDR)",
        value=isolated_count,
        delta="Aislamiento de red activo" if isolated_count > 0 else "Endpoints en red",
        delta_color="off",
        help="Endpoints desconectados de la red corporativa mediante Active Response de Wazuh.",
    )

with col4:
    rate = kpis.get("containment_rate_pct", 0.0)
    mttc = kpis.get("avg_containment_time", "N/A")
    st.metric(
        label="⚡ Tasa Contención Automática",
        value=f"{rate:.1f}%",
        delta=f"MTTC Promedio: {mttc}",
        delta_color="normal",
        help="Porcentaje de incidentes mitigados automáticamente vía SOAR / Active Response.",
    )

st.write("")
st.divider()

# ----------------------------------------------------------------------------
# 3.2 Gráficos Plotly: Distribución por Severidad y Tendencia Temporal (24h)
# ----------------------------------------------------------------------------
chart_col1, chart_col2 = st.columns(2)

# Obtener incidentes para análisis y gráficos
df_incidents = get_recent_incidents(
    limit=limit_incidents,
    status=None if filter_status == "Todos" else filter_status,
    severity=None if filter_severity == "Todas" else filter_severity,
    source=None if filter_source == "Todas" else filter_source,
)

with chart_col1:
    st.subheader("📊 Distribución de Incidentes por Severidad")
    if not df_incidents.empty and "severity" in df_incidents.columns:
        sev_counts = df_incidents["severity"].value_counts().reset_index()
        sev_counts.columns = ["severity", "count"]

        # Mapa de colores SOC estandarizados
        color_map = {
            "CRITICAL": "#DC3545",
            "HIGH": "#FD7E14",
            "MEDIUM": "#FFC107",
            "LOW": "#20C997",
            "UNKNOWN": "#6C757D",
        }

        fig_donut = px.pie(
            sev_counts,
            values="count",
            names="severity",
            hole=0.55,
            color="severity",
            color_discrete_map=color_map,
        )
        fig_donut.update_traces(
            textposition="inside",
            textinfo="percent+label",
            marker=dict(line=dict(color="#1a1e24", width=2)),
        )
        fig_donut.update_layout(
            margin=dict(t=20, b=20, l=20, r=20),
            showlegend=True,
            legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5),
            height=320,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e2e8f0"),
        )
        st.plotly_chart(fig_donut, use_container_width=True)
    else:
        st.info("ℹ️ Sin datos para mostrar en la distribución de severidad.")

with chart_col2:
    st.subheader("📈 Tendencia Temporal de Alertas (Últimas 24h)")
    df_trends = get_hourly_incident_trends(hours=24)

    if not df_trends.empty and "incident_count" in df_trends.columns:
        fig_trend = px.area(
            df_trends,
            x="time_bucket",
            y="incident_count",
            labels={"time_bucket": "Hora", "incident_count": "Alertas"},
            color_discrete_sequence=["#0d6efd"],
        )
        fig_trend.update_traces(
            mode="lines+markers",
            line=dict(width=2, color="#0d6efd"),
            marker=dict(size=6, color="#00d2ff"),
            fillcolor="rgba(13, 110, 253, 0.25)",
        )
        fig_trend.update_layout(
            margin=dict(t=20, b=20, l=20, r=20),
            height=320,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e2e8f0"),
            xaxis=dict(
                showgrid=True,
                gridcolor="#2d3748",
                tickangle=-45,
            ),
            yaxis=dict(
                showgrid=True,
                gridcolor="#2d3748",
                rangemode="tozero",
            ),
        )
        st.plotly_chart(fig_trend, use_container_width=True)
    elif not df_incidents.empty and "detected_at" in df_incidents.columns:
        # Fallback a agregación temporal local si df_trends está vacío
        df_time = df_incidents.copy()
        df_time["hour"] = df_time["detected_at"].dt.strftime("%Y-%m-%d %H:00")
        hour_counts = df_time.groupby("hour").size().reset_index(name="incident_count")
        hour_counts = hour_counts.sort_values("hour")

        fig_trend = px.line(
            hour_counts,
            x="hour",
            y="incident_count",
            markers=True,
            labels={"hour": "Hora", "incident_count": "Alertas"},
            color_discrete_sequence=["#00d2ff"],
        )
        fig_trend.update_layout(
            margin=dict(t=20, b=20, l=20, r=20),
            height=320,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e2e8f0"),
        )
        st.plotly_chart(fig_trend, use_container_width=True)
    else:
        st.info("ℹ️ Sin datos de tendencias temporales para mostrar.")

st.divider()

# ----------------------------------------------------------------------------
# 3.3 Tabla Interactiva de Incidentes Recientes con Badges de Estado
# ----------------------------------------------------------------------------
st.subheader("📋 Incidentes Recientes y Respuesta Activa")
st.caption(
    "Listado cronológico de detecciones correlacionadas. "
    "Badges: 🔵 NEW | 🟢 CONTAINED_AUTOMATICALLY | ⚪ RESOLVED | 🟣 ENRICHED | ⚠️ FALSE_POSITIVE"
)

if not df_incidents.empty:
    # Preparación de DataFrame para presentación
    display_df = df_incidents.copy()

    # Formateo de fecha
    if "detected_at" in display_df.columns:
        display_df["Fecha Detección"] = display_df["detected_at"].dt.strftime("%Y-%m-%d %H:%M:%S")

    # Mapeo y badges en columnas clave
    rename_mapping = {
        "incident_id": "ID Incidente",
        "alert_name": "Alerta / Amenaza",
        "source_detection": "Origen",
        "severity": "Severidad",
        "calculated_risk_score": "Risk Score",
        "status": "Estado",
        "src_ip": "IP Origen",
        "hostname": "Host Objetivo",
        "active_response_executed": "Acción EDR",
        "active_response_status": "Estado EDR",
    }

    cols_to_show = [c for c in [
        "Fecha Detección",
        "ID Incidente",
        "Alerta / Amenaza",
        "Origen",
        "Severidad",
        "Risk Score",
        "Estado",
        "IP Origen",
        "Host Objetivo",
        "Acción EDR",
        "Estado EDR",
    ] if c in display_df.columns or rename_mapping.get(c) in display_df.columns]

    # Renombrar columnas existentes
    for orig, new_col in rename_mapping.items():
        if orig in display_df.columns:
            display_df[new_col] = display_df[orig]

    # Presentación interactiva usando column_config
    st.dataframe(
        display_df[cols_to_show],
        use_container_width=True,
        hide_index=True,
        column_config={
            "ID Incidente": st.column_config.TextColumn("ID Incidente", width="small"),
            "Fecha Detección": st.column_config.TextColumn("Fecha Detección", width="medium"),
            "Alerta / Amenaza": st.column_config.TextColumn("Alerta / Amenaza", width="large"),
            "Severidad": st.column_config.TextColumn("Severidad", width="small"),
            "Risk Score": st.column_config.ProgressColumn(
                "Risk Score",
                format="%.1f",
                min_value=0.0,
                max_value=100.0,
                width="small",
            ),
            "Estado": st.column_config.TextColumn("Estado", width="medium"),
            "Acción EDR": st.column_config.TextColumn("Acción EDR", width="medium"),
            "Estado EDR": st.column_config.TextColumn("Estado EDR", width="small"),
        },
    )
else:
    st.info("ℹ️ Sin datos para mostrar. No hay incidentes que coincidan con los filtros seleccionados.")
