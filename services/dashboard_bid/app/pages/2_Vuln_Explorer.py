"""
SecOps Astrea Platform - Vuln Explorer & NVD Intelligence.
Explores cached NVD vulnerabilities, CVSS v3.1 scoring, active exploit presence,
and real-time correlation with security incidents detected across endpoints.
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
    from app.db_connector import get_cve_distribution, get_nvd_vulnerabilities
except ImportError:
    from db_connector import get_cve_distribution, get_nvd_vulnerabilities

st.set_page_config(
    page_title="Vuln Explorer - SecOps Astrea",
    page_icon="🔍",
    layout="wide",
)

st.title("🔍 Vuln Explorer — Inteligencia NVD y Correlación")
st.markdown(
    "Repositorio de vulnerabilidades NVD correlacionadas con el parque de hosts y telemetría SOC. "
    "Priorización basada en **CVSS v3.1** y **presencia de exploits activos (CISA KEV / PoC)**."
)
st.write("")

# ============================================================================
# 1. Filtros y Controles
# ============================================================================
col_f1, col_f2, col_f3, col_f4 = st.columns([2, 1, 1, 1])

with col_f1:
    search_cve = st.text_input(
        "🔎 Buscar Vulnerabilidad",
        placeholder="Ej: CVE-2023, Log4j, OpenSSL, CWE-89...",
        help="Búsqueda por identificador CVE, descripción o CWE.",
    )

with col_f2:
    filter_sev = st.selectbox(
        "Filtrar por Severidad",
        options=["Todas", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
        index=0,
    )

with col_f3:
    only_exploits = st.checkbox(
        "⚡ Solo con Exploit Activo",
        value=False,
        help="Muestra únicamente CVEs con exploits comprobados en la red.",
    )

with col_f4:
    limit_vulns = st.selectbox(
        "Registros a Cargar",
        options=[25, 50, 100, 200],
        index=2,
    )

st.divider()

# Cargar vulnerabilidades desde la base de datos
df_vulns = get_nvd_vulnerabilities(
    limit=limit_vulns,
    severity=None if filter_sev == "Todas" else filter_sev,
    only_exploits=only_exploits,
)

# Filtrado por búsqueda de texto
if search_cve and not df_vulns.empty:
    q = search_cve.strip().lower()
    mask = (
        df_vulns["cve_id"].astype(str).str.lower().str.contains(q)
        | df_vulns["description"].astype(str).str.lower().str.contains(q)
        | df_vulns["cwe_id"].astype(str).str.lower().str.contains(q)
    )
    df_vulns = df_vulns[mask]

# ============================================================================
# 2. Métricas y KPIs de Vulnerabilidad
# ============================================================================
m1, m2, m3, m4 = st.columns(4)

total_vulns = len(df_vulns)
crit_vulns = len(df_vulns[df_vulns["severity"] == "CRITICAL"]) if not df_vulns.empty else 0
exploit_vulns = len(df_vulns[df_vulns["has_active_exploit"] == True]) if not df_vulns.empty else 0
avg_score = df_vulns["cvss_score"].mean() if not df_vulns.empty and "cvss_score" in df_vulns.columns else 0.0

with m1:
    st.metric("Total CVEs Filtrados", total_vulns)
with m2:
    st.metric("CVEs Críticos (CVSS >= 9.0)", crit_vulns, delta="Alta prioridad" if crit_vulns > 0 else "0", delta_color="inverse")
with m3:
    st.metric("Con Exploit Activo", exploit_vulns, delta="Peligro KEV" if exploit_vulns > 0 else "0", delta_color="inverse")
with m4:
    st.metric("CVSS Promedio", f"{avg_score:.1f}" if pd.notna(avg_score) else "0.0")

st.write("")

# ============================================================================
# 3. Gráficos de Inteligencia de Vulnerabilidades
# ============================================================================
chart_c1, chart_c2 = st.columns(2)

df_dist = get_cve_distribution()

with chart_c1:
    st.subheader("📊 Distribución por Severidad CVSS")
    if not df_dist.empty and "severity" in df_dist.columns:
        color_map = {
            "CRITICAL": "#DC3545",
            "HIGH": "#FD7E14",
            "MEDIUM": "#FFC107",
            "LOW": "#20C997",
            "UNKNOWN": "#6C757D",
        }
        fig_bar = px.bar(
            df_dist,
            x="severity",
            y="cve_count",
            color="severity",
            color_discrete_map=color_map,
            labels={"severity": "Severidad", "cve_count": "Cantidad de CVEs"},
            text="cve_count",
        )
        fig_bar.update_layout(
            margin=dict(t=20, b=20, l=20, r=20),
            height=280,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e2e8f0"),
            showlegend=False,
            xaxis=dict(showgrid=False),
            yaxis=dict(showgrid=True, gridcolor="#2d3748"),
        )
        st.plotly_chart(fig_bar, use_container_width=True)
    else:
        st.info("ℹ️ Sin datos de distribución de severidad.")

with chart_c2:
    st.subheader("⚡ Presencia de Exploits Activos")
    if not df_vulns.empty and "has_active_exploit" in df_vulns.columns:
        exploit_counts = df_vulns["has_active_exploit"].value_counts().reset_index()
        exploit_counts.columns = ["has_exploit", "count"]
        exploit_counts["Estado"] = exploit_counts["has_exploit"].apply(
            lambda x: "Exploit Activo Conocido" if x else "Sin Exploit Reportado"
        )

        fig_pie = px.pie(
            exploit_counts,
            values="count",
            names="Estado",
            hole=0.5,
            color="Estado",
            color_discrete_map={
                "Exploit Activo Conocido": "#DC3545",
                "Sin Exploit Reportado": "#20C997",
            },
        )
        fig_pie.update_layout(
            margin=dict(t=20, b=20, l=20, r=20),
            height=280,
            paper_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e2e8f0"),
            legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5),
        )
        st.plotly_chart(fig_pie, use_container_width=True)
    else:
        st.info("ℹ️ Sin datos de exploits para mostrar.")

st.divider()

# ============================================================================
# 4. Tabla y Detalle de Vulnerabilidades NVD
# ============================================================================
st.subheader("📋 Catálogo NVD y Correlación de Incidentes")

if df_vulns.empty:
    st.info("ℹ️ Sin datos para mostrar. No se encontraron vulnerabilidades que coincidan con los filtros aplicados.")
else:
    # Preparación de DataFrame para visualización
    table_df = df_vulns.copy()
    if "published_date" in table_df.columns:
        table_df["Publicado"] = table_df["published_date"].dt.strftime("%Y-%m-%d")

    table_df["Exploit Activo"] = table_df["has_active_exploit"].apply(
        lambda x: "🔴 SÍ" if x else "🟢 No"
    )

    display_cols = [
        "cve_id",
        "severity",
        "cvss_score",
        "Exploit Activo",
        "cwe_id",
        "correlated_incidents",
        "Publicado",
        "description",
    ]
    present_cols = [c for c in display_cols if c in table_df.columns]

    st.dataframe(
        table_df[present_cols],
        use_container_width=True,
        hide_index=True,
        column_config={
            "cve_id": st.column_config.TextColumn("CVE ID", width="medium"),
            "severity": st.column_config.TextColumn("Severidad", width="small"),
            "cvss_score": st.column_config.NumberColumn("Score CVSS", format="%.1f", width="small"),
            "Exploit Activo": st.column_config.TextColumn("Exploit Activo", width="small"),
            "cwe_id": st.column_config.TextColumn("CWE ID", width="small"),
            "correlated_incidents": st.column_config.NumberColumn("Incidentes Vinculados", width="small"),
            "Publicado": st.column_config.TextColumn("Fecha Publicación", width="medium"),
            "description": st.column_config.TextColumn("Descripción NVD", width="large"),
        },
    )

    st.write("")
    st.markdown("#### 🔬 Inspección Detallada de Vulnerabilidad")
    selected_cve = st.selectbox(
        "Seleccionar CVE para inspección completa:",
        options=table_df["cve_id"].tolist(),
        index=0,
    )

    if selected_cve:
        cve_row = table_df[table_df["cve_id"] == selected_cve].iloc[0]
        with st.expander(f"Detalle NVD: {selected_cve} (CVSS {cve_row.get('cvss_score', 'N/A')})", expanded=True):
            exp_col1, exp_col2 = st.columns([3, 1])
            with exp_col1:
                st.markdown(f"**Descripción:**")
                st.write(cve_row.get("description") or "Sin descripción provista.")
                st.markdown(f"**Vector CVSS v3.1:** `{cve_row.get('cvss_vector') or 'N/A'}`")
                st.markdown(f"**Identificador CWE:** `{cve_row.get('cwe_id') or 'N/A'}`")
            with exp_col2:
                st.markdown(f"**Severidad:** `{cve_row.get('severity')}`")
                st.markdown(f"**Exploit Activo:** `{cve_row.get('Exploit Activo')}`")
                st.markdown(f"**Incidentes Asociados:** `{cve_row.get('correlated_incidents', 0)}`")
                st.markdown(f"🌐 [Ver en NIST NVD Database](https://nvd.nist.gov/vuln/detail/{selected_cve})")
