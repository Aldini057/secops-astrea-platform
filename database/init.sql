-- Extensiones para UUID y timestamps
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Tabla de Agentes / Hosts Registrados (Monitoreados por Wazuh)
CREATE TABLE IF NOT EXISTS agents_inventory (
    agent_id VARCHAR(50) PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    ip_address INET NOT NULL,
    os_name VARCHAR(100),
    os_version VARCHAR(100),
    status VARCHAR(50) DEFAULT 'active', -- active, isolated, disconnected
    last_keepalive TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Tabla de Inteligencia de Vulnerabilidades (NVD Cache)
CREATE TABLE IF NOT EXISTS nvd_vulnerabilities (
    cve_id VARCHAR(50) PRIMARY KEY,
    description TEXT,
    cvss_score NUMERIC(3, 1),
    cvss_vector VARCHAR(100),
    severity VARCHAR(20), -- LOW, MEDIUM, HIGH, CRITICAL
    cwe_id VARCHAR(50),
    has_active_exploit BOOLEAN DEFAULT FALSE,
    published_date TIMESTAMP WITH TIME ZONE,
    last_modified_date TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. Tabla de Incidentes y Alertas Integradas (Splunk + Wazuh + SOAR)
CREATE TABLE IF NOT EXISTS security_incidents (
    incident_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_detection VARCHAR(50) NOT NULL, -- SPLUNK, WAZUH_MANAGER, HYBRID
    alert_name VARCHAR(255) NOT NULL,
    rule_id VARCHAR(100),
    
    -- Origen y Destino
    src_ip INET,
    src_country VARCHAR(50),
    src_reputation_score INT, -- AbuseIPDB / OTX Score (0-100)
    dst_ip INET,
    dst_port INT,
    agent_id VARCHAR(50) REFERENCES agents_inventory(agent_id) ON DELETE SET NULL,
    
    -- Contexto de Vulnerabilidad
    affected_software VARCHAR(255),
    associated_cve VARCHAR(50) REFERENCES nvd_vulnerabilities(cve_id) ON DELETE SET NULL,
    
    -- Evaluación de Riesgo y Estado
    calculated_risk_score NUMERIC(4, 1), -- (CTI Score * 0.4) + (CVSS * 0.6 * 10)
    status VARCHAR(50) DEFAULT 'NEW', -- NEW, ENRICHED, CONTAINED_AUTOMATICALLY, RESOLVED, FALSE_POSITIVE
    
    -- Acciones de Respuesta Activa (EDR Wazuh)
    active_response_executed VARCHAR(100), -- ISOLATE_AGENT, BLOCK_SRC_IP, KILL_PID, NONE
    active_response_status VARCHAR(50),   -- SUCCESS, FAILED, PENDING, SKIPPED
    response_payload JSONB,
    
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP WITH TIME ZONE
);

-- Índices de consulta rápida para el dashboard BID
CREATE INDEX IF NOT EXISTS idx_incidents_detected_at ON security_incidents(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON security_incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_risk_score ON security_incidents(calculated_risk_score DESC);
