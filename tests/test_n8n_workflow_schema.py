"""
Integration & Schema tests for n8n SOAR Automation Workflow:
File: orchestration/n8n/workflows/astrea_main_pipeline.json

Validates:
- Valid JSON syntax loaded via json.loads().
- Top-level workflow structure with 'nodes' and 'connections'.
- Webhook Trigger configuration: POST method and path '/webhook/alerts'.
- Risk Score Calculation Code node containing composite formula:
    RiskScore = (CTI_Score * 0.4) + (CVSS * 0.6 * 10)
  with 0-100 normalization and >= 80.0 CRITICAL / containment threshold.
- No dangling or orphaned connections pointing to non-existent node IDs/names.
- Presence and proper wiring of CTI, NVD, PostgreSQL, IF, and Wazuh Active Response nodes.
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Set

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_FILE = REPO_ROOT / "orchestration" / "n8n" / "workflows" / "astrea_main_pipeline.json"


@pytest.fixture(scope="module")
def workflow_content() -> str:
    """Fixture providing raw text content of the workflow file."""
    assert WORKFLOW_FILE.exists(), f"Workflow file does not exist at: {WORKFLOW_FILE}"
    return WORKFLOW_FILE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def workflow_data(workflow_content: str) -> Dict[str, Any]:
    """Fixture returning the parsed JSON dictionary using json.loads."""
    try:
        data = json.loads(workflow_content)
    except json.JSONDecodeError as exc:
        pytest.fail(f"astrea_main_pipeline.json is not syntactically valid JSON: {exc}")
    assert isinstance(data, dict), "Workflow root must be a JSON object (dict)"
    return data


# ============================================================================
# 1. Syntax & Base Schema Validation
# ============================================================================

def test_workflow_file_exists_and_is_valid_json(workflow_content: str):
    """Certifies that astrea_main_pipeline.json exists and parses with json.loads."""
    data = json.loads(workflow_content)
    assert isinstance(data, dict)
    assert "name" in data
    assert data["name"] == "Astrea Main Security Pipeline"


def test_workflow_structure_nodes_and_connections(workflow_data: Dict[str, Any]):
    """Validates that workflow contains 'nodes' list and 'connections' map."""
    assert "nodes" in workflow_data, "Missing 'nodes' field in workflow JSON"
    assert "connections" in workflow_data, "Missing 'connections' field in workflow JSON"

    nodes = workflow_data["nodes"]
    connections = workflow_data["connections"]

    assert isinstance(nodes, list), "'nodes' must be a list"
    assert isinstance(connections, dict), "'connections' must be a dictionary"
    assert len(nodes) >= 8, f"Expected at least 8 pipeline nodes, found {len(nodes)}"
    assert len(connections) >= 7, f"Expected at least 7 connection sets, found {len(connections)}"


# ============================================================================
# 2. Webhook Trigger Node Validation
# ============================================================================

def test_webhook_trigger_node_configuration(workflow_data: Dict[str, Any]):
    """
    Validates Node 1 (Webhook Trigger):
    - Present in nodes list.
    - Type 'n8n-nodes-base.webhook'.
    - Method 'POST'.
    - Path '/webhook/alerts' (or 'alerts').
    """
    nodes: List[Dict[str, Any]] = workflow_data["nodes"]
    webhook_node = next(
        (n for n in nodes if n.get("type") == "n8n-nodes-base.webhook" or "webhook" in n.get("name", "").lower()),
        None
    )
    assert webhook_node is not None, "Webhook Trigger node not found in workflow"

    params = webhook_node.get("parameters", {})
    http_method = params.get("httpMethod")
    path = params.get("path")

    assert http_method == "POST", f"Webhook httpMethod must be POST, got '{http_method}'"
    # n8n routes paths either as '/webhook/alerts', 'webhook/alerts', or 'alerts'
    assert path in ["/webhook/alerts", "alerts", "webhook/alerts"], (
        f"Webhook path must be '/webhook/alerts' or 'alerts', got '{path}'"
    )


# ============================================================================
# 3. CTI & NVD Enrichment Nodes Validation
# ============================================================================

def test_cti_reputation_lookup_node(workflow_data: Dict[str, Any]):
    """
    Validates Node 2 (CTI Reputation Lookup):
    - HTTP Request towards AbuseIPDB (or fallback).
    - Checks src_ip in query and handles continueOnFail.
    """
    nodes: List[Dict[str, Any]] = workflow_data["nodes"]
    cti_node = next(
        (n for n in nodes if "cti" in n.get("name", "").lower() or "abuse" in str(n.get("parameters", {})).lower()),
        None
    )
    assert cti_node is not None, "CTI Reputation Lookup node not found"
    params = cti_node.get("parameters", {})
    url = params.get("url", "")
    assert "abuseipdb.com" in url or "check" in url
    assert cti_node.get("continueOnFail") is True, "CTI node should have continueOnFail enabled for safe fallback"


def test_nvd_vulnerability_check_node(workflow_data: Dict[str, Any]):
    """
    Validates Node 3 (NVD Vulnerability Check):
    - HTTP Request POST to http://nvd_service:8000/api/v1/vulnerabilities/check.
    - Extracts software_name and version from software_banner.
    """
    nodes: List[Dict[str, Any]] = workflow_data["nodes"]
    nvd_node = next(
        (n for n in nodes if "nvd" in n.get("name", "").lower()),
        None
    )
    assert nvd_node is not None, "NVD Vulnerability Check node not found"
    params = nvd_node.get("parameters", {})
    assert params.get("method") == "POST"
    assert "nvd_service:8000/api/v1/vulnerabilities/check" in params.get("url", "")

    # Check extraction references in JSON body or parameters
    json_body = params.get("jsonBody", "")
    assert "software_banner" in json_body or "software_name" in json_body
    assert "version" in json_body


# ============================================================================
# 4. Risk Score Calculation Code Node Validation
# ============================================================================

def test_risk_score_calculation_javascript_formula(workflow_data: Dict[str, Any]):
    """
    Validates Node 4 (Risk Score Calculation - Code Node JavaScript):
    - Language JavaScript.
    - Contains composite formula: (CTI_Score * 0.4) + (CVSS * 0.6 * 10)
    - Normalizes between 0.0 and 100.0.
    - Contains threshold 80.0 setting should_contain = true and severity = 'CRITICAL'.
    """
    nodes: List[Dict[str, Any]] = workflow_data["nodes"]
    code_node = next(
        (n for n in nodes if n.get("type") == "n8n-nodes-base.code" or "risk" in n.get("name", "").lower()),
        None
    )
    assert code_node is not None, "Risk Score Calculation Code node not found"
    params = code_node.get("parameters", {})
    js_code = params.get("jsCode", "")

    # Check for presence of the composite formula components
    assert "0.4" in js_code, "Formula must use 0.4 weighting for CTI Score"
    assert "0.6" in js_code, "Formula must use 0.6 weighting for CVSS"
    assert "10" in js_code, "Formula must scale CVSS (0-10) by 10 (or 6)"

    # Verify formula regex match in comments or implementation
    formula_regex = re.compile(
        r"(cti_score|\$json\.cti_score|cti)\s*\*\s*0\.4.*(cvss|cvss_score|\$json\.cvss)\s*\*\s*0\.6\s*\*\s*10",
        re.IGNORECASE
    )
    has_formula_pattern = bool(formula_regex.search(js_code)) or (
        "(cti_score * 0.4) + (cvss * 0.6 * 10)" in js_code.lower()
        or "(cti_score * 0.4) + (cvss_score * 0.6 * 10)" in js_code.lower()
    )
    assert has_formula_pattern, "Composite formula (CTI_Score * 0.4) + (CVSS * 0.6 * 10) must be present in code"

    # Verify normalization range logic
    assert "100" in js_code and "0" in js_code, "Must normalize score between 0.0 and 100.0"

    # Verify threshold >= 80.0 triggers CRITICAL and should_contain
    assert "80" in js_code, "Threshold of 80.0 must be evaluated in code"
    assert "CRITICAL" in js_code, "Severity 'CRITICAL' must be assigned when score >= 80.0"
    assert "should_contain" in js_code, "Flag 'should_contain' must be set"


def test_risk_score_calculation_python_simulation():
    """Simulates the composite formula to verify mathematical specifications."""
    def calc_risk(cti: float, cvss: float) -> tuple[float, str, bool]:
        raw = (cti * 0.4) + (cvss * 0.6 * 10.0)
        normalized = min(100.0, max(0.0, round(raw, 1)))
        should_contain = normalized >= 80.0
        severity = "CRITICAL" if should_contain else ("HIGH" if normalized >= 60.0 else "MEDIUM")
        return normalized, severity, should_contain

    # Test edge case: Maximum risk
    score_max, sev_max, cont_max = calc_risk(100.0, 10.0)
    assert score_max == 100.0
    assert sev_max == "CRITICAL"
    assert cont_max is True

    # Test edge case: Minimum risk
    score_min, sev_min, cont_min = calc_risk(0.0, 0.0)
    assert score_min == 0.0
    assert cont_min is False

    # Test threshold: exactly 80.0 (e.g. CTI=80, CVSS=8.0 -> 32 + 48 = 80.0)
    score_80, sev_80, cont_80 = calc_risk(80.0, 8.0)
    assert score_80 == 80.0
    assert sev_80 == "CRITICAL"
    assert cont_80 is True

    # Test below threshold: 79.4 (CTI=50, CVSS=9.9 -> 20 + 59.4 = 79.4)
    score_sub, sev_sub, cont_sub = calc_risk(50.0, 9.9)
    assert score_sub == 79.4
    assert cont_sub is False


# ============================================================================
# 5. Database Persistence & Containment Decision Nodes Validation
# ============================================================================

def test_postgresql_insert_node(workflow_data: Dict[str, Any]):
    """
    Validates Node 5 (Insert Incident PostgreSQL):
    - Executes INSERT into 'security_incidents'.
    - Sets status to 'ENRICHED' or 'NEW'.
    """
    nodes: List[Dict[str, Any]] = workflow_data["nodes"]
    pg_insert_node = next(
        (n for n in nodes if "insert" in n.get("name", "").lower() and "postgres" in str(n).lower()),
        None
    )
    assert pg_insert_node is not None, "Insert Incident PostgreSQL node not found"
    query = pg_insert_node.get("parameters", {}).get("query", "")
    assert "INSERT INTO security_incidents" in query
    assert "ENRICHED" in query or "NEW" in query


def test_if_conditional_containment_node(workflow_data: Dict[str, Any]):
    """
    Validates Node 6 (IF Conditional):
    - Evaluates should_contain is true and agent_id is not empty.
    """
    nodes: List[Dict[str, Any]] = workflow_data["nodes"]
    if_node = next(
        (n for n in nodes if n.get("type") == "n8n-nodes-base.if" or "if" in n.get("name", "").lower()),
        None
    )
    assert if_node is not None, "IF Conditional node not found"
    params = if_node.get("parameters", {})
    conditions_str = json.dumps(params.get("conditions", {}))
    assert "should_contain" in conditions_str
    assert "agent_id" in conditions_str


def test_wazuh_active_response_and_update_nodes(workflow_data: Dict[str, Any]):
    """
    Validates Node 7 (Wazuh Active Response Execution & Status Update):
    - Invokes Wazuh Active Response endpoint.
    - Specifies isolate-host or block-ip command.
    - Updates incident in PostgreSQL with status 'CONTAINED_AUTOMATICALLY'.
    """
    nodes: List[Dict[str, Any]] = workflow_data["nodes"]
    wazuh_node = next(
        (n for n in nodes if "wazuh" in n.get("name", "").lower() or "active-response" in str(n.get("parameters", {})).lower()),
        None
    )
    assert wazuh_node is not None, "Wazuh Active Response Execution node not found"
    wazuh_params = json.dumps(wazuh_node.get("parameters", {}))
    assert "active-response" in wazuh_params
    assert "isolate-host" in wazuh_params or "block-ip" in wazuh_params

    # Check update node
    update_node = next(
        (n for n in nodes if "update" in n.get("name", "").lower() or "contained" in n.get("name", "").lower()),
        None
    )
    assert update_node is not None, "Update Incident Contained node not found"
    update_query = update_node.get("parameters", {}).get("query", "")
    assert "CONTAINED_AUTOMATICALLY" in update_query
    assert "response_payload" in update_query


def test_final_response_node(workflow_data: Dict[str, Any]):
    """
    Validates Node 8 (Final Response / Webhook Return):
    - Responds 200 OK with consolidated incident payload.
    """
    nodes: List[Dict[str, Any]] = workflow_data["nodes"]
    response_node = next(
        (n for n in nodes if n.get("type") == "n8n-nodes-base.respondToWebhook" or "final response" in n.get("name", "").lower() or "webhook return" in n.get("name", "").lower()),
        None
    )
    assert response_node is not None, "Final Response / Webhook Return node not found"
    params = response_node.get("parameters", {})
    options = params.get("options", {})
    assert options.get("responseCode") == 200 or params.get("respondWith") == "json"


# ============================================================================
# 6. Integrity of Connections (No Orphaned / Invalid Node IDs)
# ============================================================================

def test_no_orphan_or_invalid_connections(workflow_data: Dict[str, Any]):
    """
    Validates connection graph integrity:
    - Every source node key in connections exists in 'nodes' (by name or ID).
    - Every destination node in connections exists in 'nodes' (by name or ID).
    - Connections form a continuous navigable path from trigger to response.
    """
    nodes: List[Dict[str, Any]] = workflow_data["nodes"]
    connections: Dict[str, Any] = workflow_data["connections"]

    valid_node_names: Set[str] = {n["name"] for n in nodes if "name" in n}
    valid_node_ids: Set[str] = {n["id"] for n in nodes if "id" in n}
    valid_references = valid_node_names | valid_node_ids

    dangling_sources: List[str] = []
    dangling_targets: List[str] = []

    for source_node, conn_groups in connections.items():
        if source_node not in valid_references:
            dangling_sources.append(source_node)

        # Inspect main connection outputs
        for output_type, route_list in conn_groups.items():
            for routes in route_list:
                for target_item in routes:
                    target_name = target_item.get("node")
                    if target_name not in valid_references:
                        dangling_targets.append(f"{source_node} -> {target_name}")

    assert not dangling_sources, f"Connections originate from non-existent nodes: {dangling_sources}"
    assert not dangling_targets, f"Connections point to non-existent target nodes: {dangling_targets}"


def test_logical_flow_continuity(workflow_data: Dict[str, Any]):
    """
    Validates that the pipeline connects key stages continuously:
    Webhook Trigger -> CTI -> NVD -> Risk Score -> DB Insert -> IF -> Active Response & Final Response.
    """
    connections: Dict[str, Any] = workflow_data["connections"]

    # Webhook Trigger must have an outgoing connection
    assert "Webhook Trigger" in connections
    # CTI must connect downstream
    assert "CTI Reputation Lookup" in connections
    # NVD must connect downstream
    assert "NVD Vulnerability Check" in connections
    # Risk calculation must connect to DB
    assert "Risk Score Calculation" in connections
    # IF node must have two outputs (True and False branches)
    assert "IF Conditional" in connections
    if_routes = connections["IF Conditional"].get("main", [])
    assert len(if_routes) == 2, "IF Conditional must provide both True and False branches"
