"""
Phase 4: Report Generator

Produces JSON and HTML reports from scan results.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime

from jinja2 import Template

from shadow_api_scanner.core.config import ScanConfig, SEVERITY_LEVELS
from shadow_api_scanner.core.models import ScanResult
from shadow_api_scanner.utils.helpers import ensure_dir

logger = logging.getLogger("shadow_api_scanner")

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Shadow API Scan Report — {{ scan.target_url }}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6}
.container{max-width:1200px;margin:0 auto;padding:2rem}
h1{font-size:1.8rem;background:linear-gradient(135deg,#6366f1,#8b5cf6);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:.5rem}
h2{font-size:1.3rem;color:#94a3b8;margin:2rem 0 1rem;border-bottom:1px solid #1e293b;padding-bottom:.5rem}
h3{font-size:1.1rem;color:#cbd5e1;margin:.5rem 0}
.header{background:linear-gradient(135deg,#1e1b4b,#312e81);border-radius:12px;padding:2rem;margin-bottom:2rem;border:1px solid #3730a3}
.subtitle{color:#a5b4fc;font-size:.9rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin:1rem 0}
.card{background:#1e293b;border-radius:10px;padding:1.5rem;border:1px solid #334155}
.card .label{color:#64748b;font-size:.8rem;text-transform:uppercase;letter-spacing:.05em}
.card .value{font-size:2rem;font-weight:700;margin-top:.3rem}
.critical{color:#ef4444}.high{color:#f97316}.medium{color:#eab308}.low{color:#22c55e}.info{color:#3b82f6}
.badge{display:inline-block;padding:2px 10px;border-radius:9999px;font-size:.75rem;font-weight:600}
.badge.Critical{background:#7f1d1d;color:#fca5a5}
.badge.High{background:#7c2d12;color:#fdba74}
.badge.Medium{background:#713f12;color:#fde047}
.badge.Low{background:#14532d;color:#86efac}
.badge.Info{background:#1e3a5f;color:#93c5fd}
table{width:100%;border-collapse:collapse;margin:1rem 0;font-size:.85rem}
th{background:#1e293b;color:#94a3b8;text-align:left;padding:10px 12px;border-bottom:2px solid #334155}
td{padding:10px 12px;border-bottom:1px solid #1e293b;vertical-align:top}
tr:hover{background:#1e293b80}
.vuln-card{background:#1e293b;border-radius:10px;padding:1.5rem;margin:1rem 0;border-left:4px solid #334155}
.vuln-card.Critical{border-left-color:#ef4444}
.vuln-card.High{border-left-color:#f97316}
.vuln-card.Medium{border-left-color:#eab308}
.vuln-card.Low{border-left-color:#22c55e}
pre{background:#0f172a;border:1px solid #334155;border-radius:6px;padding:1rem;overflow-x:auto;font-size:.8rem;margin:.5rem 0;color:#94a3b8}
.remediation{background:#14532d20;border:1px solid #16a34a30;border-radius:6px;padding:.8rem;margin-top:.8rem;font-size:.85rem}
.footer{text-align:center;color:#475569;margin-top:3rem;padding-top:1rem;border-top:1px solid #1e293b;font-size:.8rem}
.score-ring{width:80px;height:80px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:1.5rem;font-weight:700;margin:0 auto}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>🛡️ Shadow API Scanner Report</h1>
<p class="subtitle">Target: {{ scan.target_url }} &nbsp;|&nbsp; Scan ID: {{ scan.scan_id }} &nbsp;|&nbsp; {{ scan.started_at }}</p>
</div>

<div class="grid">
<div class="card"><div class="label">Risk Level</div>
<div class="value {{ scan.overall_risk_level.value | lower }}">{{ scan.overall_risk_level.value }}</div></div>
<div class="card"><div class="label">Risk Score</div>
<div class="value">{{ "%.1f"|format(scan.overall_risk_score) }}/10</div></div>
<div class="card"><div class="label">Total Endpoints</div>
<div class="value">{{ scan.all_endpoints|length }}</div></div>
<div class="card"><div class="label">Shadow APIs</div>
<div class="value critical">{{ scan.shadow_endpoints|length }}</div></div>
<div class="card"><div class="label">Vulnerabilities</div>
<div class="value high">{{ scan.vulnerabilities|length }}</div></div>
<div class="card"><div class="label">JS Files Analyzed</div>
<div class="value info">{{ scan.js_files_analyzed }}</div></div>
</div>

<div class="grid">
<div class="card"><div class="label">Critical</div><div class="value critical">{{ scan.critical_count }}</div></div>
<div class="card"><div class="label">High</div><div class="value high">{{ scan.high_count }}</div></div>
<div class="card"><div class="label">Medium</div><div class="value medium">{{ scan.medium_count }}</div></div>
<div class="card"><div class="label">Low</div><div class="value low">{{ scan.low_count }}</div></div>
</div>

<h2>📡 Discovered Endpoints ({{ scan.all_endpoints|length }})</h2>
<table>
<thead><tr><th>Method</th><th>URL</th><th>Type</th><th>Source</th><th>Shadow</th><th>Status</th></tr></thead>
<tbody>
{% for ep in scan.all_endpoints %}
<tr>
<td><strong>{{ ep.method }}</strong></td>
<td style="word-break:break-all">{{ ep.url }}</td>
<td>{{ ep.endpoint_type.value }}</td>
<td>{{ ep.source.value }}</td>
<td>{% if ep.is_shadow %}<span class="badge Critical">SHADOW</span>{% else %}<span class="badge Low">Documented</span>{% endif %}</td>
<td>{{ ep.status_code or '—' }}</td>
</tr>
{% endfor %}
</tbody>
</table>

<h2>⚠️ Vulnerabilities ({{ scan.vulnerabilities|length }})</h2>
{% for vuln in scan.vulnerabilities %}
<div class="vuln-card {{ vuln.severity.value }}">
<div style="display:flex;justify-content:space-between;align-items:start">
<h3>{{ vuln.title }}</h3>
<span class="badge {{ vuln.severity.value }}">{{ vuln.severity.value }} ({{ "%.1f"|format(vuln.risk_score) }})</span>
</div>
<p style="color:#94a3b8;font-size:.85rem;margin:.5rem 0">{{ vuln.owasp_category }}: {{ vuln.owasp_name }}</p>
<p>{{ vuln.description }}</p>
{% if vuln.poc_request %}<h4 style="margin-top:1rem;color:#64748b">Proof of Concept — Request</h4><pre>{{ vuln.poc_request }}</pre>{% endif %}
{% if vuln.poc_response %}<h4 style="color:#64748b">Response</h4><pre>{{ vuln.poc_response[:800] }}</pre>{% endif %}
{% if vuln.remediation %}<div class="remediation">💡 <strong>Remediation:</strong> {{ vuln.remediation }}</div>{% endif %}
{% if vuln.cwe_id %}<p style="margin-top:.5rem;font-size:.8rem;color:#64748b">CWE: {{ vuln.cwe_id }}</p>{% endif %}
</div>
{% endfor %}

{% if scan.errors %}
<h2>❌ Errors</h2>
<ul>{% for e in scan.errors %}<li style="color:#f87171">{{ e }}</li>{% endfor %}</ul>
{% endif %}

<div class="footer">
<p>Generated by Shadow API Scanner v1.0.0 &nbsp;|&nbsp; {{ scan.completed_at }}</p>
</div>
</div>
</body>
</html>"""


class ReportGenerator:
    """Generate JSON and HTML reports from scan results."""

    def __init__(self, config: ScanConfig):
        self.config = config

    def generate(self, result: ScanResult) -> dict[str, str]:
        """
        Generate reports in all configured formats.

        Returns:
            Dict mapping format name → output file path.
        """
        logger.info("=" * 60)
        logger.info("📄 PHASE 4: Report Generation")
        logger.info("=" * 60)

        output_dir = ensure_dir(self.config.output_dir)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        generated: dict[str, str] = {}

        # JSON report
        if "json" in self.config.report_formats:
            json_path = os.path.join(output_dir, f"scan_report_{timestamp}.json")
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(result.to_dict(), f, indent=2, default=str)
            generated["json"] = json_path
            logger.info(f"  ✅ JSON report: {json_path}")

        # HTML report
        if "html" in self.config.report_formats:
            html_path = os.path.join(output_dir, f"scan_report_{timestamp}.html")
            template = Template(HTML_TEMPLATE)
            html_content = template.render(scan=result)
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            generated["html"] = html_path
            logger.info(f"  ✅ HTML report: {html_path}")

        return generated
