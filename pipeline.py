import os
import sys
import json
import pandas as pd
from scoring import calculate_application_risks
from graph_engine import DependencyGraphEngine
from integration_engine import EnterpriseIntegrator

def run_automated_security_pipeline(risk_threshold=50.0):
    print("======================================================================")
    print("🛡️  INITIALIZING SYSTEM SCAN: AUTOMATED SBOM RISK PIPELINE")
    print("======================================================================")

    # Initialize Graph Engine
    print("\n[1/4] Constructing NetworkX attack-path mappings...")
    graph_engine = DependencyGraphEngine()
    graph_engine.load_all_data(
        'sample_data/applications.json', 
        'sample_data/sbom_dependencies.csv', 
        'sample_data/vulnerability_db.json'
    )
    
    integrator = EnterpriseIntegrator()

    # Calculate Risks
    print("\n[2/4] Executing risk equation scoring matrix...")
    df_report = calculate_application_risks()
    if df_report is None or df_report.empty:
        print("❌ Ingestion Error: Application list could not be parsed.")
        sys.exit(1)

    automated_master_records = []
    failed_build_triggered = False
    critical_violations_count = 0

    # Process each application
    print("\n[3/4] Running compliance validations & generating downstream integrations...")
    for _, row in df_report.iterrows():
        app_id = str(row['App ID']).strip()
        app_name = row['Application Name']
        risk_score = row['Risk Score']
        max_cvss = row['Max CVSS Severity']
        total_vulns = row['Total Vulnerabilities']

        # Get transitive paths
        paths = graph_engine.trace_transitive_vulnerabilities(app_id)
        
        status = "COMPLIANT"
        if risk_score >= risk_threshold:
            status = "FAIL (CRITICAL VIOLATION)"
            failed_build_triggered = True
            critical_violations_count += 1
            
            # 🚀 SIEM Integration: Trigger an alert immediately for a non-compliant gate
            integrator.push_siem_telemetry(app_name, risk_score, len(paths))
            
            # 🚀 Jira Integration: Auto-compile ticket templates for engineering teams
            ticket = integrator.compile_jira_markdown_payload(app_name, app_id, risk_score, paths)
            
            # Save the precompiled Jira ticket artifact locally for audit
            ticket_file = f"sample_data/jira_{app_id}.json"
            with open(ticket_file, 'w') as tf:
                json.dump(ticket, tf, indent=4)
            print(f"📝 Compiled ticket template written to: {ticket_file}")

        app_record = {
            "application_id": app_id,
            "application_name": app_name,
            "composite_risk_score": risk_score,
            "max_cvss_severity": max_cvss,
            "total_discovered_vulnerabilities": total_vulns,
            "compliance_gate_verdict": status,
            "resolved_transitive_attack_paths": paths[:5]  # Keep paths capped at 5 in the report to maintain speed
        }
        automated_master_records.append(app_record)
        print(f"  👉 Asset: {app_name} | Score: {risk_score}/100 | Verdict: {status}")

    # Output serialized artifact
    output_filename = "enterprise_risk_report.json"
    pipeline_payload = {
        "scan_timestamp": "2026-07-12T09:00:00Z",
        "global_summary": {
            "total_assets_scanned": len(automated_master_records),
            "critical_violations_found": critical_violations_count,
            "pipeline_passed": not failed_build_triggered
        },
        "records": automated_master_records
    }

    with open(output_filename, 'w') as f:
        json.dump(pipeline_payload, f, indent=4)
    print(f"\n[4/4] Unified scan artifact successfully written to: {output_filename}")

    # Final CI/CD system gate check
    if failed_build_triggered:
        print(f"\n❌ PIPELINE FAILURE: {critical_violations_count} application(s) failed corporate risk gates.")
        print("💡 Action Required: Upstream builds blocked. Apply mitigations and rerun.")
        print("======================================================================")
        sys.exit(1)
    else:
        print("\n🟢 PIPELINE SUCCESS: All applications compliant.")
        print("======================================================================")
        sys.exit(0)

if __name__ == "__main__":
    run_automated_security_pipeline(risk_threshold=50.0)