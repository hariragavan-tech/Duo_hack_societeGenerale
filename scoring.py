import pandas as pd
import json
import os
import ast
from datetime import datetime

def load_dependencies():
    try:
        return pd.read_csv('sample_data/sbom_dependencies.csv')
    except Exception as e:
        print(f"Error loading dependencies: {e}")
        return None

def calculate_application_risks():
    try:
        # Load official files
        with open('sample_data/applications.json', 'r') as f:
            apps = json.load(f)
        with open('sample_data/vulnerability_db.json', 'r') as f:
            vuln_list = json.load(f)
        with open('sample_data/license_rules.json', 'r') as f:
            license_rules = json.load(f)
            
        deps_df = pd.read_csv('sample_data/sbom_dependencies.csv')
        
        # High performance indexing hash maps
        vuln_dict = {v['library']: v for v in vuln_list}
        lic_dict = {l['license']: l for l in license_rules}
        
        report_rows = []
        CURRENT_YEAR = 2026
        
        for app in apps:
            app_id = app['app_id']
            app_name = app['name']
            criticality = app['criticality']
            
            # Filter rows utilizing the exact official header: 'application_id'
            app_deps = deps_df[deps_df['application_id'] == app_id]
            
            total_vulns = 0
            max_cvss = 0.0
            license_penalty = 0
            maintenance_penalty = 0
            
            for _, dep_row in app_deps.iterrows():
                lib = dep_row['library']
                lic = dep_row['license']
                last_updated_str = dep_row['last_updated']
                
                # Check 1: Volumetric CVE Scans
                if lib in vuln_dict:
                    total_vulns += 1
                    cvss = float(vuln_dict[lib]['cvss_score'])
                    if cvss > max_cvss:
                        max_cvss = cvss
                        
                # Check 2: License Risk Rules (FIXED: Safe key lookup using .get())
                if lic in lic_dict:
                    rule = lic_dict[lic]
                    if rule.get('status') == 'DISALLOWED':
                        risk_lvl = rule.get('risk_level', 'LOW')
                        if risk_lvl == 'CRITICAL':
                            license_penalty = max(license_penalty, 35)
                        elif risk_lvl == 'HIGH':
                            license_penalty = max(license_penalty, 20)
                        else:
                            license_penalty = max(license_penalty, 10)
                            
                # Check 3: Maintenance age calculations
                try:
                    updated_year = datetime.strptime(last_updated_str.strip(), "%Y-%m-%d").year
                    if (CURRENT_YEAR - updated_year) >= 2:
                        maintenance_penalty = min(maintenance_penalty + 5, 20)
                except:
                    pass
            
            # 🛠️ FIXED RISK SCORING METHODOLOGY:
            # Replaced the artificial +45 point boost with a balanced enterprise calculation framework.
            # CVSS base component (scaled up to 50 max points) + license status + maintenance lag.
            cvss_component = max_cvss * 5.0
            base_score = cvss_component + license_penalty + maintenance_penalty
            
            # Adjust score dynamically based on business asset criticality weighting multipliers
            if criticality == "HIGH":
                base_score += 15.0
            elif criticality == "CRITICAL":
                base_score += 25.0
                
            composite_risk_score = min(round(base_score, 1), 100.0)
            
            report_rows.append({
                "App ID": app_id,
                "Application Name": app_name,
                "Business Criticality": criticality,
                "Risk Score": composite_risk_score,
                "Total Vulnerabilities": total_vulns,
                "Max CVSS Severity": max_cvss
            })
            
        return pd.DataFrame(report_rows)
    except Exception as e:
        print(f"❌ Error compiling application risks: {str(e)}")
        return None

def automated_codebase_static_scan(source_file_to_scan, ml_intel_engine):
    """
    Leverages Abstract Syntax Tree nodes to find every single function name explicitly 
    declared within an app module file, automatically routing them to the verification matrix.
    """
    if not os.path.exists(source_file_to_scan):
        return {}

    try:
        with open(source_file_to_scan, "r", errors='ignore') as f:
            code_str = f.read()

        node_tree = ast.parse(code_str)
        found_functions = [node.name for node in ast.walk(node_tree) if isinstance(node, ast.FunctionDef)]
        
        static_verdicts = {}
        high_risk_keywords = ["lookup", "execute", "eval", "process", "validate", "pipeline", "scan", "risk"]
        
        for func in found_functions:
            verdict = ml_intel_engine.predict_exploitability_lite(source_file_to_scan, func)
            
            # Map exact data dictionary property columns expected by the Streamlit display ledger
            if any(k in func.lower() for k in high_risk_keywords) or "HIGH" in verdict:
                static_verdicts[func] = {
                    "Discovered Code Location": os.path.basename(source_file_to_scan),
                    "Exploitability Matrix Status": "🔴 HIGH EXPLOITABILITY DETECTED",
                    "Policy Enforcement Action": "🚫 BLOCK PIPELINE BUILD"
                }
            else:
                static_verdicts[func] = {
                    "Discovered Code Location": os.path.basename(source_file_to_scan),
                    "Exploitability Matrix Status": "🟢 NOMINAL ROUTE CLEAR",
                    "Policy Enforcement Action": "✅ PERMIT PASSTHROUGH"
                }
        return static_verdicts
    except Exception as e:
        return {"error": {"Discovered Code Location": "Error", "Exploitability Matrix Status": str(e), "Policy Enforcement Action": "FAIL"}}