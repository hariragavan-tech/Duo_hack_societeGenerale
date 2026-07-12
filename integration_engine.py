import json
import urllib.request

class EnterpriseIntegrator:
    def __init__(self, webhook_url=None):
        # We use httpbin.org to cleanly mock and test POST requests locally
        self.webhook_url = webhook_url or "https://httpbin.org/post"

    def push_siem_telemetry(self, app_name, risk_score, violation_count):
        """
        Simulates sending detailed security telemetry payloads directly to SIEM (Splunk/Datadog).
        """
        severity = "CRITICAL" if risk_score >= 70 else "WARNING"
        payload = {
            "event": {
                "source": "DevSecOps-Orchestrator-Gate",
                "application": app_name,
                "composite_risk_score": risk_score,
                "severity_class": severity,
                "metrics": {
                    "vulnerable_paths_discovered": violation_count,
                    "pipeline_status": "BLOCKED" if risk_score >= 50 else "APPROVED"
                }
            }
        }
        
        print(f"📡 [SIEM TELEMETRY] Pushing event payload for '{app_name}' to Corporate SIEM Pipeline...")
        
        try:
            data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(
                self.webhook_url, 
                data=data, 
                headers={'Content-Type': 'application/json', 'User-Agent': 'Security-Orchestrator'}
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status == 200:
                    print("✅ SIEM telemetry stream ingestion acknowledged successfully.")
                    return True
        except Exception as e:
            print(f"⚠️ Simulated telemetry routing bypass: {e}")
            return False

    def compile_jira_markdown_payload(self, app_name, app_id, risk_score, paths):
        """
        Pre-formats a detailed Jira Ticket layout complete with remediation details
        and specific transitive path mappings for engineering teams.
        """
        print(f"🎫 [JIRA UTILITY] Compiling pre-filled ticket payload for '{app_name}'...")
        
        description = (
            f"h1. 🚨 SECURITY COMPLIANCE DEVIATION DETECTED\n\n"
            f"The automated CI/CD pipeline blocked deployment of *{app_name}* ({app_id}) "
            f"due to a security compliance threshold breach.\n\n"
            f"* *Assigned Risk Score:* {risk_score}/100 (Threshold: 50.0)\n"
            f"* *Pipeline Action:* DEPLOYMENT GATE BLOCKED\n\n"
            f"h3. 🔍 Detected Transitive Risk Paths:\n"
        )
        
        # Pull top 3 paths to detail on the ticket
        for idx, path in enumerate(paths[:3], 1):
            description += f"{idx}. *{path['cve_id']}* (CVSS: {path['cvss_score']}) -> Attack Vector: `{path['attack_path']}`\n"
            
        description += (
            f"\nh3. 🛠️ Auto-Assigned Mitigations:\n"
            f"* Run a dependency tree isolation sweep.\n"
            f"* Replace/upgrade affected transitive components to latest non-vulnerable versions.\n"
            f"* Run `python pipeline.py` locally to re-verify compliance status."
        )

        jira_issue = {
            "fields": {
                "project": {"key": "SEC"},
                "summary": f"Security Defect: Resolve Transitive Dependencies in {app_name}",
                "description": description,
                "issuetype": {"name": "Bug"},
                "priority": {"name": "High"}
            }
        }
        
        return jira_issue