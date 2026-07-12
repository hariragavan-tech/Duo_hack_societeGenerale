import os
import json
import csv
import random
from datetime import datetime, timedelta

# Set seed for perfectly reproducible datasets across both developers
random.seed(42)

# Ensure output directory exists
os.makedirs('sample_data', exist_ok=True)

print("🚀 Starting synthetic SBOM data generation...")

# -------------------------------------------------------------------------
# 1. Create applications.json (10 Records)
# -------------------------------------------------------------------------
apps = [
    {"app_id": "APP-01", "name": "Core-Payment-Gateway", "business_criticality": "Critical", "owner": "FinTech-Team", "type": "proprietary"},
    {"app_id": "APP-02", "name": "Customer-Data-API", "business_criticality": "High", "owner": "Backend-Squad", "type": "proprietary"},
    {"app_id": "APP-03", "name": "Auth-Service", "business_criticality": "Critical", "owner": "SecOps-Team", "type": "proprietary"},
    {"app_id": "APP-04", "name": "Public-Marketing-Site", "business_criticality": "Low", "owner": "Marketing-IT", "type": "proprietary"},
    {"app_id": "APP-05", "name": "Analytics-Dashboard", "business_criticality": "Medium", "owner": "Data-Platform", "type": "proprietary"},
    {"app_id": "APP-06", "name": "Inventory-Manager", "business_criticality": "High", "owner": "Logistics-Devs", "type": "proprietary"},
    {"app_id": "APP-07", "name": "Notification-Hub", "business_criticality": "Medium", "owner": "Ops-Team", "type": "proprietary"},
    {"app_id": "APP-08", "name": "Reporting-Engine", "business_criticality": "Medium", "owner": "Finance-IT", "type": "proprietary"},
    {"app_id": "APP-09", "name": "Internal-Log-Viewer", "business_criticality": "Low", "owner": "SRE-Team", "type": "internal"},
    {"app_id": "APP-10", "name": "DevOps-Automation-Tool", "business_criticality": "Low", "owner": "Platform-Eng", "type": "internal"}
]

with open('sample_data/applications.json', 'w') as f:
    json.dump(apps, f, indent=4)

# -------------------------------------------------------------------------
# 2. Create license_rules.json (15 Records)
# -------------------------------------------------------------------------
license_rules = [
    {"license_type": "MIT", "compatible_with_proprietary": True, "risk_level": "Low", "description": "Highly permissive"},
    {"license_type": "Apache-2.0", "compatible_with_proprietary": True, "risk_level": "Low", "description": "Permissive with patent grant"},
    {"license_type": "BSD-3-Clause", "compatible_with_proprietary": True, "risk_level": "Low", "description": "Permissive minimal restriction"},
    {"license_type": "GPL-3.0", "compatible_with_proprietary": False, "risk_level": "Critical", "description": "Viral copyleft - strict sharing requirements"},
    {"license_type": "GPL-2.0", "compatible_with_proprietary": False, "risk_level": "Critical", "description": "Viral copyleft old version"},
    {"license_type": "LGPL-3.0", "compatible_with_proprietary": True, "risk_level": "Medium", "description": "Permissive for dynamic linking only"},
    {"license_type": "AGPL-3.0", "compatible_with_proprietary": False, "risk_level": "Critical", "description": "Network-triggered viral copyleft"},
    {"license_type": "MPL-2.0", "compatible_with_proprietary": True, "risk_level": "Medium", "description": "File-level copyleft modification restriction"},
    {"license_type": "Proprietary", "compatible_with_proprietary": True, "risk_level": "Low", "description": "Commercial customized framework"},
    {"license_type": "None", "compatible_with_proprietary": False, "risk_level": "High", "description": "Unlicensed/Unknown legal status"}
]

with open('sample_data/license_rules.json', 'w') as f:
    json.dump(license_rules, f, indent=4)

# -------------------------------------------------------------------------
# 3. Define Libraries, Vulnerabilities, and Labels to match the Risk Targets
# -------------------------------------------------------------------------
# Total rows to generate = 500 (10 apps x 50 libraries each)
# Targets:
# Clean: 45% (225 rows)
# Vulnerable (Direct): 18% (90 rows)
# Unmaintained: 15% (75 rows)
# License Conflict: 12% (60 rows)
# Transitive Vulnerable: 10% (50 rows)

today = datetime.now()
three_years_ago = (today - timedelta(days=3*365)).strftime('%Y-%m-%d')
one_year_ago = (today - timedelta(days=365)).strftime('%Y-%m-%d')
six_months_ago = (today - timedelta(days=180)).strftime('%Y-%m-%d')

vulnerability_db = []
sbom_dependencies = []
dependency_labels = []

# Generate helper data frameworks
libs_clean = [f"lib-clean-{i}" for i in range(1, 100)]
libs_vuln = [f"lib-vuln-{i}" for i in range(1, 50)]
libs_unmaintained = [f"lib-legacy-{i}" for i in range(1, 50)]
libs_license = [f"lib-copyleft-{i}" for i in range(1, 50)]
libs_transitive = [f"lib-trans-{i}" for i in range(1, 50)]

cve_counter = 1001

def create_cve(lib_name, version, severity):
    global cve_counter
    cve_id = f"CVE-2026-{cve_counter}"
    cve_counter += 1
    cvss = round(random.uniform(9.0, 10.0), 1) if severity == "Critical" else round(random.uniform(7.0, 8.9), 1) if severity == "High" else round(random.uniform(4.0, 6.9), 1)
    
    vulnerability_db.append({
        "cve_id": cve_id,
        "affected_library": lib_name,
        "affected_version": version,
        "cvss_score": cvss,
        "patch_available": random.choice([True, False])
    })
    return cve_id, cvss

# Track item allocations systematically across the 500 records
row_index = 0

for app in apps:
    app_id = app['app_id']
    is_internal = app['type'] == 'internal'
    
    # Each app gets 50 library components assigned to it
    for local_idx in range(50):
        # Determine the target bucket based on total row index distribution thresholds
        if row_index < 225:
            # 45% Clean
            status, r_type, r_sev = "Clean", "None", "Low"
            lib_name = random.choice(libs_clean)
            version = f"{random.randint(1,5)}.{random.randint(0,9)}.0"
            license_type = random.choice(["MIT", "Apache-2.0", "BSD-3-Clause"])
            last_updated = random.choice([one_year_ago, Geist_date := six_months_ago])
            dep_type = "direct"
            parent = app_id
            expl = "Component secure with standard verified open source parameters."
            
        elif row_index < 315:
            # 18% Direct Vulnerable
            status, r_type, r_sev = "Vulnerable", "Known CVE", random.choice(["Critical", "High", "Medium"])
            lib_name = random.choice(libs_vuln)
            version = "2.14.1" # Standardized version matching vulnerability
            license_type = "MIT"
            last_updated = six_months_ago
            dep_type = "direct"
            parent = app_id
            cve_id, cvss = create_cve(lib_name, version, r_sev)
            expl = f"Directly references {lib_name} containing active payload exposure tracked via {cve_id} (CVSS: {cvss})."
            
        elif row_index < 390:
            # 15% Unmaintained Risk
            status, r_type, r_sev = "Unmaintained", "Maintenance Risk", "Medium"
            lib_name = random.choice(libs_unmaintained)
            version = "0.4.2-beta"
            license_type = "Apache-2.0"
            last_updated = three_years_ago # Stale > 2 Years
            dep_type = "direct"
            parent = app_id
            expl = "Codebase component abandoned; zero structural commits or version upgrades pushed within the past 2+ years."
            
        elif row_index < 450:
            # 12% License Conflict Risk
            lib_name = random.choice(libs_license)
            version = "1.0.0"
            last_updated = six_months_ago
            dep_type = "direct"
            parent = app_id
            
            # Implementation of the internal vs proprietary edge-case rule
            if is_internal:
                license_type = "GPL-3.0"
                status, r_type, r_sev = "Clean", "None", "Low"
                expl = "GPL-3.0 dependency verified inside safe non-distributed workspace; policy exempt."
            else:
                license_type = random.choice(["GPL-3.0", "AGPL-3.0", "None"])
                status, r_type, r_sev = "Conflict", "License Infraction", "Critical" if license_type != "None" else "High"
                expl = f"Compliance alert: Linkage of structural {license_type} elements inside closed proprietary builds."
                
        else:
            # 10% Transitive Vulnerability Chains
            status, r_type, r_sev = "Vulnerable", "Transitive CVE", random.choice(["Critical", "High", "Medium"])
            lib_name = random.choice(libs_transitive)
            version = "1.0.8"
            license_type = "MIT"
            last_updated = six_months_ago
            dep_type = "transitive"
            
            # Form an explicit parent link chain to represent graph layers
            intermediate_parent = f"direct-bridge-lib-{app_id}"
            parent = intermediate_parent
            
            cve_id, cvss = create_cve(lib_name, version, r_sev)
            expl = f"Nested exposure risk: Inherited via underlying structural connector path [{app_id} -> {intermediate_parent} -> {lib_name} ({cve_id})]."
            
            # Ensure the bridging intermediary exists in the SBOM environment mapping
            if not any(d['library_name'] == intermediate_parent and d['app_id'] == app_id for d in sbom_dependencies):
                sbom_dependencies.append({
                    "app_id": app_id, "library_name": intermediate_parent, "version": "1.0.0",
                    "license": "MIT", "dependency_type": "direct", "last_updated": six_months_ago, "parent_library": app_id
                })
                dependency_labels.append({
                    "app_id": app_id, "library_name": intermediate_parent, "version": "1.0.0",
                    "risk_status": "Clean", "risk_type": "None", "severity": "Low", "explanation": "Direct gateway package."
                })
        
        # Save records
        sbom_dependencies.append({
            "app_id": app_id,
            "library_name": lib_name,
            "version": version,
            "license": license_type,
            "dependency_type": dep_type,
            "last_updated": last_updated,
            "parent_library": parent
        })
        
        dependency_labels.append({
            "app_id": app_id,
            "library_name": lib_name,
            "version": version,
            "risk_status": status,
            "risk_type": r_type,
            "severity": r_sev,
            "explanation": expl
        })
        
        row_index += 1

# Slice/adjust array instances cleanly to cap at exactly 500 rows if padding operations occurred
sbom_dependencies = sbom_dependencies[:500]
dependency_labels = dependency_labels[:500]

# -------------------------------------------------------------------------
# 4. Save CSV Output Files
# -------------------------------------------------------------------------
with open('sample_data/sbom_dependencies.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=["app_id", "library_name", "version", "license", "dependency_type", "last_updated", "parent_library"])
    writer.writeheader()
    writer.writerows(sbom_dependencies)

with open('sample_data/vulnerability_db.json', 'w') as f:
    json.dump(vulnerability_db[:200], f, indent=4) # Clean truncate to 200 items match

with open('sample_data/dependency_labels.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=["app_id", "library_name", "version", "risk_status", "risk_type", "severity", "explanation"])
    writer.writeheader()
    writer.writerows(dependency_labels)

print("✅ Data successfully saved inside the `sample_data/` folder!")
print(f"Total SBOM Lines Generated: {len(sbom_dependencies)}")
print(f"Total Labels Generated: {len(dependency_labels)}")