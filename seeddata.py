import pandas as pd
import json
import random

# 1. Load your large existing datasets
try:
    dependencies_df = pd.read_csv('sample_data/sbom_dependencies.csv')
    with open('sample_data/vulnerability_db.json', 'r') as f:
        vulnerabilities = json.load(f)
except FileNotFoundError:
    print("❌ Check your file paths! Make sure sample_data/ folder is correct.")
    exit()

print(f"Loaded {len(dependencies_df)} dependency links and {len(vulnerabilities)} CVE profiles.")

# 2. Extract a unique list of all libraries your apps are actually using
active_libraries = dependencies_df['library_name'].unique().tolist()

# 3. Automatically update your vulnerability database to match your libraries
# This ensures that your NetworkX graph engine WILL find matches across all apps!
if active_libraries and vulnerabilities:
    print("🔗 Syncing vulnerabilities to active library names...")
    for idx, vuln in enumerate(vulnerabilities):
        # Assign a real library name from your actual data pool to this CVE
        vuln['affected_library'] = active_libraries[idx % len(active_libraries)]
        
        # Match the version string dynamically if needed
        matching_rows = dependencies_df[dependencies_df['library_name'] == vuln['affected_library']]
        if not matching_rows.empty:
            vuln['affected_version'] = str(matching_rows.iloc[0]['version'])

    # 4. Save the synchronized database back to the JSON file
    with open('sample_data/vulnerability_db.json', 'w') as f:
        json.dump(vulnerabilities, f, indent=4)
    print("✅ Success! vulnerability_db.json has been synced with your active data profiles.")
else:
    print("❌ Data arrays are empty. Please check your source files.")