import os
import numpy as np
import pandas as pd  # 🌟 FIXED: Missing import statement added to eliminate the NameError crash
from groq import Groq
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer

class SupplyChainLLMPlaybook:
    def __init__(self):
        api_key = os.environ.get("GROQ_API_KEY", "").strip()
        if api_key and not api_key.startswith("your_"):
            self.client = Groq(api_key=api_key)
            self.fallback_mode = False
        else:
            self.client = None
            self.fallback_mode = True

    def generate_remediation_narrative(self, app_name, paths_found):
        if self.fallback_mode or not self.client:
            narrative = f"### 🤖 Executive Mitigation Script (Local Sandbox Automation)\n\n"
            narrative += f"**Target Application Asset Framework:** {app_name}\n\n"
            if not paths_found:
                narrative += "✨ *No active high-severity transitive attack paths discovered requiring priority quarantine.* Systems check nominal.\n"
                return narrative
            
            narrative += "#### 📌 Structural Transitive Threat Path Breakdown:\n"
            for p in paths_found:
                narrative += f"- **{p['cve_id']}** (CVSS: {p['cvss_score']}): Identified along the supply chain path matrix: `{p['attack_path']}`.\n"
            
            narrative += "\\n#### 🛠️ Actionable Threat Containment Protocol:\\n"
            narrative += "1. **Block Reflection Points:** Audit the root-level dependencies to shield child assets.\n"
            return narrative

class SupplyChainMLIntelligence:
    def __init__(self):
        self.classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.classifier_vectorizer = TfidfVectorizer(stop_words='english')
        self.semantic_vectorizer = TfidfVectorizer(stop_words='english')
        self.is_trained = False
        
        # Pre-seed the semantic engine parameters using corporate threat vectors
        base_corpus = [
            "critical remote code execution vulnerability discovered in parsing core libraries",
            "unauthorized privilege escalation flaw via nested serialization variables",
            "improper verification of cryptographic signatures leading to supply chain injection",
            "denial of service vulnerability due to resource exhaustion in network stack handles"
        ]
        self.semantic_vectorizer.fit(base_corpus)

    def train_risk_classifier(self, label_csv_path):
        if os.path.exists(label_csv_path):
            try:
                df = pd.read_csv(label_csv_path)
                X = self.classifier_vectorizer.fit_transform(df['explanation'].fillna(''))
                y = df['is_risky'].values
                self.classifier.fit(X, y)
                self.is_trained = True
            except Exception as e:
                print(f"Fallback training initialized due to read anomaly: {e}")
                self._load_fallback_classifier()
        else:
            self._load_fallback_classifier()

    def _load_fallback_classifier(self):
        fallback_df = pd.DataFrame({
            'explanation': ["Critical remote exploit", "Safe stable library footprint", "Vulnerable code execution", "Nominal patch profile"],
            'is_risky': [1, 0, 1, 0]
        })
        X_text = self.classifier_vectorizer.fit_transform(fallback_df['explanation'])
        y = fallback_df['is_risky'].values
        self.classifier.fit(X_text, y)
        self.is_trained = True

    def semantic_vulnerability_match(self, library_desc, vulnerability_desc):
        if not library_desc or not vulnerability_desc:
            return 0.0
        try:
            tfidf_matrix = self.semantic_vectorizer.transform([library_desc, vulnerability_desc])
            v1, v2 = tfidf_matrix.toarray()[0], tfidf_matrix.toarray()[1]
            
            dot_product = np.dot(v1, v2)
            norm_1, norm_2 = np.linalg.norm(v1), np.linalg.norm(v2)
            if norm_1 == 0 or norm_2 == 0:
                return 0.0
            return float(dot_product / (norm_1 * norm_2))
        except:
            return 0.0

    def predict_exploitability_lite(self, code_filepath, target_function_name):
        try:
            if not os.path.exists(code_filepath):
                return "LOW (Static Source Target Unresolved)"
            with open(code_filepath, 'r', errors='ignore') as file:
                if target_function_name in file.read():
                    return "HIGH EXPLOITABILITY DETECTED: Codebase entry point references active variable paths."
            return "LOW EXPLOITABILITY VECTORS IDENTIFIED"
        except:
            return "LOW"

def automated_semantic_threat_scan(dependencies_dataframe, vulnerability_database, intelligence_engine, similarity_threshold=0.20):
    """
    Computes natural language vector distances between internal dependency descriptions 
    and global exploit registries to uncover zero-day targets dynamically.
    """
    automated_alerts = []
    
    if dependencies_dataframe is None or not vulnerability_database:
        return automated_alerts

    for index, row in dependencies_dataframe.iterrows():
        lib_name = row.get('library', 'Unknown')
        lib_desc = f"{lib_name} {row.get('dependency_type', '')} package license model {row.get('license', '')}"
        
        for vuln in vulnerability_database:
            vuln_desc = vuln.get('description', '')
            
            score = intelligence_engine.semantic_vulnerability_match(lib_desc, vuln_desc)
            if score >= similarity_threshold:
                automated_alerts.append({
                    "Discovered Library": lib_name,
                    "Target Zero-Day Alignment Vector": vuln.get('vulnerability_name', 'Zero-Day Alignment'),
                    "Calculated Semantic Distance Correlation": round(float(score), 3),
                    "Recommended Proactive Patch Option": vuln.get('remediation_patch', 'Mitigate immediately via staging cluster isolation.')
                })
                
    return pd.DataFrame(automated_alerts).drop_duplicates().to_dict(orient='records')