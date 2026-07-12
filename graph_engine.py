import networkx as nx
import json
import pandas as pd

class DependencyGraphEngine:
    def __init__(self):
        self.G = nx.DiGraph()
        self.vuln_db = {}
        self.lib_to_app_map = {}

    def load_all_data(self, apps_json, sbom_csv, vuln_json, transitive_json='sample_data/transitive_dependencies.json'):
        try:
            with open(vuln_json, 'r') as f:
                vulns = json.load(f)
                self.vuln_db = {v['library']: v for v in vulns}

            # Map libraries to application IDs to identify the entry points of an application
            df_deps = pd.read_csv(sbom_csv)
            for _, row in df_deps.iterrows():
                app_id = str(row['application_id']).strip()
                lib_name = str(row['library']).strip()
                
                if app_id not in self.lib_to_app_map:
                    self.lib_to_app_map[app_id] = set()
                self.lib_to_app_map[app_id].add(lib_name)

            # Map the true parent-child links from transitive_dependencies.json
            with open(transitive_json, 'r') as f:
                transitive_data = json.load(f)

            self.G.clear()
            for edge in transitive_data:
                parent = str(edge['parent_library']).strip()
                child = str(edge['child_library']).strip()
                self.G.add_edge(parent, child)
                
            print("🌲 NetworkX Graph constructed successfully!")
        except Exception as e:
            print(f"❌ Graph Construction Error: {str(e)}")

    def trace_transitive_vulnerabilities(self, target_app_id):
        paths_discovered = []
        target_app_id = str(target_app_id).strip()
        app_libraries = self.lib_to_app_map.get(target_app_id, set())
        
        # OPTIMIZATION: Only evaluate nodes in our graph that actually have a matching CVE
        vulnerable_libs_in_graph = [node for node in self.G.nodes if node in self.vuln_db]
        
        for lib_node in vulnerable_libs_in_graph:
            vuln = self.vuln_db[lib_node]
            
            # Check if any entrypoint library of this app reaches the vulnerable library node
            for start_lib in app_libraries:
                if start_lib in self.G and nx.has_path(self.G, start_lib, lib_node):
                    path_chain = nx.shortest_path(self.G, start_lib, lib_node)
                    
                    paths_discovered.append({
                        "cve_id": vuln['cve_id'],
                        "cvss_score": vuln['cvss_score'],
                        "dependency_depth": len(path_chain),
                        "attack_path": f"{target_app_id} -> " + " -> ".join(path_chain)
                    })
        return paths_discovered