# Societe Generale | Software Supply Chain Security Hub
Continuous Integration Gates, Deep Transitive Dependency Graph Traversal and Autonomous ML Diagnostics.

---

## Description
This enterprise-grade DevSecOps guardrail dashboard is engineered to systematically protect complex software ecosystems from supply chain injections, hidden transitive vulnerabilities, and licensing compliance conflicts. Built specifically for high-assurance enterprise environments, it automates the auditing of Software Bills of Materials (SBOMs), tracks deep multi-hop dependency risk chains, and evaluates live operational logs to prevent compromised open-source packages from introducing security vectors into staging clusters.

The platform resolves real-world dependency management challenges by replacing manual, reactive package inspection with autonomous background intelligence. It leverages NetworkX directed graphs to isolate nested risk paths, natural language processing (TF-IDF vector text mapping) to proactively flag unclassified zero-day alignments, and a supervised Random Forest model to classify runtime telemetry logs. Additionally, compiler-level Abstract Syntax Tree (AST) static parsing crawls application source files to analyze method exploitability patterns, enabling security engineers to distinguish between the simple presence of a library and an active vulnerable code execution path.

---


## Prerequisites / Requirements
Before installing and executing the orchestration hub, ensure your target development environment meets the following baseline parameters:
* Runtime Environment: Python 3.9 or higher installed on the system path.
* Core Machine Learning Libraries: scikit-learn (minimum version 1.0) for execution of clustering models and text vectorizations.
* Data Processing and Graphing: pandas, numpy, and networkx for structural data manipulation and directed graph tree path resolutions.
* Visual Layer Elements: streamlit and plotly for application container layouts and interactive scatter plots.
* Operating System Support: Linux, macOS, or Windows 10/11 with terminal accessibility.

---

## Installation Guide
Execute the following commands sequentially in your terminal infrastructure to clone the repository assets, configure the system directory, and download all mandatory dependency packages:

```bash
# Clone the enterprise source repository from the version control engine
git clone https://github.com/hariragavan-tech/Duo_hack_societyGenerale

# Navigate into the initialized software core directory
cd Duo_hack_societyGenerale

# Install the required data processing, visualization, and machine learning dependencies
pip install streamlit pandas numpy scikit-learn plotly networkx

```

---

## Usage / Quick Start

The system supports both real-time interface operations and offline command-line continuous integration gate validations.

### 1. Launching the Interactive Enterprise Dashboard

The application evaluates the ecosystem natively and contains a dynamic LLM Playbook generator fallback architecture that operates cleanly without any setup requirements. To activate the high-fidelity live text summary narration generation during review, you can supply your credentials directly into the terminal shell immediately before running the execution commands:

```bash

$env:GROQ_API_KEY="GROQ_API_KEY" (not mandatory)

```

To initialize the dark-mode analytical security hub and visualize structural risk tabs, run the following command to spin up the local hosting engine:

```bash
streamlit run app.py

```

Once initialized, launch your web browser and navigate to the local network port address output by the engine (typically mapping to http://localhost:8501).

### 2. Executing the Headless CI/CD Deployment Gate

To simulate an automated build pipeline validator that parses files, evaluates security baselines, and returns strict exit status codes, trigger the pipeline wrapper natively:

```bash
python pipeline.py

```
The application evaluates the ecosystem natively and contains a dynamic LLM Playbook generator fallback architecture that operates cleanly without any setup requirements. To activate the high-fidelity live text summary narration generation during review, you can supply your credentials directly into the terminal shell immediately before running the execution commands:


This automated gate prints out telemetry logs, pushes event files to `enterprise_risk_report.json`, and returns a hard exit code status (`sys.exit(1)`) if computed risks exceed the pre-configured corporate safety threshold, successfully blocking vulnerable code pushes from entering production clusters.

---

## License

Distributed under the Apache License 2.0. For more information regarding explicit permissions, compliance constraints, and legal liabilities, please refer directly to the dedicated LICENSE file hosted within the root directory of this repository.
