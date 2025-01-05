import os
import time
import re
import json
import subprocess
import streamlit as st
import nmap
# LangChain imports
from langchain.chat_models import ChatOpenAI
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate

# Logo & heading
LOGO_URL = "https://asset-group.github.io/img/sample-logo-test-2.png"

# In this code, we define ICS KEYWORDS so we can label them ICS or IT
ICS_KEYWORDS = [
    "modbus", "dnp3", "bacnet", "s7", "siemens", 
    "enip", "fox", "omron", "rockwell", "ethernet/ip"
]

# ---------------------------
# STREAMLIT PAGE SETUP
# ---------------------------
st.set_page_config(page_title="CyberBoT", layout="wide")

st.markdown(
    f"""
    <div style='display: flex; align-items: center;'>
        <img src="{LOGO_URL}" width="80" style='margin-right: 20px'>
        <h3 style='margin-bottom: 0px;'>SUTD ASSET Research Group</h3>
    </div>
    """,
    unsafe_allow_html=True
)

st.title("Generative AI-Powered Cybersecurity Vulnerability Research Assistant")

# ---------------------------
# LangChain Setup
# ---------------------------
# We'll use ChatOpenAI for GPT-4 or GPT-3.5
# Adjust model_name as needed (e.g., "gpt-3.5-turbo")
openai_api_key = os.getenv("OPENAI_API_KEY", "")
llm = ChatOpenAI(
    openai_api_key=openai_api_key,
    model_name="gpt-4",
    temperature=0.7
)

# 1. ICS Scripts Check
def ics_scripts_available():
    scripts_needed = [
        "modbus-discover.nse",
        "fox-info.nse",
        "dnp3-info.nse",
        "bacnet-info.nse",
        "s7-info.nse",
        "enip-info.nse"
    ]
    potential_paths = [
        "/usr/share/nmap/scripts",
        "/usr/local/share/nmap/scripts",
        "/Program Files (x86)/Nmap/scripts",  # Windows example
        "/Program Files/Nmap/scripts"
    ]
    missing = []
    for script_name in scripts_needed:
        found = False
        for folder in potential_paths:
            path = os.path.join(folder, script_name)
            if os.path.isfile(path):
                found = True
                break
        if not found:
            missing.append(script_name)
    return (False, missing) if missing else (True, [])

# 2. Quick OT Port Scan
def run_quick_ot_port_scan(target_ip):
    nm = nmap.PortScanner()
    ics_ports = "80,8080,102,161,1025,3389,502,20000,47808,44818,9600,1962,50100"  # common ICS ports
    base_args = f"-sC -sV -p{ics_ports}"

    start_time = time.time()
    with st.spinner("Running Quick OT Port Scan..."):
        nm.scan(hosts=target_ip, arguments=base_args)
    end_time = time.time()

    st.write(f"Quick OT Port Scan completed in **{(end_time - start_time):.2f} seconds**.")
    return nm.csv()

# 3. ICS Script Scan
def run_ics_script_scan(target_ip):
    nm = nmap.PortScanner()
    ics_scripts = "modbus-discover,fox-info,dnp3-info,bacnet-info,s7-info,enip-info"
    base_args = f"-sV --script={ics_scripts}"

    start_time = time.time()
    with st.spinner("Running ICS Script Scan..."):
        nm.scan(hosts=target_ip, arguments=base_args)
    end_time = time.time()

    st.write(f"ICS Script Scan completed in **{(end_time - start_time):.2f} seconds**.")
    return nm.csv()

# 4. Parse Nmap CSV only for open ports
def parse_nmap_csv_only_open(nmap_csv):
    results = []
    lines = nmap_csv.strip().splitlines()
    if len(lines) <= 1:
        return results
    for line in lines[1:]:
        parts = line.split(";")
        if len(parts) < 7:
            continue
        state = parts[6].lower()  # open, closed, filtered, etc.
        if state not in ["open", "open|filtered"]:
            continue
        port = parts[4]
        service_name = (parts[5] or "").lower()
        product = (parts[7] or "").lower()
        version = (parts[10] or "").lower()  # typically in part[10]
        combined = f"{service_name} {product} {version}"
        is_ics = any(keyword in combined for keyword in ICS_KEYWORDS)
        results.append((port, service_name, version, is_ics))
    return results

# 5. ExploitDB
def search_exploitdb(service_name, version):
    try:
        result = subprocess.check_output(["searchsploit", f"{service_name} {version}"], text=True)
        return result if result else "No exploits found."
    except subprocess.CalledProcessError:
        return "No exploits found."
    except Exception as e:
        return f"Error querying ExploitDB: {str(e)}"

# 6. Regex CVE
def extract_cves_from_text(text):
    cve_pattern = r"(CVE-\d{4}-\d+)"
    cves = re.findall(cve_pattern, text, re.IGNORECASE)
    return list(set(cves))

# 7. LangChain LLMChain for GPT Analysis
#    We incorporate a "chain of thought" style instruction, 
#    asking GPT to reason step-by-step in a hidden chain-of-thought (CoT).
analysis_prompt_template = """
You are a cybersecurity research expert focusing on both IT and ICS/OT vulnerabilities.
Scan results:
{scan_data}

Goal: 
1) Identify possible vulnerabilities for each discovered open port/service (IT or ICS).
2) Consider lateral movement from IT to OT.
3) Summarize in JSON with fields: 
   "summary": <text summary>,
   "potential_vulnerabilities": [
       {{"service_type": "IT" or "OT", "service": <string>, "version": <string>,
         "issue": <string>, "recommendation": <string>}}
   ]

Use concise, factual explanations. 
Do not include vulnerabilities for non-open services.

Think carefully step-by-step (chain-of-thought) but provide only the final short answer in JSON format. Suggest how these vulnerabilities can be exploited and mention past incident reference, if any.
"""

analysis_prompt = PromptTemplate(
    input_variables=["scan_data"],
    template=analysis_prompt_template
)
analysis_chain = LLMChain(prompt=analysis_prompt, llm=llm)

# ---------------------------
# STREAMLIT WORKFLOW
# ---------------------------
target_ip = st.text_input("Enter target IP:", "10.10.10.1")

if st.button("Run ASSeT GenAI BoT"):

    # A. Check ICS scripts
    are_scripts, missing_scripts = ics_scripts_available()
    if not are_scripts:
        st.warning(f"Missing ICS scripts: {', '.join(missing_scripts)}")
        st.info("ICS scanning may be skipped or fail until these scripts are installed.")

    # B. Quick OT Scan
    st.subheader("Step 1: Quick ICS/OT Port Scan")
    quick_csv = run_quick_ot_port_scan(target_ip)
    st.text("Quick OT Scan Results:\n" + quick_csv)
    parsed_quick = parse_nmap_csv_only_open(quick_csv)
    found_ics = any(item[3] for item in parsed_quick)

    # C. Optional ICS Script Scan
    final_csv = quick_csv
    if found_ics and are_scripts:
        st.warning("ICS protocols found in Quick Scan. Optionally run ICS scripts.")
        if st.checkbox("Perform ICS Script Scan"):
            ics_csv = run_ics_script_scan(target_ip)
            st.text("ICS Script Scan Results:\n" + ics_csv)
            final_csv = ics_csv
    else:
        if not found_ics:
            st.success("No ICS/SCADA protocols discovered.")
        if not are_scripts:
            st.info("Skipping ICS script scan (scripts missing).")

    # D. GPT Analysis via LangChain
    st.subheader("Step 2: GPT Analysis")
    with st.spinner("Analyzing with chain-of-thought prompt..."):
        # We supply final_csv to the chain
        chain_result = analysis_chain.run(scan_data=final_csv)

    # Attempt JSON parse
    try:
        chain_parsed = json.loads(chain_result)
        is_error = False
    except json.JSONDecodeError:
        chain_parsed = {"error": "Invalid JSON", "raw_text": chain_result}
        is_error = True

    # E. Display GPT Analysis
    if not is_error:
        st.subheader("Analysis Summary")
        st.write(chain_parsed.get("summary", "No summary."))

        st.subheader("Potential Vulnerabilities")
        vulns = chain_parsed.get("potential_vulnerabilities", [])
        if vulns:
            for v in vulns:
                service_type = v.get("service_type", "Unknown").upper()
                service = v.get("service", "unknown")
                version = v.get("version", "")
                issue = v.get("issue", "")
                recommendation = v.get("recommendation", "")
                st.markdown(f"- **Service Type:** {service_type}")
                st.markdown(f"  **Service:** {service} (version: {version})")
                st.markdown(f"  **Issue:** {issue}")
                st.markdown(f"  **Recommendation:** {recommendation}")
                st.write("---")
        else:
            st.info("No vulnerabilities identified or none returned in structured format.")
    else:
        st.subheader("GPT Analysis (Raw Text)")
        st.warning(chain_parsed["error"])
        st.write(chain_parsed["raw_text"])

    # F. Extract CVEs
    st.subheader("Step 3: Extracting CVEs from Analysis")
    raw_text = json.dumps(chain_parsed) if not is_error else chain_parsed["raw_text"]
    cves_found = extract_cves_from_text(raw_text)
    if cves_found:
        st.write("CVEs Found:")
        for cve in cves_found:
            st.write(f"- {cve}")
    else:
        st.info("No CVEs identified in analysis text.")

    # G. ExploitDB for Discovered Services
    st.subheader("Step 4: Searching ExploitDB for Discovered Services")
    final_parsed = parse_nmap_csv_only_open(final_csv)
    if not final_parsed:
        st.info("No open ports or services found in final scan.")
    else:
        for (port, srv_name, srv_ver, is_ics) in final_parsed:
            if srv_name or srv_ver:
                cat = "ICS" if is_ics else "IT"
                st.markdown(f"**({cat}) Searching ExploitDB for:** {srv_name} {srv_ver} (port {port})")
                exploits = search_exploitdb(srv_name, srv_ver)
                st.text(exploits)

    # H. Final Summary / Next Steps
    st.markdown("---")
    st.markdown("### Next Steps and Recommendations")
    st.write("""
    1. Validate both IT and ICS findings in a safe environment.
    2. If ICS protocols are detected (Modbus, DNP3, etc.), perform deeper testing.
    3. Consider lateral movement from IT services into OT networks.
    4. Check discovered CVEs on ICS-CERT, NVD, or vendor advisories.
    5. Use GPT-based suggestions as a starting point—always verify with official documentation.
    """)

st.markdown("---")
st.markdown("© 2025, SUTD ASSET Team - Generative AI-Powered Security Research Assistant")
