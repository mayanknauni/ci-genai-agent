# CyberBoT: Generative AI-Powered Cybersecurity Vulnerability Research Assistant

## Overview
CyberBoT is a Streamlit-based cybersecurity vulnerability research assistant powered by Generative AI (GPT-4) and LangChain. It assists cybersecurity researchers in identifying and analyzing both IT and ICS/OT vulnerabilities with the help of Nmap scans, CVE extraction, and ExploitDB searches.

## Features
- **Quick OT Port Scan:** Identifies commonly used ports in ICS/OT environments.
- **ICS Script Scan:** Uses Nmap's ICS-specific scripts to detect OT protocol vulnerabilities.
- **ExploitDB Integration:** Automatically searches for available exploits for detected services.
- **CVE Extraction:** Extracts CVE identifiers from scan results and GPT analysis.
- **GPT-Powered Analysis:** Uses LangChain with GPT-4 to analyze scan results and provide vulnerability insights.
- **ICS/OT Detection:** Identifies ICS-specific services for specialized vulnerability analysis.

## Technologies Used
- **Python 3.10+**
- **Streamlit** (Web UI)
- **LangChain**
- **OpenAI GPT API**
- **Nmap & NSE Scripts**
- **ExploitDB (searchsploit)**

## Flow Diagram
 ![image](https://github.com/user-attachments/assets/fdee3a44-6421-4437-9d85-cca669be9bdb)


## Setup Instructions
1. **Clone the Repository:**
   ```bash
   git clone https://github.com/username/CyberBoT.git
   cd CyberBoT
   ```
2. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
3. **Set OpenAI API Key:**
   ```bash
   export OPENAI_API_KEY=your-api-key-here
   ```
4. **Run the Application:**
   ```bash
   streamlit run app.py
   ```

## How to Use
1. **Enter Target IP:** Provide the IP address you want to scan.
2. **Quick OT Scan:** Perform a preliminary scan of common ICS/OT ports.
3. **ICS Script Scan (Optional):** Run a deeper scan if ICS protocols are detected.
4. **GPT Analysis:** Review the AI-generated security analysis report.
5. **ExploitDB Search:** Check for known exploits related to the discovered services.
6. **CVEs Extraction:** Automatically extract any mentioned CVEs from the analysis.

## Key Components
- **ICS Keywords:** List of protocol identifiers used for ICS detection.
- **Nmap Integration:** Predefined OT port scans and ICS-specific script scans.
- **LangChain Analysis:** Chain-of-thought reasoning for vulnerability assessment.
- **ExploitDB Integration:** Local `searchsploit` queries for vulnerability checks.

## Future Work
- **Integration with External Cyber Threat Intelligence (CTI) Sources:**
   - Incorporate feeds from sources such as MITRE ATT&CK, AlienVault OTX, and CISA advisories.
   - Real-time threat intelligence correlation with scan results.
   - Automate alerting for newly discovered vulnerabilities matching scan data.

## ICS Keywords
- Modbus, DNP3, BACnet, S7, Siemens, ENIP, Fox, Omron, Rockwell

## License
This project is licensed under the MIT License.

## Disclaimer
This tool is intended for educational and authorized testing purposes only. Unauthorized use against production systems may be illegal.

## Contribution
We welcome community contributions to improve CyberBoT. Feel free to submit pull requests or raise issues on the repository.

---
© 2025 SUTD ASSET Team - Generative AI-Powered Security Research Assistant
