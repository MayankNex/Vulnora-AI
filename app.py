import json
import os

import streamlit as st
from dotenv import load_dotenv

from vulnora.scanner import ScanError, scan_website
from vulnora.explain import explain_findings

load_dotenv()
st.set_page_config(page_title="Vulnora AI", page_icon="🛡️", layout="wide")
st.title("🛡️ Vulnora AI")
st.caption("Understand your website's security posture — safely and in plain language.")

with st.sidebar:
    st.header("About this scan")
    st.write("Passive checks only. No exploitation, brute-force, crawling, or automatic changes.")
    st.warning("Scan only websites you own or have explicit permission to assess.")
    st.markdown("[GitHub repository](https://github.com/MayankNex/Vulnora-AI)")

url = st.text_input("Website URL", placeholder="https://example.com")
authorized = st.checkbox("I own this website or have explicit permission to assess it.")
run = st.button("Run safe scan", type="primary", disabled=not authorized or not url.strip())

if run:
    with st.spinner("Checking public security configuration..."):
        try:
            st.session_state["vulnora_report"] = scan_website(url.strip())
        except ScanError as exc:
            st.error(str(exc))
        except Exception:
            st.error("The scan could not be completed. Check the URL and try again.")

report = st.session_state.get("vulnora_report")
if report:
    st.divider()
    st.subheader("Scan summary")
    a, b, c = st.columns(3)
    a.metric("Findings", len(report["findings"]))
    b.metric("High", sum(x["severity"] == "High" for x in report["findings"]))
    c.metric("Medium", sum(x["severity"] == "Medium" for x in report["findings"]))
    st.caption(f"Requested: {report['requested_url']} · Final: {report['final_url']}")
    st.caption(f"HTTP status: {report['status_code']} · HTTPS: {'Yes' if report['https'] else 'No'}")

    for finding in report["findings"]:
        with st.expander(f"{finding['severity']} · {finding['title']}", expanded=True):
            st.write(finding["description"])
            st.markdown(f"**Evidence:** {finding['evidence']}")
            st.markdown(f"**Suggested fix:** {finding['remediation']}")

    if os.getenv("OPENAI_API_KEY"):
        if st.button("Explain findings with AI"):
            with st.spinner("Generating explanation..."):
                try:
                    st.session_state["vulnora_ai"] = explain_findings(report)
                except Exception:
                    st.warning("AI explanation is unavailable. Scan results are still available.")
        if st.session_state.get("vulnora_ai"):
            st.subheader("AI explanation")
            st.write(st.session_state["vulnora_ai"])

    st.download_button("Download JSON report", json.dumps(report, indent=2),
                       file_name="vulnora-report.json", mime="application/json")
    st.caption("Missing headers are configuration observations, not confirmed exploitable vulnerabilities.")
