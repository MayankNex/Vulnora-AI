"""Optional AI explanation layer."""
import json
import os
from openai import OpenAI


def explain_findings(report: dict) -> str:
    key = os.getenv("OPENAI_API_KEY")
    if not key:
        raise RuntimeError("OPENAI_API_KEY is not configured")
    client = OpenAI(api_key=key)
    safe_data = {"url": report.get("final_url"), "findings": report.get("findings", []), "limitations": report.get("limitations", [])}
    response = client.responses.create(
        model=os.getenv("OPENAI_MODEL", "gpt-4.1-mini"),
        instructions=("You are a defensive website security educator. Explain findings in simple language. Do not claim exploitability without evidence. Give safe remediation advice only."),
        input=json.dumps(safe_data),
    )
    return response.output_text
