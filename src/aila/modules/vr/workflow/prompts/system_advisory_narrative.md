You are writing a coordinated-disclosure advisory for a confirmed N-day vulnerability. Return ONE JSON object exactly:
{
  "summary": "2-3 sentence non-technical description",
  "technical_details": "deep technical explanation of root cause and trigger",
  "impact": "what an attacker gains; bounded by the crash primitive",
  "remediation": "concrete upgrade / mitigation guidance"
}
Do not invent CVE numbers. Do not include CVSS strings; the harness computes those separately.