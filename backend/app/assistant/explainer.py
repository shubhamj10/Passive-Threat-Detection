"""Optional AI explainer for FINISHED alerts. Never on the detection path.

Sends only a redacted summary (pseudonymised IPs, no payloads, no raw traffic,
no domain names). Without Azure OpenAI settings, uses an offline template.
This is the ONLY package allowed to make outbound network connections.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets

_SALT = secrets.token_bytes(16)   # per process: pseudonyms cannot be reversed or linked across runs
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

CLASS_TEXT = {
    "ddos": "a denial-of-service flood against one internal destination",
    "botnet_c2_beaconing": "regular 'check-in' connections from an internal host to one external server, "
                           "a pattern typical of malware talking to its command-and-control server",
    "dga_domain": "an internal host looking up many random-looking domain names, typical of malware "
                  "using a domain generation algorithm (DGA) to find its controller",
    "dns_tunnelling": "an internal host sending many long, random DNS names under one domain, which can be "
                      "used to smuggle data out over DNS",
}


def pseudonymise(text: str) -> str:
    def rep(m):
        h = hmac.new(_SALT, m.group(0).encode(), hashlib.sha256).hexdigest()[:6]
        return f"host-{h}"
    return _IP.sub(rep, text)


def redact(alert: dict) -> dict:
    ev = alert["evidence"]
    return {
        "threat_class": alert["threat_class"], "attack_subtype": alert.get("attack_subtype"),
        "severity": alert["severity"], "confidence": alert["confidence"],
        "entity": pseudonymise(alert["entity"]).split("->")[0] if alert["threat_class"] in ("dga_domain", "dns_tunnelling")
        else pseudonymise(alert["entity"]),
        "features": {k: round(v, 4) for k, v in ev["features"].items()},
        "thresholds": ev["thresholds"], "gates_passed": ev["gates_passed"],
        "top_features": ev["top_shap_features"], "mitre_attack": alert["mitre_attack"],
        "detector_trust_score": alert["trace"].get("detector_trust_score"),
    }


def _secs(iso_s: str) -> float:
    from datetime import datetime
    return datetime.fromisoformat(iso_s.replace("Z", "+00:00")).timestamp()


def template_explanation(alert: dict) -> str:
    r = redact(alert)
    f = r["features"]
    what = CLASS_TEXT.get(r["threat_class"], r["threat_class"])
    top = ", ".join(r["top_features"])
    lines = [f"The {alert['model']['name']} model flagged {what} with {r['confidence']:.0%} confidence "
             f"({r['severity']} severity)."]
    if r["threat_class"] == "ddos":
        w = alert["trace"]["data_window"]
        secs = int(_secs(w["end"]) - _secs(w["start"]))
        lines.append(f"In a single {secs}-second window it saw "
                     f"{int(f['flows'])} flows from {int(f['unique_src'])} sources "
                     f"({f['pkts_per_s']:.0f} packets/s); subtype: {r['attack_subtype']}.")
    elif r["threat_class"] == "botnet_c2_beaconing":
        lines.append(f"{int(f['events'])} connections about every {f['interval_mean']:.0f} s with very little "
                     f"variation (interval CV {f['interval_cv']:.3f}) and near-identical sizes (size CV {f['size_cv']:.3f}).")
    elif r["threat_class"] == "dga_domain":
        lines.append(f"Names scored as unlike normal domains (bigram score {f['sld_bigram_ll']:.2f}), "
                     f"with {f['nx_ratio']:.0%} of lookups failing (NXDOMAIN).")
    else:
        lines.append(f"{int(f['n_queries'])} queries in a minute, labels up to {int(f['max_label_len'])} "
                     f"characters, {f['txt_ratio']:.0%} TXT/NULL record requests.")
    lines.append(f"The features that pushed the score most were: {top}. "
                 f"Gates passed: {', '.join(r['gates_passed'])}.")
    if r["detector_trust_score"] is not None and r["detector_trust_score"] < 70:
        lines.append(f"Caution: this detector's trust score is {r['detector_trust_score']}, so verify manually.")
    lines.append("This system only informs; an analyst decides any action.")
    return " ".join(lines)


def azure_configured() -> bool:
    return all(os.environ.get(k) for k in ("AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_API_KEY",
                                           "AZURE_OPENAI_DEPLOYMENT", "AZURE_OPENAI_API_VERSION"))


def explain(alert: dict) -> dict:
    if azure_configured():
        try:
            from openai import AzureOpenAI  # type: ignore  (optional dependency)
            client = AzureOpenAI(azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
                                 api_key=os.environ["AZURE_OPENAI_API_KEY"],
                                 api_version=os.environ["AZURE_OPENAI_API_VERSION"], timeout=20)
            msg = client.chat.completions.create(
                model=os.environ["AZURE_OPENAI_DEPLOYMENT"], max_tokens=300, temperature=0.2,
                messages=[{"role": "system", "content": (
                    "You explain network security alerts to SOC analysts in plain English, in 4 sentences or fewer. "
                    "Explain what the evidence shows and what an analyst should check. Do not invent facts. "
                    "Never recommend automated blocking: humans decide actions.")},
                    {"role": "user", "content": f"Redacted alert: {redact(alert)}"}])
            return {"source": "azure_openai", "text": msg.choices[0].message.content.strip()}
        except Exception as e:  # fall back, never fail the analyst
            return {"source": "offline_template", "text": template_explanation(alert),
                    "note": f"Azure OpenAI unavailable ({type(e).__name__}); used offline explanation"}
    return {"source": "offline_template", "text": template_explanation(alert)}
