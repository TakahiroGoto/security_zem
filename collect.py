#!/usr/bin/env python3
"""Daily AI security vulnerability collector.

Sources: NVD, GitHub Advisory, Hacker News, RSS feeds
Output: data/YYYY-MM-DD.json, data/latest.json, updated index.html
"""

import hashlib
import json
import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import feedparser
import requests

JST = timezone(timedelta(hours=9))
TODAY = datetime.now(JST).strftime("%Y-%m-%d")
DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

KEYWORDS = [
    "LiteLLM", "LangChain", "OpenAI", "Anthropic", "AutoGPT",
    "CrewAI", "Ollama", "llama.cpp", "vLLM", "HuggingFace",
    "LlamaIndex", "Langsmith", "ComfyUI", "LocalAI", "Dify",
    "Flowise", "n8n AI", "Bedrock", "Vertex AI",
]

AI_TERMS = {
    "litellm", "langchain", "openai", "anthropic", "autogpt",
    "crewai", "ollama", "llama", "vllm", "huggingface",
    "llamaindex", "langsmith", "comfyui", "localai", "dify",
    "flowise", "bedrock", "vertex ai",
    "llm", "large language model", "generative ai", "ai agent",
    "prompt injection", "rag", "vector db", "embedding model",
    "chatgpt", "claude", "gemini", "mistral", "gpt-",
    "model poisoning", "jailbreak", "ai security",
}

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
SEV_STYLE = {
    "CRITICAL": ("#f43f5e", "rgba(244,63,94,0.12)"),
    "HIGH":     ("#f59e0b", "rgba(245,158,11,0.12)"),
    "MEDIUM":   ("#00d4ff", "rgba(0,212,255,0.10)"),
    "LOW":      ("#10b981", "rgba(16,185,129,0.10)"),
    "INFO":     ("#64748b", "rgba(100,116,139,0.10)"),
    "UNKNOWN":  ("#64748b", "rgba(100,116,139,0.10)"),
}


# ── helpers ──────────────────────────────────────────────────────────────────

def make_id(item: dict) -> str:
    key = item.get("cve_id") or item.get("url") or item.get("title", "")
    return hashlib.md5(key.encode()).hexdigest()[:16]


def is_ai_related(text: str) -> bool:
    t = text.lower()
    return any(term in t for term in AI_TERMS)


def strip_html(s: str) -> str:
    return re.sub(r"<[^>]+>", "", s)


# ── collectors ────────────────────────────────────────────────────────────────

def fetch_nvd() -> list[dict]:
    items: list[dict] = []
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    start = (datetime.now(JST) - timedelta(days=7)).strftime("%Y-%m-%dT00:00:00.000")
    end = datetime.now(JST).strftime("%Y-%m-%dT23:59:59.999")
    seen: set[str] = set()

    for kw in KEYWORDS[:12]:
        try:
            r = requests.get(
                base,
                params={"keywordSearch": kw, "pubStartDate": start, "pubEndDate": end, "resultsPerPage": 10},
                timeout=20,
                headers={"User-Agent": "AI-SEC-INTEL/1.0"},
            )
            if r.status_code != 200:
                time.sleep(6)
                continue
            for vuln in r.json().get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cid = cve.get("id", "")
                if cid in seen:
                    continue
                seen.add(cid)
                desc = next(
                    (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
                )
                severity, score = "UNKNOWN", None
                for mk in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    ms = cve.get("metrics", {}).get(mk, [])
                    if ms:
                        severity = ms[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                        score = ms[0].get("cvssData", {}).get("baseScore")
                        break
                items.append({
                    "source": "NVD",
                    "cve_id": cid,
                    "title": cid,
                    "description": desc[:300],
                    "severity": severity,
                    "score": score,
                    "keyword": kw,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
                    "published": cve.get("published", "")[:10],
                })
            time.sleep(6)
        except Exception as e:
            print(f"[NVD] {kw}: {e}")
            time.sleep(6)
    return items


def fetch_github_advisories() -> list[dict]:
    items: list[dict] = []
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token := os.getenv("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"

    for eco in ["pip", "npm"]:
        try:
            r = requests.get(
                "https://api.github.com/advisories",
                params={"ecosystem": eco, "per_page": 50, "sort": "updated", "direction": "desc"},
                headers=headers,
                timeout=20,
            )
            if r.status_code != 200:
                continue
            for adv in r.json():
                summary = adv.get("summary", "")
                desc = adv.get("description", "")
                pkgs = " ".join(
                    v.get("package", {}).get("name", "") for v in adv.get("vulnerabilities", [])
                )
                if not is_ai_related(summary + " " + desc + " " + pkgs):
                    continue
                sev = adv.get("severity", "unknown").upper()
                cvss = adv.get("cvss") or {}
                items.append({
                    "source": "GitHub Advisory",
                    "cve_id": adv.get("cve_id") or adv.get("ghsa_id", ""),
                    "title": summary[:120],
                    "description": strip_html(desc)[:300],
                    "severity": sev,
                    "score": cvss.get("score"),
                    "url": adv.get("html_url", ""),
                    "published": (adv.get("published_at") or "")[:10],
                })
        except Exception as e:
            print(f"[GitHub Advisory] {eco}: {e}")
    return items


def fetch_hackernews() -> list[dict]:
    items: list[dict] = []
    cutoff = int((datetime.now() - timedelta(days=3)).timestamp())
    for query in ["AI LLM vulnerability", "prompt injection", "LangChain security CVE"]:
        try:
            r = requests.get(
                "https://hn.algolia.com/api/v1/search",
                params={
                    "query": query, "tags": "story", "hitsPerPage": 10,
                    "numericFilters": f"created_at_i>{cutoff}",
                },
                timeout=15,
            )
            if r.status_code != 200:
                continue
            for hit in r.json().get("hits", []):
                title = hit.get("title", "")
                if not is_ai_related(title + " " + (hit.get("url") or "")):
                    continue
                url = hit.get("url") or f"https://news.ycombinator.com/item?id={hit.get('objectID')}"
                items.append({
                    "source": "Hacker News",
                    "cve_id": "",
                    "title": title,
                    "description": f"▲{hit.get('points', 0)} points / {hit.get('num_comments', 0)} comments",
                    "severity": "INFO",
                    "score": None,
                    "url": url,
                    "published": datetime.fromtimestamp(hit.get("created_at_i", 0)).strftime("%Y-%m-%d"),
                })
        except Exception as e:
            print(f"[HN] {e}")
    return items


def fetch_rss() -> list[dict]:
    feeds = [
        ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
        ("Bleeping Computer", "https://www.bleepingcomputer.com/feed/"),
        ("JPCERT/CC",        "https://www.jpcert.or.jp/rss/jpcert.rdf"),
        ("Dark Reading",     "https://www.darkreading.com/rss.xml"),
    ]
    items: list[dict] = []
    cutoff = (datetime.now() - timedelta(days=3)).strftime("%Y-%m-%d")
    for source, url in feeds:
        try:
            feed = feedparser.parse(url)
            for entry in feed.entries[:30]:
                title = entry.get("title", "")
                summary = strip_html(entry.get("summary", ""))
                if not is_ai_related(title + " " + summary):
                    continue
                pub = entry.get("published_parsed")
                pub_str = datetime(*pub[:6]).strftime("%Y-%m-%d") if pub else TODAY
                if pub_str < cutoff:
                    continue
                items.append({
                    "source": source,
                    "cve_id": "",
                    "title": title,
                    "description": summary[:300],
                    "severity": "INFO",
                    "score": None,
                    "url": entry.get("link", ""),
                    "published": pub_str,
                })
        except Exception as e:
            print(f"[RSS] {source}: {e}")
    return items


# ── pipeline ──────────────────────────────────────────────────────────────────

def collect_all() -> list[dict]:
    print("[*] NVD ...")
    nvd = fetch_nvd()
    print(f"    {len(nvd)} items")

    print("[*] GitHub Advisories ...")
    gh = fetch_github_advisories()
    print(f"    {len(gh)} items")

    print("[*] Hacker News ...")
    hn = fetch_hackernews()
    print(f"    {len(hn)} items")

    print("[*] RSS ...")
    rss = fetch_rss()
    print(f"    {len(rss)} items")

    seen: dict[str, dict] = {}
    for item in nvd + gh + hn + rss:
        iid = make_id(item)
        if iid not in seen:
            item["id"] = iid
            seen[iid] = item
    return list(seen.values())


def load_prev_ids() -> set[str]:
    prev = DATA_DIR / "latest.json"
    if not prev.exists():
        return set()
    with open(prev, encoding="utf-8") as f:
        data = json.load(f)
    return {i.get("id", make_id(i)) for i in data.get("items", [])}


def save_data(items: list[dict], diff: list[dict]) -> None:
    with open(DATA_DIR / "latest.json", "w", encoding="utf-8") as f:
        json.dump({"date": TODAY, "items": items}, f, ensure_ascii=False, indent=2)
    with open(DATA_DIR / f"{TODAY}.json", "w", encoding="utf-8") as f:
        json.dump({"date": TODAY, "items": items, "diff": diff}, f, ensure_ascii=False, indent=2)
    print(f"[+] Saved {len(items)} total, {len(diff)} new")


# ── HTML generation ───────────────────────────────────────────────────────────

def _sev_key(item: dict) -> int:
    s = item.get("severity", "UNKNOWN")
    return SEV_ORDER.index(s) if s in SEV_ORDER else len(SEV_ORDER)


def render_diff_html(diff: list[dict]) -> str:
    if not diff:
        return f'<div class="diff-empty">本日 ({TODAY}) の新規情報はありません。</div>'

    rows = []
    for item in sorted(diff, key=_sev_key):
        sev = item.get("severity", "UNKNOWN")
        color, bg = SEV_STYLE.get(sev, SEV_STYLE["UNKNOWN"])
        score_str = f" ({item['score']})" if item.get("score") else ""
        cve_badge = (
            f'<span class="diff-cve">{item["cve_id"]}</span>' if item.get("cve_id") else ""
        )
        title = item.get("title", "").replace("<", "&lt;").replace(">", "&gt;")
        desc = item.get("description", "").replace("<", "&lt;").replace(">", "&gt;")[:200]
        url = item.get("url", "#")
        rows.append(
            f'    <div class="diff-row">'
            f'<span class="diff-sev" style="color:{color};background:{bg};">{sev}{score_str}</span>'
            f'<span class="diff-source">{item["source"]}</span>'
            f'<div class="diff-body">'
            f'<a href="{url}" target="_blank" rel="noopener" class="diff-title">{title}</a>'
            f'{cve_badge}'
            f'<p class="diff-desc">{desc}</p>'
            f'</div>'
            f'<span class="diff-date">{item.get("published", "")}</span>'
            f'</div>'
        )
    return "\n".join(rows)


def update_html(diff: list[dict]) -> None:
    html_path = Path("index.html")
    if not html_path.exists():
        print("[!] index.html not found")
        return

    content = html_path.read_text(encoding="utf-8")
    start_tag = "<!-- DAILY_DIFF_START -->"
    end_tag = "<!-- DAILY_DIFF_END -->"

    block = (
        f"{start_tag}\n"
        f'  <section style="padding-bottom:0;">\n'
        f'    <div class="diff-section">\n'
        f'      <div class="section-label">// DAILY UPDATE — {TODAY}</div>\n'
        f'      <h2 class="section-title">本日の新着情報'
        f'<span class="diff-count">{len(diff)}</span></h2>\n'
        f'      <p class="section-desc">前日との差分のみ表示 — NVD / GitHub Advisory / Hacker News / RSS</p>\n'
        f'      <div class="diff-list">\n'
        f'{render_diff_html(diff)}\n'
        f'      </div>\n'
        f'    </div>\n'
        f'  </section>\n'
        f"{end_tag}"
    )

    pattern = re.compile(re.escape(start_tag) + r".*?" + re.escape(end_tag), re.DOTALL)
    if pattern.search(content):
        content = pattern.sub(block, content)
    else:
        content = content.replace(start_tag + end_tag, block)

    html_path.write_text(content, encoding="utf-8")
    print("[+] index.html updated")


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print(f"=== AI SEC INTEL Daily Collector — {TODAY} ===")
    prev_ids = load_prev_ids()
    print(f"[*] Previous known IDs: {len(prev_ids)}")
    items = collect_all()
    diff = [i for i in items if i.get("id") not in prev_ids]
    print(f"[+] New today: {len(diff)}")
    save_data(items, diff)
    update_html(diff)
    print("=== Done ===")


if __name__ == "__main__":
    main()
