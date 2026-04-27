#!/usr/bin/env python3
"""Fenrir research helper: fetch current vulnerability research from arXiv/Reddit.

Usage:
    python3 scripts/research.py --cron
    python3 scripts/research.py --topics "sql injection xss ssrf"
    python3 scripts/research.py --browser-fallback
"""

import json
import sys
import time
import urllib.request
from pathlib import Path

RESEARCH_DIR = Path.home() / ".fenrir" / "research"
SOURCES_DIR = RESEARCH_DIR / "sources"
ARXIV_DIR = SOURCES_DIR / "arxiv"


def ensure_dirs():
    """Create research directories."""
    for d in [RESEARCH_DIR, SOURCES_DIR, ARXIV_DIR]:
        d.mkdir(parents=True, exist_ok=True)


def fetch_arxiv(query: str = "LLM jailbreak vulnerability", limit: int = 5) -> list[dict]:
    """Fetch papers from arXiv API."""
    url = (
        f"http://export.arxiv.org/api/query?"
        f"search_query=all:%22{query}%22&max_results={limit}&sortBy=lastUpdatedDate"
    )

    req = urllib.request.Request(url)
    req.add_header("User-Agent", "FenrirProMax/0.1.0 (security research)")

    try:
        resp = urllib.request.urlopen(req, timeout=30)
        xml_data = resp.read().decode("utf-8", errors="ignore")

        # Parse XML manually (no external dependencies)
        papers = []
        entries = xml_data.split("<entry>")
        for entry in entries[1:]:  # Skip header
            title = ""
            summary = ""
            author = ""
            published = ""
            link = ""

            if "<title>" in entry:
                title = entry.split("<title>")[1].split("</title>")[0].strip()
            if "<summary>" in entry:
                summary = entry.split("<summary>")[1].split("</summary>")[0].strip()[:500]
            if "<author>" in entry:
                author = entry.split("<author>")[1].split("<name>")[1].split("</name>")[0].strip()
            if "<published>" in entry:
                published = entry.split("<published>")[1].split("</published>")[0]
            if '<link rel="alternate"' in entry:
                link = entry.split('<link rel="alternate" href="')[1].split('"')[0]

            if title:
                papers.append({
                    "title": title,
                    "authors": author,
                    "published": published,
                    "summary": summary,
                    "link": link,
                })

        return papers
    except Exception as e:
        return [{"error": str(e)}]


def run_cron(topics: list[str] | None = None):
    """Run scheduled research update."""
    ensure_dirs()

    default_topics = [
        "LLM jailbreak",
        "web application vulnerability",
        "SQL injection attack",
        "cross-site scripting",
        "server-side request forgery",
        "privilege escalation cloud",
    ]
    topics = topics or default_topics

    all_papers = []
    for topic in topics:
        papers = fetch_arxiv(topic, limit=3)
        all_papers.extend(papers)
        time.sleep(3)  # Rate limit courtesy

    # Save to research directory
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    output_file = ARXIV_DIR / f"research_{timestamp}.json"

    # Also update latest
    latest_file = ARXIV_DIR / "latest.json"

    data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "topics": topics,
        "papers": all_papers,
        "total_found": len(all_papers),
    }

    output_file.write_text(json.dumps(data, indent=2))
    latest_file.write_text(json.dumps(data, indent=2))

    return data


def main():
    args = sys.argv[1:]

    if not args or "--help" in args:
        print(__doc__)
        return

    if "--cron" in args:
        data = run_cron()
        print(f"Research complete: {data['total_found']} papers fetched")

        # Check for browser fallback
        error_papers = [p for p in data["papers"] if "error" in p]
        if error_papers and len(error_papers) > len(data["papers"]) * 0.5:
            fallback = SOURCES_DIR / "browser-fallback-needed.json"
            fallback.write_text(json.dumps({
                "needed": True,
                "timestamp": time.time(),
                "errors": error_papers[:5],
            }))
            print("\nBrowser fallback needed: arXiv API unreachable")
        else:
            print(f"Papers saved to: {ARXIV_DIR}")

    elif "--topics" in args:
        idx = args.index("--topics")
        topics_str = args[idx + 1] if idx + 1 < len(args) else ""
        topics = topics_str.split()
        data = run_cron(topics)
        print(json.dumps(data, indent=2))

    elif "--browser-fallback" in args:
        print("Browser fallback: use browser tools to scrape arXiv directly")
        print("Follow scripts/browser-research.md pattern")
    else:
        # Default: fetch papers for a query
        query = " ".join(args)
        papers = fetch_arxiv(query)
        print(json.dumps(papers, indent=2))


if __name__ == "__main__":
    main()
