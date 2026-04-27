"""Browser tool wrapper using Playwright for interactive browsing."""

from __future__ import annotations

import json
from typing import Any

from loguru import logger
from pydantic import BaseModel

# Playwright lazy imports to avoid startup overhead


class BrowserTool:
    """Playwright-based browser automation for interactive recon."""

    def __init__(self, config: Any = None):
        self.config = config
        self._browser = None
        self._context = None
        self._page = None

    def _ensure_browser(self):
        """Ensure browser is launched."""
        if self._browser is None:
            try:
                from playwright.sync_api import sync_playwright

                pw = sync_playwright().start()
                self._browser = pw.chromium.launch(headless=True)
                self._context = self._browser.new_context(
                    viewport={"width": 1280, "height": 800},
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    ignore_https_errors=True,
                    bypass_csp=True,
                )
                self._page = self._context.new_page()
            except Exception as e:
                logger.error(f"Failed to launch browser: {e}")
                raise

    def navigate(self, url: str, wait_until: str = "load", timeout: int = 30000) -> dict[str, Any]:
        """Navigate to URL and return page info."""
        self._ensure_browser()

        try:
            response = self._page.goto(url, wait_until=wait_until, timeout=timeout)
            page_info = {
                "url": self._page.url,
                "title": self._page.title(),
                "status": response.status if response else None,
                "headers": dict(response.headers) if response else {},
                "final_url": self._page.url,
            }
            logger.info(f"Browser navigated to {url} (title: {page_info['title']})")
            return page_info
        except Exception as e:
            logger.error(f"Browser navigation failed: {e}")
            return {"error": str(e), "url": url}

    def click(self, selector: str) -> dict[str, Any]:
        """Click an element on the page."""
        self._ensure_browser()

        try:
            self._page.click(selector, timeout=10000)
            self._page.wait_for_load_state("networkidle", timeout=5000)
            return {
                "success": True,
                "url": self._page.url,
                "title": self._page.title(),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def fill(self, selector: str, value: str) -> dict[str, Any]:
        """Fill a form field."""
        self._ensure_browser()

        try:
            self._page.fill(selector, value, timeout=10000)
            return {"success": True, "selector": selector, "value": value}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def screenshot(self, path: str = "") -> dict[str, Any]:
        """Take a screenshot of the current page."""
        self._ensure_browser()

        try:
            if not path:
                import tempfile
                path = tempfile.mktemp(suffix=".png")

            self._page.screenshot(path=path, full_page=True)
            return {"success": True, "path": path}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def evaluate(self, javascript: str) -> dict[str, Any]:
        """Execute JavaScript in the browser context."""
        self._ensure_browser()

        try:
            result = self._page.evaluate(javascript)
            return {"success": True, "result": result}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_content(self, full: bool = True) -> dict[str, Any]:
        """Get the current page's HTML content."""
        self._ensure_browser()

        try:
            if full:
                html = self._page.content()
            else:
                html = self._page.locator("body").inner_text()
            return {
                "success": True,
                "url": self._page.url,
                "title": self._page.title(),
                "html_length": len(html),
                "preview": html[:5000],
                "full_html": html if len(html) <= 50000 else html[:50000],
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_links(self) -> list[str]:
        """Extract all links from the current page."""
        self._ensure_browser()

        try:
            links = self._page.evaluate("""
                () => {
                    const links = document.querySelectorAll('a[href]');
                    return Array.from(links).map(a => a.href);
                }
            """)
            return links
        except Exception as e:
            logger.error(f"Failed to extract links: {e}")
            return []

    def get_forms(self) -> list[dict[str, Any]]:
        """Extract all forms from the current page."""
        self._ensure_browser()

        try:
            forms = self._page.evaluate("""
                () => {
                    const forms = document.querySelectorAll('form');
                    return Array.from(forms).map(f => ({
                        action: f.action,
                        method: f.method,
                        inputs: Array.from(f.querySelectorAll('input')).map(i => ({
                            name: i.name,
                            type: i.type,
                            value: i.value
                        }))
                    }));
                }
            """)
            return forms
        except Exception as e:
            logger.error(f"Failed to extract forms: {e}")
            return []

    def get_local_storage(self) -> dict[str, Any]:
        """Get localStorage contents."""
        self._ensure_browser()
        try:
            return self._page.evaluate("() => Object.assign({}, localStorage)")
        except Exception as e:
            return {"error": str(e)}

    def get_cookies(self) -> list[dict[str, Any]]:
        """Get browser cookies."""
        self._ensure_browser()
        try:
            cookies = self._context.cookies()
            return cookies
        except Exception as e:
            return [{"error": str(e)}]

    def set_cookies(self, cookies: list[dict[str, Any]]) -> dict[str, Any]:
        """Set cookies in browser context."""
        self._ensure_browser()
        try:
            self._context.add_cookies(cookies)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def discover_endpoints(self, base_url: str, depth: int = 2) -> list[str]:
        """Discover endpoints by exploring pages."""
        self._ensure_browser()
        discovered = []

        try:
            self.navigate(base_url)
            links = self.get_links()

            for link in links[:50]:
                if link.startswith(base_url) or link.startswith("/"):
                    if link not in discovered:
                        discovered.append(link)

            if depth > 1:
                for link in discovered[:20]:
                    try:
                        self.navigate(link, wait_until="domcontentloaded", timeout=10000)
                        sub_links = self.get_links()
                        for sub in sub_links:
                            if sub.startswith(base_url) and sub not in discovered:
                                discovered.append(sub)
                    except Exception:
                        continue
        except Exception as e:
            logger.error(f"Endpoint discovery failed: {e}")

        return discovered[:200]

    def close(self) -> None:
        """Close browser."""
        if self._browser:
            self._browser.close()
            self._browser = None
            self._context = None
            self._page = None
