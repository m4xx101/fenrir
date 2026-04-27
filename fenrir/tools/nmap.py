"""Nmap tool wrapper: scan execution and XML parsing."""

from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import xmltodict
from loguru import logger
from pydantic import BaseModel, Field


class PortResult(BaseModel):
    """Parsed port scan result."""
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    extra_info: str = ""


class HostResult(BaseModel):
    """Parsed host scan result."""
    ip: str
    hostname: str = ""
    ports: list[PortResult] = Field(default_factory=list)
    os_guess: str = ""


class NmapResult(BaseModel):
    """Full nmap scan result."""
    target: str
    hosts: list[HostResult] = Field(default_factory=list)
    scan_args: str = ""
    raw_output: str = ""


class NmapTool:
    """Nmap wrapper with scan execution and XML parsing."""

    def __init__(self, config: Any = None):
        self.config = config
        self.nmap_binary = "nmap"
        if config and hasattr(config, "tools"):
            self.nmap_binary = config.tools.nmap_binary

    def scan(
        self,
        target: str,
        ports: str = "-p-",
        rate: str = "-T4",
        service_detection: bool = True,
        os_detection: bool = False,
        script_scans: str = "",
        additional_args: str = "",
        timeout: int = 300,
    ) -> dict[str, Any]:
        """Run Nmap scan and return parsed results.

        Args:
            target: Target host or IP
            ports: Port specification (e.g., '-p-') for all ports, '-p 1-1000' for specific
            rate: Timing template ('-T0' to '-T5')
            service_detection: Enable -sV version detection
            os_detection: Enable -O OS detection
            script_scans: NSE scripts to run
            additional_args: Extra nmap arguments
            timeout: Max seconds to wait
        """
        args = [self.nmap_binary]

        if ports:
            args.append(ports)
        if rate:
            args.append(rate)
        if service_detection:
            args.append("-sV")
        if os_detection:
            args.append("-O")
        if script_scans:
            args.append(f"--script={script_scans}")

        # Always use XML output and all ports format
        args.append("-oX")
        args.append("-")  # stdout
        if additional_args:
            args.append(additional_args)

        args.append(target)

        logger.info(f"Running nmap: {' '.join(args)[:200]}...")

        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            if result.returncode != 0 and not result.stdout:
                return {
                    "success": False,
                    "error": result.stderr[:500],
                    "raw_output": result.stdout,
                }

            # Parse XML output
            parsed = self.parse_xml(result.stdout)
            parsed["raw_output"] = result.stdout[:10000]  # Truncate for saving
            parsed["scan_args"] = " ".join(args[1:])
            parsed["success"] = True
            return parsed

        except subprocess.TimeoutExpired:
            return {"success": False, "error": f"Nmap timed out after {timeout}s"}
        except FileNotFoundError:
            return {"success": False, "error": f"Nmap binary not found: {self.nmap_binary}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def parse_xml(self, xml_output: str) -> dict[str, Any]:
        """Parse Nmap XML output into structured results."""
        hosts = []

        try:
            data = xmltodict.parse(xml_output)
        except Exception as e:
            return {"hosts": [], "error": f"XML parse error: {e}"}

        nmaprun = data.get("nmaprun", {})

        # Parse hosts
        host_data = nmaprun.get("host", [])
        if isinstance(host_data, dict):
            host_data = [host_data]

        for host in host_data:
            # IP address
            addresses = host.get("address", [])
            if isinstance(addresses, dict):
                addresses = [addresses]
            ip = ""
            for addr in addresses:
                if addr.get("@addrtype") == "ipv4":
                    ip = addr.get("@addr", "")
                    break
            if not ip and addresses:
                ip = addresses[0].get("@addr", "")

            # Hostname
            hostnames_data = host.get("hostnames", {})
            hostname_data = hostnames_data.get("hostname", {})
            hostname = ""
            if isinstance(hostname_data, list) and hostname_data:
                hostname = hostname_data[0].get("@name", "")
            elif isinstance(hostname_data, dict):
                hostname = hostname_data.get("@name", "")

            # Ports
            ports = []
            ports_elem = host.get("ports", {})
            port_elems = ports_elem.get("port", [])
            if isinstance(port_elems, dict):
                port_elems = [port_elems]

            for port_elem in port_elems:
                if not port_elem:
                    continue
                port_num = int(port_elem.get("@portid", 0))
                protocol = port_elem.get("@protocol", "tcp")

                state_elem = port_elem.get("state", {})
                state = state_elem.get("@state", "unknown")

                service_elem = port_elem.get("service", {})
                service = service_elem.get("@name", "")
                version = service_elem.get("@version", "")
                product = service_elem.get("@product", "")
                extra = service_elem.get("@extrainfo", "")

                version_parts = []
                if product:
                    version_parts.append(product)
                if version:
                    version_parts.append(version)

                ports.append(
                    PortResult(
                        port=port_num,
                        protocol=protocol,
                        state=state,
                        service=service,
                        version=" ".join(version_parts),
                        extra_info=extra,
                    )
                )

            # OS detection
            os_elem = host.get("os", {})
            os_match = os_elem.get("osmatch", {})
            os_guess = ""
            if isinstance(os_match, list) and os_match:
                os_guess = os_match[0].get("@name", "")
            elif isinstance(os_match, dict):
                os_guess = os_match.get("@name", "")

            hosts.append(
                HostResult(
                    ip=ip,
                    hostname=hostname,
                    ports=ports,
                    os_guess=os_guess,
                )
            )

        # Parse scan info
        scan_args = nmaprun.get("@args", "").split("--")

        result = {
            "hosts": [h.model_dump() for h in hosts],
            "scan_args": " ".join(scan_args) if isinstance(scan_args, list) else scan_args,
            "target": nmaprun.get("@args", "").split()[-1] if scan_args else "",
            "total_hosts": len(hosts),
        }

        return result

    def quick_scan(self, target: str) -> dict[str, Any]:
        """Quick top 1000 ports scan."""
        return self.scan(target, ports="-F", rate="-T4", service_detection=True)

    def full_scan(self, target: str) -> dict[str, Any]:
        """Full port range scan with service detection."""
        return self.scan(
            target,
            ports="-p-",
            rate="-T4",
            service_detection=True,
            os_detection=True,
        )

    def vuln_scan(self, target: str) -> dict[str, Any]:
        """Nmap scan with vulnerability scripts."""
        return self.scan(
            target,
            ports="-F",
            rate="-T4",
            service_detection=True,
            script_scans="vuln,exploit",
        )
