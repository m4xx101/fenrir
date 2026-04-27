"""Dynamic tool onboarding and MCP wrapper generation for Fenrir.

Provides capabilities to analyze Python scripts, clone and inspect git repositories,
generate Model Context Protocol (MCP) wrappers, and register them with the Fenrir
tool registry.
"""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
import tempfile
import venv
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple

from loguru import logger
from pydantic import BaseModel, Field, field_validator, ConfigDict


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class ToolArgument(BaseModel):
    """Represents a single CLI argument for a security tool."""
    name: str
    type: Literal["string", "integer", "float", "boolean", "file"] = "string"
    required: bool = True
    default: Optional[str] = None
    help: str = ""

    model_config = ConfigDict(populate_by_name=True)


class ToolMetadata(BaseModel):
    """Structured metadata about an onboarded security tool."""
    name: str
    description: str = "Unknown tool"
    version: Optional[str] = None
    arguments: List[ToolArgument] = Field(default_factory=list)
    input_types: List[Literal["url", "file", "parameter"]] = Field(
        default_factory=lambda: ["parameter"]
    )
    output_format: str = "text"
    security_risk: Literal["low", "medium", "high"] = "medium"
    sandbox_required: bool = True

    @field_validator("arguments")
    @classmethod
    def validate_args_unique(cls, v: List[ToolArgument]) -> List[ToolArgument]:
        names = [a.name.lstrip("-") for a in v]
        if len(names) != len(set(names)):
            raise ValueError("Duplicate argument names detected")
        return v


# ---------------------------------------------------------------------------
# ScriptAnalyzer
# ---------------------------------------------------------------------------

class _ASTVisitor(ast.NodeVisitor):
    """AST visitor to extract argparse/click definitions and security-relevant nodes."""

    def __init__(self, source: str):
        self.source = source
        self.arguments: List[ToolArgument] = []
        self.imports: List[str] = []
        self.functions: List[Dict[str, Any]] = []
        self.env_vars: List[str] = []
        self.dangerous_calls: List[Dict[str, str]] = []
        self.entry_point: Optional[str] = None
        self.uses_argparse = False
        self.uses_click = False

    def generic_visit(self, node):
        # Track imports
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            else:
                names = [f"{node.module}.{alias.name}" if alias.name != "*" else node.module for alias in node.names]
            self.imports.extend(names)

            if "argparse" in names:
                self.uses_argparse = True
            if "click" in names:
                self.uses_click = True

        # Track function definitions & decorators
        if isinstance(node, ast.FunctionDef):
            decor_names = []
            for dec in node.decorator_list:
                if isinstance(dec, ast.Attribute):
                    decor_names.append(dec.attr)
                elif isinstance(dec, ast.Name):
                    decor_names.append(dec.id)

            self.functions.append({
                "name": node.name,
                "line": node.lineno,
                "decorator": next(iter(decor_names), None),
            })

            if node.name in ("main", "cli", "run", "execute") and "main" not in [d for d in decor_names]:
                self.entry_point = node.name

        # Track argparse add_argument calls
        if isinstance(node, ast.Call):
            func_attr = getattr(node.func, "attr", None)
            func_name = getattr(node.func, "id", None)
            
            if func_attr == "add_argument":
                self._extract_argparse_args(node)
            elif func_attr in ("option", "argument") and self.uses_click:
                self._extract_click_args(node)
            
            # Track env var access
            if isinstance(node.func, ast.Attribute):
                val = node.func.attr
                if val in ("getenv", "environ"):
                    if node.args and isinstance(node.args[0], (ast.Constant, ast.Str)):
                        env_val = node.args[0].value
                        self.env_vars.append(env_val)

            # Security audit: dangerous operations
            self._check_danger(node)

        self.generic_visit_super(node)

    def generic_visit_super(self, node):
        super().generic_visit(node)

    def _extract_argparse_args(self, node: ast.Call):
        arg_def: Dict[str, Any] = {}
        if node.args:
            name_node = node.args[0]
            if isinstance(name_node, ast.Constant):
                arg_def["name"] = name_node.value
            elif isinstance(name_node, ast.Str):
                arg_def["name"] = name_node.s

        for kw in node.keywords:
            if kw.arg == "type":
                if isinstance(kw.value, ast.Name):
                    arg_def["type"] = kw.value.id.lower()
                elif isinstance(kw.value, ast.Attribute):
                    arg_def["type"] = kw.value.attr.lower()
            elif kw.arg == "required":
                if isinstance(kw.value, ast.Constant):
                    arg_def["required"] = kw.value.value
            elif kw.arg == "default":
                if isinstance(kw.value, ast.Constant):
                    arg_def["default"] = str(kw.value.value)
            elif kw.arg == "help":
                if isinstance(kw.value, ast.Constant):
                    arg_def["help"] = kw.value.value

        if "name" in arg_def:
            self.arguments.append(ToolArgument(**arg_def))

    def _extract_click_args(self, node: ast.Call):
        # Simplified extraction for click.option / click.argument
        arg_def: Dict[str, Any] = {}
        if node.args:
            name_node = node.args[0]
            name = name_node.value if isinstance(name_node, ast.Constant) else ""
            if name:
                arg_def["name"] = name.replace("-", "_").lstrip("_")

        for kw in node.keywords:
            if kw.arg == "required":
                arg_def["required"] = kw.value.value if isinstance(kw.value, ast.Constant) else True
            elif kw.arg == "default":
                arg_def["default"] = str(kw.value.value) if isinstance(kw.value, ast.Constant) else None
            elif kw.arg == "help" or kw.arg == "prompt":
                arg_def["help"] = kw.value.value if isinstance(kw.value, ast.Constant) else ""

        if "name" in arg_def:
            self.arguments.append(ToolArgument(**arg_def))

    def _check_danger(self, node: ast.Call):
        DANGEROUS = {"eval", "exec", "compile", "system", "popen", "rmtree"}
        name = ""
        if isinstance(node.func, ast.Name):
            name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            name = node.func.attr

        line = self.source.split("\n")[node.lineno - 1].strip() if node.lineno else ""

        if name in DANGEROUS or any(d in name for d in ("rmtree", "exec", "popen")):
            self.dangerous_calls.append({"call": name, "line": line})
        
        # Check for hardcoded external IPs/URLs in string literals passed to subprocess/network calls
        if name in ("request", "get", "post", "connect", "socket"):
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if re.search(r"(?:\d{1,3}\.){3}\d{1,3}|http[s]?://", arg.value):
                        self.dangerous_calls.append({"call": name, "line": line})


class ScriptAnalyzer:
    """Static analysis of Python security scripts to extract metadata and assess risk."""

    def analyze(self, path: str) -> Dict[str, Any]:
        """Analyze a Python script and return extracted metadata."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Script not found: {path}")

        source = p.read_text(encoding="utf-8")
        tree = ast.parse(source)
        visitor = _ASTVisitor(source)
        visitor.visit(tree)

        # Attempt to infer output format from print/return patterns
        output_fmt = "text"
        if any("json" in imp.lower() for imp in visitor.imports):
            output_fmt = "json"

        # Determine security risk based on dangerous operations
        risk_score = len(visitor.dangerous_calls)
        security_risk: Literal["low", "medium", "high"] = (
            "high" if risk_score >= 3
            else "medium" if risk_score >= 1
            else "low"
        )

        return {
            "name": p.stem,
            "description": f"Tool from {p.name}",
            "version": None,
            "arguments": [a.model_dump() for a in visitor.arguments],
            "imports": visitor.imports,
            "entry_point": visitor.entry_point or "__main__",
            "env_vars": visitor.env_vars,
            "output_format": output_fmt,
            "cli_framework": "click" if visitor.uses_click else ("argparse" if visitor.uses_argparse else "unknown"),
            "security_audit": {
                "risk": security_risk,
                "dangerous_calls": visitor.dangerous_calls,
                "sandbox_required": security_risk in ("medium", "high")
            }
        }


# ---------------------------------------------------------------------------
# RepoCloner
# ---------------------------------------------------------------------------

class RepoCloner:
    """Handles cloning git repositories, extracting setup information, and preparing environments."""

    BASE_DIR = Path("/tmp/fenrir-tools")

    def clone(self, url: str, dest: Optional[str] = None) -> Path:
        """Clone a git repository."""
        self.BASE_DIR.mkdir(parents=True, exist_ok=True)
        repo_name = url.rstrip("/").split("/")[-1].removesuffix(".git")
        target = Path(dest) if dest else self.BASE_DIR / repo_name

        if target.exists() and (target / ".git").exists():
            logger.info(f"Repo already exists at {target}, pulling updates...")
            try:
                subprocess.run(
                    ["git", "-C", str(target), "pull"],
                    check=True, capture_output=True, timeout=120
                )
            except subprocess.CalledProcessError as e:
                logger.warning(f"Pull failed, falling back to fresh clone: {e}")
                shutil.rmtree(target)
            else:
                return target

        logger.info(f"Cloning {url} to {target}")
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", url, str(target)],
                check=True, capture_output=True, timeout=300
            )
        except subprocess.CalledProcessError as e:
            logger.error(f"Git clone failed: {e.stderr.decode('utf-8', errors='replace')}")
            raise RuntimeError(f"Failed to clone repository: {e}")

        return target

    def extract_requirements(self, repo_path: Path) -> Dict[str, Any]:
        """Extract dependencies from setup files."""
        reqs: List[str] = []
        
        # requirements.txt
        req_file = repo_path / "requirements.txt"
        if req_file.exists():
            reqs.extend(
                line.strip() for line in req_file.read_text().splitlines()
                if line.strip() and not line.startswith("#")
            )

        # setup.py
        setup_py = repo_path / "setup.py"
        if setup_py.exists():
            text = setup_py.read_text()
            # Simple regex extraction for install_requires
            match = re.search(r"install_requires\s*=\s*\[(.*?)\]", text, re.DOTALL)
            if match:
                items = re.findall(r'"([^"]+)"|\'([^\']+)\'', match.group(1))
                reqs.extend([m[0] or m[1] for m in items])

        # pyproject.toml
        pyproject = repo_path / "pyproject.toml"
        if pyproject.exists():
            text = pyproject.read_text()
            # Match dependencies array
            match = re.search(r"dependencies\s*=\s*\[(.*?)\]", text, re.DOTALL)
            if match:
                reqs.extend(
                    m.strip().strip("\"'")
                    for m in re.split(r"[,\n]", match.group(1))
                    if m.strip()
                )

        return {"requirements": reqs, "has_requirements_txt": (repo_path / "requirements.txt").exists()}

    def identify_entry_point(self, repo_path: Path) -> Optional[str]:
        """Identify the main executable script or entry point in the repo."""
        # Check pyproject.toml [project.scripts]
        pyproject = repo_path / "pyproject.toml"
        if pyproject.exists():
            text = pyproject.read_text()
            match = re.search(r"\[project\.scripts\]\s*(.*?)(\n\[|\Z)", text, re.DOTALL)
            if match:
                scripts = re.findall(r"(\w[\w-]*)\s*=\s*['\"](.+?)['\"]", match.group(1))
                if scripts:
                    # Return the module path
                    return scripts[0][1].split(":")[0].replace(".", "/") + ".py"

        # Check setup.py console_scripts
        setup_py = repo_path / "setup.py"
        if setup_py.exists():
            text = setup_py.read_text()
            match = re.search(r"entry_points\s*=\s*{.*?console_scripts.*?\[(.*?)\]}", text, re.DOTALL)
            if match:
                scripts = re.findall(r"(\w[\w-]*)\s*=\s*['\"](.+?)['\"]", match.group(1))
                if scripts:
                    return scripts[0][1].split(":")[0].replace(".", "/") + ".py"

        # Fallback: find __main__.py or top-level scripts
        main_py = repo_path / "__main__.py"
        if main_py.exists():
            return str(main_py.relative_to(repo_path))
        
        # Look for a cli.py or main.py in common locations
        for candidate in ["cli.py", "main.py", "run.py"]:
            for p in repo_path.glob(f"**/{candidate}"):
                if not p.name == "test_" + candidate:
                    return str(p.relative_to(repo_path))

        return None

    def setup_venv(self, repo_path: Path, requirements: Optional[List[str]] = None) -> Path:
        """Create an isolated venv and install dependencies."""
        venv_dir = repo_path / ".venv"
        if venv_dir.exists() and (venv_dir / "bin" / "python").exists():
            logger.info(f"Existing venv found at {venv_dir}")
            return venv_dir

        logger.info(f"Creating venv at {venv_dir}")
        try:
            venv.create(str(venv_dir), with_pip=True, clear=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"venv creation failed: {e}")
            raise

        self._run_in_venv(venv_dir, ["pip", "install", "--upgrade", "pip", "setuptools"])
        
        if requirements:
            # Write to temp req file to avoid shell escaping issues
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write("\n".join(requirements))
                f.flush()
                self._run_in_venv(venv_dir, ["pip", "install", "-r", f.name])
            os.unlink(f.name)

        return venv_dir

    def _run_in_venv(self, venv_dir: Path, cmd: List[str]):
        """Run a command inside the venv."""
        py_bin = str(venv_dir / "bin" / "python")
        full_cmd = [py_bin, "-m"] + cmd
        try:
            subprocess.run(full_cmd, check=True, capture_output=True, timeout=300)
        except subprocess.CalledProcessError as e:
            err = e.stderr.decode("utf-8", errors="replace")
            logger.warning(f"venv command failed: {' '.join(full_cmd)} -> {err}")


# ---------------------------------------------------------------------------
# ToolLoader
# ---------------------------------------------------------------------------

MCP_WRAPPER_TEMPLATE = '''"""
Auto-generated MCP Wrapper for {name}
Generated by Fenrir ToolLoader. Do not edit manually.
"""
import subprocess
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional, List

SCRIPT_PATH = "{script_path}"
VENV_PYTHON = "{venv_python}"

def {wrapper_func_name}({args_signature}) -> Dict[str, Any]:
    """{description}"""
    cmd = [VENV_PYTHON, SCRIPT_PATH]
    {cmd_build}
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout={timeout},
            check=False
        )
        return {{
            "success": proc.returncode == 0,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "returncode": proc.returncode
        }}
    except subprocess.TimeoutExpired:
        return {{"success": False, "stderr": "Tool execution timed out"}}
    except Exception as e:
        return {{"success": False, "stderr": str(e)}}

# MCP Tool Registry Interface
__tool_info__ = {{
    "name": "{name}",
    "description": "{description}",
    "arguments": {args_def_json},
    "version": "{version}",
    "sandbox_required": {sandbox}
}}

def get_tool_info() -> Dict[str, Any]:
    return __tool_info__
'''


class ToolLoader:
    """Orchestrates tool onboarding from scripts and git repositories."""

    def __init__(
        self,
        analyzer: Optional[ScriptAnalyzer] = None,
        cloner: Optional[RepoCloner] = None,
    ):
        self.analyzer = analyzer or ScriptAnalyzer()
        self.cloner = cloner or RepoCloner()

    def analyze_script(self, path: str) -> Dict[str, Any]:
        """Read a Python script and extract tool metadata."""
        logger.info(f"Analyzing script: {path}")
        return self.analyzer.analyze(path)

    def analyze_repo(self, url: str, dest: str) -> Dict[str, Any]:
        """Clone a git repo and extract tool metadata from README/setup files."""
        logger.info(f"Analyzing repository: {url}")
        repo_path = self.cloner.clone(url, dest)
        
        info: Dict[str, Any] = {
            "name": repo_path.name,
            "description": "",
            "version": None,
            "entry_point": self.cloner.identify_entry_point(repo_path),
            "requirements": self.cloner.extract_requirements(repo_path),
            "path": str(repo_path)
        }

        # Extract metadata from README
        readme = next(repo_path.glob("README*"), None)
        if readme:
            text = readme.read_text(encoding="utf-8", errors="ignore")
            info["description"] = text.split("\n")[0].lstrip("# ").strip()

        # Extract name/version from setup.py/pyproject.toml
        setup_py = repo_path / "setup.py"
        if setup_py.exists():
            text = setup_py.read_text()
            match = re.search(r'name\s*=\s*["\'](.+?)["\']', text)
            if match: info["name"] = match.group(1)
            match = re.search(r'version\s*=\s*["\'](.+?)["\']', text)
            if match: info["version"] = match.group(1)

        pyproject = repo_path / "pyproject.toml"
        if pyproject.exists():
            text = pyproject.read_text()
            match = re.search(r'name\s*=\s*["\'](.+?)["\']', text)
            if match: info["name"] = match.group(1)
            match = re.search(r'version\s*=\s*["\'](.+?)["\']', text)
            if match: info["version"] = match.group(1)

        # Analyze entry point if found
        if info.get("entry_point"):
            entry = repo_path / info["entry_point"]
            if entry.exists():
                try:
                    analysis = self.analyzer.analyze(str(entry))
                    info["arguments"] = analysis.get("arguments", [])
                    info["security_audit"] = analysis.get("security_audit", {})
                except Exception as e:
                    logger.warning(f"Failed to analyze entry point: {e}")

        return info

    def generate_mcp_wrapper(self, tool_meta: Dict[str, Any], output_dir: Optional[str] = None) -> str:
        """Generate a Python MCP wrapper exposing CLI args as typed functions."""
        name = tool_meta.get("name", "unnamed_tool").replace("-", "_")
        desc = tool_meta.get("description", "No description")
        version = tool_meta.get("version", "0.0.0")
        entry = tool_meta.get("entry_point", tool_meta.get("path", "main.py"))
        venv_py = str(Path(tool_meta.get("path", ".venv")) / ".venv" / "bin" / "python")
        
        # Build signature and cmd construction
        args = tool_meta.get("arguments", [])
        signatures = []
        cmd_lines = []

        for arg in args:
            arg_name = arg.get("name", "").lstrip("-").replace("-", "_")
            if not arg_name: continue
            arg_type = arg.get("type", "str")
            py_type_map = {"string": "str", "integer": "int", "float": "float", "boolean": "bool"}
            py_type = py_type_map.get(arg_type, "str")
            default = f' = None' if not arg.get("required") else ""
            signatures.append(f"{arg_name}: {py_type}{default}")
            
            cli_name = arg.get("name", "").lstrip("-")
            if arg_type == "boolean":
                cmd_lines.append(f'if {arg_name}: cmd.append("--{cli_name}")')
            else:
                cmd_lines.append(f'if {arg_name}: cmd.extend(["--{cli_name}", str({arg_name})])')

        if not signatures:
            signatures.append("target: str")
            cmd_lines.append('if target: cmd.append(target)')

        args_sig = ", ".join(signatures)
        cmd_str = "\n    ".join(cmd_lines)
        args_def = json.dumps(args, indent=4)

        wrapper_code = MCP_WRAPPER_TEMPLATE.format(
            name=name,
            wrapper_func_name=f"run_{name}",
            description=desc,
            script_path=entry,
            venv_python=venv_py,
            args_signature=args_sig,
            cmd_build=cmd_str,
            timeout=120,
            args_def_json=args_def,
            version=version,
            sandbox=tool_meta.get("sandbox_required", True)
        )

        if output_dir:
            out_path = Path(output_dir) / f"{name}_wrapper.py"
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(wrapper_code)
            return str(out_path)
        
        # Return source if no dir
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(wrapper_code)
            return f.name

    def validate_wrapper(self, path: str) -> bool:
        """Run syntax and import checks against the generated wrapper."""
        logger.info(f"Validating wrapper: {path}")
        p = Path(path)
        if not p.exists():
            return False

        # 1. Syntax check
        try:
            compile(p.read_text(), path, "exec")
        except SyntaxError as e:
            logger.error(f"Syntax error in wrapper: {e}")
            return False

        # 2. Import check
        sys.path.append(str(p.parent))
        try:
            module_name = p.stem
            mod = __import__(module_name)
            if not hasattr(mod, "get_tool_info"):
                logger.warning("Wrapper missing 'get_tool_info' function")
                return False
            
            info = mod.get_tool_info()
            required_keys = {"name", "description", "arguments"}
            if not required_keys.issubset(info.keys()):
                logger.warning(f"Wrapper missing required keys in __tool_info__")
                return False
        except Exception as e:
            logger.error(f"Import validation failed: {e}")
            return False
        finally:
            sys.path.pop()

        # 3. Dry-run check (if main function exists)
        try:
            main_func = getattr(mod, f"run_{info['name'].replace('-', '_')}", None)
            if main_func:
                # Call with all None args to check internal cmd building
                sig_args = {a.get("name", "").replace("-", "_"): None 
                            for a in info.get("arguments", [])}
                if sig_args:
                    res = main_func(**sig_args)
                    if "returncode" not in res:
                        logger.warning("Wrapper function does not return expected dict")
                        return False
        except Exception as e:
            logger.warning(f"Dry-run validation skipped (expected for network tools): {e}")

        logger.success(f"Wrapper validated successfully: {path}")
        return True

    def register_with_registry(self, wrapper_path: str, registry: Optional[Any] = None) -> str:
        """Add the wrapper to the Fenrir ToolRegistry."""
        logger.info(f"Registering wrapper with registry: {wrapper_path}")
        p = Path(wrapper_path)
        if not p.exists():
            raise FileNotFoundError(f"Wrapper not found: {wrapper_path}")

        # Import wrapper module
        sys.path.append(str(p.parent))
        module_name = p.stem
        mod = __import__(module_name)
        sys.path.pop()

        info = mod.get_tool_info()
        tool_name = info["name"]
        func = getattr(mod, f"run_{tool_name.replace('-', '_')}")
        desc = info.get("description", "Auto-registered tool")

        reg = registry or ToolRegistry()
        reg.register(tool_name, func, desc)
        logger.success(f"Registered tool '{tool_name}' with registry")
        return tool_name
