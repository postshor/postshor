"""Walking a directory tree and deciding what kind of file each one is."""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path

DEFAULT_EXCLUDES = (
    ".git", ".hg", ".svn", "node_modules", "bower_components", ".venv", "venv", "env",
    "__pycache__", ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "site-packages", "dist", "build", "target", ".gradle", ".idea", ".vscode",
    ".terraform", ".next", ".nuxt", "coverage", ".cache",
)
VENDORED = ("vendor", "third_party", "third-party", "external", "Pods", "deps")

MAX_FILE_BYTES = 2 * 1024 * 1024

_EXT_KINDS = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "javascript", ".tsx": "javascript", ".mts": "javascript", ".cts": "javascript",
    ".java": "jvm", ".kt": "jvm", ".kts": "jvm", ".scala": "jvm", ".groovy": "jvm",
    ".go": "go",
    ".c": "c", ".h": "c", ".cc": "c", ".cpp": "c", ".cxx": "c", ".hpp": "c", ".hh": "c", ".hxx": "c", ".m": "c", ".mm": "c",
    ".cs": "csharp",
    ".rs": "rust",
    ".php": "php",
    ".rb": "ruby",
    ".swift": "swift",
    ".tf": "iac", ".hcl": "iac", ".bicep": "iac",
    ".yaml": "config", ".yml": "config", ".json": "config", ".toml": "config", ".ini": "config",
    ".conf": "config", ".cnf": "config", ".cfg": "config", ".properties": "config", ".xml": "config",
    ".env": "config",
}

# Files handled by the certificate/key scanner instead of pattern rules.
KEY_EXTENSIONS = {".pem", ".crt", ".cer", ".der", ".key", ".pub", ".p12", ".pfx", ".csr"}
KEY_FILENAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "authorized_keys"}

_CONFIG_NAMES = {"nginx.conf", "httpd.conf", "apache2.conf", "haproxy.cfg", "openssl.cnf", "dockerfile", ".env"}


def classify(path: Path) -> set[str]:
    """Return the rule kinds that apply to a file. Empty set = skip."""
    name = path.name.lower()
    if name in ("sshd_config", "ssh_config") or (path.parent.name in ("ssh", ".ssh") and name == "config"):
        return {"ssh-config", "any"}
    if path.suffix.lower() in KEY_EXTENSIONS or name in KEY_FILENAMES:
        return set()
    kind = _EXT_KINDS.get(path.suffix.lower())
    if kind:
        return {kind, "any"}
    if name in _CONFIG_NAMES or name.startswith(".env"):
        return {"config", "any"}
    return set()


def is_key_file(path: Path) -> bool:
    return path.suffix.lower() in KEY_EXTENSIONS or path.name in KEY_FILENAMES


def walk(root: Path, excludes: list[str], include_vendored: bool = False):
    """Yield files under root, pruning excluded directories."""
    skip_dirs = set(DEFAULT_EXCLUDES)
    if not include_vendored:
        skip_dirs.update(VENDORED)
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        dirnames[:] = [
            d for d in dirnames
            if d not in skip_dirs and not _excluded(f"{rel_dir}/{d}".lstrip("./"), excludes)
        ]
        for fn in filenames:
            rel = f"{rel_dir}/{fn}".lstrip("./") if rel_dir != "." else fn
            if not _excluded(rel, excludes):
                yield Path(dirpath) / fn


def _excluded(rel_path: str, patterns: list[str]) -> bool:
    return any(
        fnmatch.fnmatch(rel_path, p) or fnmatch.fnmatch(rel_path, p.rstrip("/") + "/*")
        for p in patterns
    )


def read_text(path: Path) -> str | None:
    """Read a text file, returning None for binaries and oversized files."""
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")
