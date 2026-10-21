"""Safe main-only bridge from native hook payloads to local signed receipts."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat

import hook_receipt

MAX_COMPONENT_BYTES = 2_000_000


def ensure_private_state(state_dir: Path | str) -> Path:
    """Create the fixed per-host receipt path and refuse unsafe path components."""
    home = Path.home().absolute()
    target = Path(os.path.abspath(os.fspath(state_dir)))
    try:
        parts = target.relative_to(home).parts
    except ValueError as exc:
        raise OSError("receipt state must remain under the current home directory") from exc
    if not parts:
        raise OSError("receipt state cannot be the home directory")

    home_info = home.lstat()
    if (not stat.S_ISDIR(home_info.st_mode) or stat.S_ISLNK(home_info.st_mode)
            or home_info.st_uid != os.getuid()):
        raise OSError("home directory is unsafe")

    current = home
    for index, component in enumerate(parts):
        current = current / component
        try:
            current.mkdir(mode=0o700)
        except FileExistsError:
            pass
        info = current.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.getuid()):
            raise OSError("receipt state path contains an unsafe directory")
        is_private_node = component == "hook-receipts" or index == len(parts) - 1
        if is_private_node and info.st_mode & 0o077:
            raise OSError("receipt state directory must be owner-only")
        if not is_private_node and info.st_mode & 0o022:
            raise OSError("receipt state parent is group- or world-writable")
    return current


def handler_version(handler_id: str, components: tuple[Path | str, ...]) -> str:
    """Bind a distinct handler label to exact, bounded, regular source bytes."""
    if not isinstance(handler_id, str) or not handler_id or len(handler_id) > 96:
        raise ValueError("invalid handler identity")
    digest = hashlib.sha256()
    digest.update(b"native-hook-handler-v1\0" + handler_id.encode("ascii", "strict") + b"\0")
    for component in components:
        path = Path(component)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size > MAX_COMPONENT_BYTES:
            raise OSError("handler source is unsafe or oversized")
        data = path.read_bytes()
        if len(data) > MAX_COMPONENT_BYTES:
            raise OSError("handler source exceeds the size limit")
        digest.update(path.name.encode("utf-8", "strict") + b"\0")
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return f"{handler_id}:{digest.hexdigest()}"


def create_native(state_dir: Path | str, payload: dict, outcome: str, version: str) -> str:
    """Normalize native identity explicitly and create one signed receipt."""
    if not isinstance(payload, dict):
        raise ValueError("native payload must be an object")
    event = payload.get("hook_event_name") or payload.get("event")
    identity = {"event": event, "session_id": payload.get("session_id")}
    for field in ("prompt_id", "turn_id"):
        if field in payload:
            identity[field] = payload[field]
    if not isinstance(event, str) or event not in hook_receipt.EVENTS:
        raise ValueError("unsupported native event")
    hook_receipt._ids(identity, event)
    if outcome not in hook_receipt.OUTCOMES:
        raise ValueError("unsupported receipt outcome")
    protected_state = ensure_private_state(state_dir)
    marker, _receipt = hook_receipt.create(protected_state, identity, outcome, version)
    return marker


def outcome_for(result: dict, *, skipped: bool = False) -> str:
    if skipped:
        return "skipped"
    if isinstance(result, dict):
        output = result.get("hookSpecificOutput")
        if isinstance(output, dict) and output.get("permissionDecision") == "deny":
            return "failure"
        if result.get("decision") == "block":
            return "failure"
        if isinstance(result.get("systemMessage"), str) and result["systemMessage"].strip():
            return "failure"
    return "success"
