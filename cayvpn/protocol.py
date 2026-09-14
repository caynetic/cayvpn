from __future__ import annotations

import json
import socket
from dataclasses import dataclass, field
from typing import Any


PROTOCOL_VERSION = 1
DEFAULT_AGENT_TIMEOUT = 15
ACTION_TIMEOUTS = {
    "system.verify": 60,
    "route.switch": 90,
    "route.ipv6_reconcile": 45,
    "runtime.reconcile": 180,
    "egress.activate": 60,
    "egress.probe": 30,
    "component.install": 300,
    "remote_admin.configure": 300,
    "remote_admin.renew": 300,
    "backup.create": 300,
    "update.check": 30,
    "update.stage": 1800,
    "update.apply": 1800,
    "update.discard": 30,
    "update.status": 15,
}
FORBIDDEN_KEYS = {
    "shell",
    "command",
    "commands",
    "script",
    "setup",
    "postup",
    "postdown",
    "preup",
    "predown",
    "exec",
}

VALID_ACTIONS = {
    "system.snapshot",
    "system.verify",
    "runtime.reconcile",
    "wireguard.reconcile",
    "wireguard.remove_peer",
    "egress.validate",
    "egress.activate",
    "egress.deactivate",
    "egress.probe",
    "route.switch",
    "route.ipv6_reconcile",
    "route.fail_closed",
    "route.remove",
    "firewall.reconcile",
    "admin.reconcile",
    "component.install",
    "remote_admin.configure",
    "remote_admin.renew",
    "secret.store",
    "totp.create",
    "totp.uri",
    "totp.verify",
    "config.render_client",
    "config.render_admin",
    "secret.delete",
    "backup.create",
    "update.check",
    "update.stage",
    "update.apply",
    "update.discard",
    "update.status",
}


def _validate_payload(value: Any, path: str = "payload") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower().replace("_", "") in {item.replace("_", "") for item in FORBIDDEN_KEYS}:
                raise ValueError(f"forbidden operation field: {path}.{key}")
            _validate_payload(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _validate_payload(child, f"{path}[{index}]")
    elif isinstance(value, (str, int, float, bool)) or value is None:
        return
    else:
        raise ValueError(f"unsupported payload value at {path}")


@dataclass(frozen=True)
class AgentRequest:
    operation_id: str
    action: str
    node_id: int = 1
    desired_generation: int = 0
    payload: dict[str, Any] = field(default_factory=dict)
    protocol_version: int = PROTOCOL_VERSION

    def __post_init__(self) -> None:
        if self.protocol_version != PROTOCOL_VERSION:
            raise ValueError("unsupported agent protocol version")
        if self.action not in VALID_ACTIONS:
            raise ValueError("unsupported agent action")
        if not self.operation_id or len(self.operation_id) > 64:
            raise ValueError("invalid operation id")
        _validate_payload(self.payload)

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol_version": self.protocol_version,
            "operation_id": self.operation_id,
            "node_id": self.node_id,
            "desired_generation": self.desired_generation,
            "action": self.action,
            "payload": self.payload,
        }


@dataclass(frozen=True)
class AgentResponse:
    operation_id: str
    status: str
    observed_generation: int | None = None
    result: dict[str, Any] = field(default_factory=dict)
    error_code: str | None = None
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "status": self.status,
            "observed_generation": self.observed_generation,
            "result": self.result,
            "error_code": self.error_code,
            "error_message": self.error_message,
        }


class AgentClient:
    def __init__(self, socket_path, inline_executor=None):
        self.socket_path = socket_path
        self.inline_executor = inline_executor

    @staticmethod
    def timeout_for(action: str) -> int:
        return ACTION_TIMEOUTS.get(action, DEFAULT_AGENT_TIMEOUT)

    def execute(self, request: AgentRequest) -> AgentResponse:
        if self.inline_executor is not None:
            return self.inline_executor(request)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect(str(self.socket_path))
            sock.settimeout(self.timeout_for(request.action))
            sock.sendall((json.dumps(request.to_dict()) + "\n").encode())
            buffer = b""
            while b"\n" not in buffer:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buffer += chunk
            if not buffer:
                return AgentResponse(request.operation_id, "failed", error_code="agent_empty_response", error_message="Agent returned no response")
            data = json.loads(buffer.split(b"\n", 1)[0].decode())
            return AgentResponse(
                operation_id=data.get("operation_id", request.operation_id),
                status=data.get("status", "failed"),
                observed_generation=data.get("observed_generation"),
                result=data.get("result") or {},
                error_code=data.get("error_code"),
                error_message=data.get("error_message"),
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return AgentResponse(request.operation_id, "queued", error_code="agent_unavailable", error_message=str(exc))
        finally:
            sock.close()
