"""Typed access to the Docker facts the probe reports.

Kept separate from ``inventory`` so the allowlisted parsing of container and
volume facts has exactly one home, and so the worker can reuse the same view.
Only the allowlisted fields the probe emits are read here.
"""

from __future__ import annotations

from typing import Any, Dict, List


class DockerFacts(object):
    @staticmethod
    def parse_containers(section: Any) -> Dict[str, Dict[str, Any]]:
        containers: Dict[str, Dict[str, Any]] = {}
        for item in section or []:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if not name:
                continue
            containers[name] = {
                "name": name,
                "id": item.get("id"),
                "image": item.get("image"),
                "image_id": item.get("image_id"),
                "repo_digests": list(item.get("repo_digests") or []),
                "running": bool(item.get("running")),
                "status": item.get("status"),
                "restart_policy": item.get("restart_policy"),
                "network_mode": item.get("network_mode"),
                "compose_project": item.get("compose_project"),
                "compose_service": item.get("compose_service"),
                "mounts": list(item.get("mounts") or []),
            }
        return containers

    @staticmethod
    def parse_volumes(section: Any) -> Dict[str, Dict[str, Any]]:
        volumes: Dict[str, Dict[str, Any]] = {}
        for item in section or []:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if not name:
                continue
            volumes[name] = {
                "name": name,
                "driver": item.get("driver"),
                "options": item.get("options") or {},
                "mountpoint": item.get("mountpoint"),
                "scope": item.get("scope"),
            }
        return volumes

    @staticmethod
    def running(container: Dict[str, Any]) -> bool:
        return bool(container.get("running"))

    @staticmethod
    def repo_digests(container: Dict[str, Any]) -> List[str]:
        return list(container.get("repo_digests") or [])
