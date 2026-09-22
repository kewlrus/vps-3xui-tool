"""Typed systemd facts and the Certbot scheduler conflict rules.

Unknown Certbot schedulers or hooks are conflicts, never something to adapt
around. The rules live here so the same logic is used by the CLI inventory and
by any future remote check.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

REMOVABLE_HOOK_KEYS = ("pre_hook", "post_hook", "renew_hook", "deploy_hook")


class SystemdFacts(object):
    @staticmethod
    def parse_units(section: Any) -> Dict[str, Dict[str, Any]]:
        section = section or {}
        units = section.get("units") if isinstance(section, dict) else None
        parsed: Dict[str, Dict[str, Any]] = {}
        for name, state in (units or {}).items():
            if not isinstance(state, dict):
                continue
            parsed[name] = {
                "load_state": state.get("load_state"),
                "active_state": state.get("active_state"),
                "unit_file_state": state.get("unit_file_state"),
            }
        return parsed

    @staticmethod
    def certbot_conflicts(
        certbot: Dict[str, Any],
        unit_files: List[str],
        cron_entries: List[str],
        renewal_hooks: Dict[str, Dict[str, Any]],
        guard_present: bool,
        guard_enabled: bool,
    ) -> List[Dict[str, Optional[str]]]:
        findings: List[Dict[str, Optional[str]]] = []
        allowed_units = {
            certbot["service_unit"],
            certbot["timer_unit"],
            certbot["cleanup_service"],
            certbot["cleanup_timer"],
        }
        for unit in unit_files or []:
            if "certbot" in unit and unit not in allowed_units:
                findings.append(
                    {
                        "code": "E_CONFLICT",
                        "message": "An unexpected Certbot scheduler unit is installed.",
                        "resource": unit,
                        "next_action": "review_certbot_schedulers",
                    }
                )
        if cron_entries:
            findings.append(
                {
                    "code": "E_CONFLICT",
                    "message": "A Certbot cron entry exists outside the approved systemd automation.",
                    "resource": "cron",
                    "next_action": "review_certbot_schedulers",
                }
            )
        permitted = set(certbot["permitted_hooks"])
        for filename, hooks in (renewal_hooks or {}).items():
            for key, value in hooks.items():
                if key in REMOVABLE_HOOK_KEYS:
                    if not value:
                        continue
                    if key in permitted:
                        continue
                    if key == "deploy_hook" and "renew_hook" in permitted:
                        continue
                    findings.append(
                        {
                            "code": "E_CONFLICT",
                            "message": "A Certbot renewal file defines an unapproved hook.",
                            "resource": "%s:%s" % (filename, key),
                            "next_action": "review_certbot_hooks",
                        }
                    )
                elif key == "authenticator" and value and value not in ("standalone",):
                    findings.append(
                        {
                            "code": "E_CONFLICT",
                            "message": "A Certbot renewal file uses an unapproved authenticator.",
                            "resource": filename,
                            "next_action": "review_certbot_renewal",
                        }
                    )
        if guard_enabled and not guard_present:
            findings.append(
                {
                    "code": "E_CONFLICT",
                    "message": "The guard approval file exists but the guard helper is missing.",
                    "resource": certbot["guard_enabled_path"],
                    "next_action": "review_certbot_guard",
                }
            )
        return findings
