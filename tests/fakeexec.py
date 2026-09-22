"""Fake ``subprocess.run`` for exercising the *real* adapters.

The real OpenSSH, systemd and Docker adapters are tested by intercepting
``subprocess.run`` and returning scripted results. This keeps every missing
interface, wrong flag, ignored return code or reflected-output bug visible
without touching a real host.
"""

from __future__ import annotations

import subprocess
from typing import Callable, Dict, List, Optional, Tuple


class FakeRun(object):
    def __init__(self):
        self.calls: List[Tuple[List[str], Dict]] = []
        self.rules: List[Tuple[Callable[[List[str]], bool], subprocess.CompletedProcess]] = []
        self.default = subprocess.CompletedProcess([], 0, b"", b"")
        self.last_kwargs: Dict = {}

    def on(self, predicate, stdout=b"", returncode=0, stderr=b"") -> "FakeRun":
        self.rules.append(
            (predicate, subprocess.CompletedProcess([], returncode, stdout, stderr))
        )
        return self

    def on_subcommand(self, subcommand: str, stdout=b"", returncode=0, stderr=b"") -> "FakeRun":
        def predicate(argv):
            return subcommand in argv

        return self.on(predicate, stdout=stdout, returncode=returncode, stderr=stderr)

    def on_first(self, token: str, stdout=b"", returncode=0, stderr=b"") -> "FakeRun":
        return self.on(lambda argv: bool(argv) and argv[0] == token,
                       stdout=stdout, returncode=returncode, stderr=stderr)

    def __call__(self, argv, *args, **kwargs):
        argv = list(argv)
        self.calls.append((argv, kwargs))
        self.last_kwargs = kwargs
        for predicate, result in self.rules:
            if predicate(argv):
                return subprocess.CompletedProcess(argv, result.returncode, result.stdout, result.stderr)
        return subprocess.CompletedProcess(argv, self.default.returncode,
                                           self.default.stdout, self.default.stderr)

    def command_lines(self) -> List[str]:
        return [" ".join(call[0]) for call in self.calls]

    def find(self, needle: str) -> Optional[List[str]]:
        for argv, _kwargs in self.calls:
            if any(needle in token for token in argv):
                return argv
        return None
