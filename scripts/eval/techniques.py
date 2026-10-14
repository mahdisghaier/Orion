"""The attack techniques the evaluation runs, and the Sigma rule that is supposed to find each one.

Everything here is harmless and local: processes that sleep, a listener on 127.0.0.1, and files in one
scratch folder. Each instance carries a unique marker so the evaluation knows exactly which events
belong to the scenario under test (ground truth) and which are unrelated activity (noise).
"""
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

FIM_DIR = Path.home() / "orion-eval-fim"
HOLD_SECONDS = 100          # how long the "long-lived" variants stay alive (Metricbeat samples every 30 s)
NC_HOLD_SECONDS = 420       # the listener must outlive Wazuh's 360 s listening-port check


@dataclass
class Instance:
    technique: str
    variant: str                  # "long" | "short" | "file"
    marker: str                   # unique text (or port number) that identifies this instance's events
    numeric: bool = False         # numeric markers are matched as whole numbers only
    procs: List[subprocess.Popen] = field(default_factory=list)
    started_at: float = 0.0
    kill_after: Optional[float] = None    # seconds; the runner stops the instance then (a short listener never exits by itself)
    stopped: bool = False

    def matches(self, text: str) -> bool:
        if self.numeric:
            return re.search(rf"(?<!\d){re.escape(self.marker)}(?!\d)", text) is not None
        return self.marker.lower() in text.lower()


def _spawn(argv: List[str]) -> subprocess.Popen:
    return subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)


def _free_port() -> int:
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ── launchers: (run_id, variant, helper_port) -> Instance ────────────────────────────

def launch_listener(run: str, variant: str, helper_port: int) -> Instance:
    port = _free_port()
    argv = ["nc", "-l", "-k", "127.0.0.1", str(port)] if variant == "long" else ["nc", "-l", "127.0.0.1", str(port)]
    inst = Instance("T1046", variant, str(port), numeric=True, kill_after=None if variant == "long" else 1.0)
    inst.procs.append(_spawn(argv))
    return inst


def launch_shell(run: str, variant: str, helper_port: int) -> Instance:
    marker = f"orion-eval-{run}-sh-{variant}-{os.urandom(2).hex()}"
    seconds = HOLD_SECONDS if variant == "long" else 1
    inst = Instance("T1059.004", variant, marker)
    inst.procs.append(_spawn(["bash", "-c", f"sleep {seconds}; : {marker}"]))
    return inst


def launch_transfer(run: str, variant: str, helper_port: int) -> Instance:
    marker = f"orion-eval-{run}-curl-{variant}-{os.urandom(2).hex()}"
    seconds = HOLD_SECONDS if variant == "long" else 1
    inst = Instance("T1105", variant, marker)
    # the helper accepts the connection and never answers, so curl stays alive until --max-time
    inst.procs.append(_spawn(["curl", "-s", "--max-time", str(seconds), "-o", "/dev/null",
                              f"http://127.0.0.1:{helper_port}/?m={marker}"]))
    return inst


def launch_history_clear(run: str, variant: str, helper_port: int) -> Instance:
    marker = f"orion-eval-{run}-hist-{variant}-{os.urandom(2).hex()}"
    seconds = HOLD_SECONDS if variant == "long" else 1
    # a decoy history file: the evaluation never touches the real ~/.bash_history
    script = f"export HISTFILE=/tmp/{marker}; history -c; sleep {seconds}; : {marker}"
    inst = Instance("T1070.003", variant, marker)
    inst.procs.append(_spawn(["bash", "-c", script]))
    return inst


def launch_file_change(run: str, variant: str, helper_port: int) -> Instance:
    marker = f"orion-eval-{run}-file-{os.urandom(2).hex()}"
    FIM_DIR.mkdir(exist_ok=True)
    script = (f"cd {FIM_DIR} && echo one > {marker}.txt && sleep 3 && echo two >> {marker}.txt && sleep 3 && rm {marker}.txt")
    inst = Instance("T1565.001", variant, marker)
    inst.procs.append(_spawn(["bash", "-c", script]))
    return inst


@dataclass
class Technique:
    key: str
    name: str
    tactic: str
    rule: str
    launch: Callable[[str, str, int], Instance]
    variants: tuple = ("long", "short")
    needs_fim: bool = False
    hold: int = HOLD_SECONDS


def _rule(title: str, detection: str, tags: List[str], category: str = "process_creation") -> str:
    return (f"title: {title}\nstatus: experimental\nlogsource:\n  product: linux\n  category: {category}\n"
            f"detection:\n  selection:\n{detection}\n  condition: selection\ntags:\n" + "".join(f"  - {t}\n" for t in tags))


TECHNIQUES: List[Technique] = [
    Technique("T1046", "Network service discovery: a netcat listener", "discovery",
              _rule("Netcat binary executed",
                    "    Image|endswith:\n      - '/nc'\n      - '/ncat'\n      - '/netcat'\n      - '/nc.openbsd'",
                    ["attack.discovery", "attack.t1046"]),
              launch_listener, hold=NC_HOLD_SECONDS),
    Technique("T1059.004", "Unix shell command execution", "execution",
              _rule("Shell executed",
                    "    Image|endswith:\n      - '/bash'\n      - '/sh'\n      - '/dash'",
                    ["attack.execution", "attack.t1059.004"]),
              launch_shell),
    Technique("T1105", "Ingress tool transfer with curl", "command_and_control",
              _rule("Download tool executed",
                    "    Image|endswith:\n      - '/curl'\n      - '/wget'",
                    ["attack.command_and_control", "attack.t1105"]),
              launch_transfer),
    Technique("T1070.003", "Clear command history", "defense_evasion",
              _rule("Shell history cleared",
                    "    CommandLine|contains:\n      - 'history -c'\n      - '.bash_history'",
                    ["attack.defense_evasion", "attack.t1070.003"]),
              launch_history_clear),
    Technique("T1565.001", "File modification in a watched folder", "impact",
              _rule("Watched file changed", "    TargetFilename|contains: 'orion-eval-fim'",
                    ["attack.impact", "attack.t1565.001"], category="file_event"),
              launch_file_change, variants=("file",), needs_fim=True, hold=15),
]


def start_helper_listener() -> tuple:
    """A tiny server that accepts connections and never replies (keeps curl alive). Returns (process, port)."""
    port = _free_port()
    code = ("import socket,time\ns=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
            f"s.bind(('127.0.0.1',{port}));s.listen(64)\nkeep=[]\nwhile True:\n    keep.append(s.accept())\n")
    return _spawn([sys.executable, "-c", code]), port


def stop(inst: Instance) -> None:
    import signal
    inst.stopped = True
    for p in inst.procs:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            p.wait(timeout=3)
        except Exception:
            pass
