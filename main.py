#!/usr/bin/env python3
"""
AD Recon TUI — passive log pane + command bar.
Wraps netexec/smbclient/impacket. Curses-based, no external deps.

Usage: python3 recon_tui.py -t <dc-ip>
"""

import curses
import threading
import queue
import subprocess
import re
import time
import argparse
from datetime import datetime
from dataclasses import dataclass
from enum import Enum


# ---------------------------------------------------------------------------
# Logging primitives
# ---------------------------------------------------------------------------

class Level(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    DANGEROUS = "DANGEROUS"


@dataclass
class LogLine:
    ts: str
    level: Level
    msg: str

    def render(self) -> str:
        return f"[{self.ts}] [{self.level.value}] {self.msg}"


class App:
    def __init__(self, target_ip: str):
        self.log_q: "queue.Queue[LogLine]" = queue.Queue()
        self.scrollback: list[LogLine] = []
        self.running = True
        self.target = target_ip       # this is the IP we connect to
        self.domain = None            # discovered via bootstrap
        self.hostname = None
        self.username = None
        self.password = None
        self.smb_signing = None
        self.scroll_offset = 0
        self.lock = threading.Lock()

    def log(self, level: Level, msg: str):
        line = LogLine(ts=datetime.now().strftime("%H:%M:%S"), level=level, msg=msg)
        self.log_q.put(line)

    def info(self, msg): self.log(Level.INFO, msg)
    def warn(self, msg): self.log(Level.WARNING, msg)
    def danger(self, msg): self.log(Level.DANGEROUS, msg)


def run_cmd(cmd: list[str], timeout: int = 60) -> tuple[str, str, int]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except FileNotFoundError:
        return "", f"COMMAND NOT FOUND: {cmd[0]}", -1


# ---------------------------------------------------------------------------
# Recon functions
# ---------------------------------------------------------------------------

def task_bootstrap(app: App, target: str, domain: str = ""):
    """
    Runs automatically at startup. Plain `nxc smb <ip>` to fingerprint the
    host and pull the domain name before anything else happens.
    """
    app.info(f"Bootstrapping — running nxc smb {target} ...")
    stdout, stderr, rc = run_cmd(["nxc", "smb", target])

    if rc == -1:
        app.danger(f"nxc smb failed to run: {stderr.strip()}  (is netexec/nxc installed & on PATH?)")
        return

    # Typical line:
    # SMB  10.10.11.50  445  DC01  [*] Windows 10 / Server 2019 Build 17763 x64
    #      (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)
    m = re.search(
        r"\[\*\]\s+(.*?)\s+\(name:(\S+)\)\s+\(domain:(\S+)\)\s+\(signing:(\w+)\)",
        stdout,
    )
    if not m:
        app.warn("Bootstrap ran but couldn't parse nxc output — is the host up / port 445 open?")
        if stdout.strip():
            app.info(f"Raw nxc output: {stdout.strip()[:200]}")
        return

    os_info, hostname, domain_found, signing = m.groups()
    app.hostname = hostname
    app.domain = domain_found
    app.smb_signing = signing == "True"

    app.info(f"Target resolved: {target} -> hostname={hostname} domain={domain_found}")
    app.info(f"OS fingerprint: {os_info}")

    if not app.smb_signing:
        app.danger(f"SMB signing is DISABLED on {target} — relay attacks may be possible")
    else:
        app.info("SMB signing: enabled")

    app.info("Bootstrap complete. Domain/hostname set — try 'smbnull' next.")


def task_smb_null_session_enum(app: App, target: str, domain: str = ""):
    """Step 1: Null session / anonymous SMB enumeration + share listing."""
    app.info(f"Starting SMB null-session enumeration against {target}")

    app.info("Testing null session (empty user/pass)...")
    stdout, stderr, rc = run_cmd(["nxc", "smb", target, "-u", "", "-p", ""])
    null_ok = "[+]" in stdout
    app.danger(f"NULL SESSION ACCEPTED on {target}") if null_ok else app.info("Null session rejected")

    app.info("Testing guest account (no password)...")
    stdout, stderr, rc = run_cmd(["nxc", "smb", target, "-u", "guest", "-p", ""])
    guest_ok = "[+]" in stdout
    app.danger(f"GUEST SESSION ACCEPTED on {target}") if guest_ok else app.info("Guest session rejected")

    if not (null_ok or guest_ok):
        app.warn("No anonymous access available — share enum needs valid creds")
        app.info("SMB null-session enumeration complete")
        return

    user = "guest" if (guest_ok and not null_ok) else ""
    app.info(f"Enumerating shares as '{user or 'null'}'...")
    stdout, stderr, rc = run_cmd(["nxc", "smb", target, "-u", user, "-p", "", "--shares"])

    found_any = False
    for line in stdout.splitlines():
        m = re.search(
            r"^\S+\s+\S+\s+\d+\s+\S+\s+(READ,WRITE|READ|WRITE|NO ACCESS)\s+(\S+)\s*(.*)$",
            line.strip(),
        )
        if m:
            perms, name, comment = m.groups()
            found_any = True
            if "WRITE" in perms:
                app.danger(f"Share '{name}' is WRITABLE ({perms}) — {comment.strip()}")
            elif "READ" in perms:
                app.warn(f"Share '{name}' is readable ({perms}) — {comment.strip()}")
            else:
                app.info(f"Share '{name}': {perms}")

    if not found_any:
        app.warn("No shares parsed from nxc output (check raw output / version)")

    app.info("SMB null-session enumeration complete")


TASKS = {
    "smbnull": task_smb_null_session_enum,
    # future: "ridcycle": task_rid_cycle, "shares": task_share_content, ...
}


# ---------------------------------------------------------------------------
# Curses TUI
# ---------------------------------------------------------------------------

COLOR_MAP = {}


def init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_CYAN, -1)
    curses.init_pair(2, curses.COLOR_YELLOW, -1)
    curses.init_pair(3, curses.COLOR_RED, -1)
    curses.init_pair(4, curses.COLOR_GREEN, -1)
    COLOR_MAP[Level.INFO] = curses.color_pair(1)
    COLOR_MAP[Level.WARNING] = curses.color_pair(2) | curses.A_BOLD
    COLOR_MAP[Level.DANGEROUS] = curses.color_pair(3) | curses.A_BOLD


def draw(stdscr, app: App, input_buf: str):
    stdscr.erase()
    h, w = stdscr.getmaxyx()
    feed_h = h - 3

    with app.lock:
        lines = app.scrollback[-feed_h:] if app.scroll_offset == 0 else \
            app.scrollback[max(0, len(app.scrollback) - feed_h - app.scroll_offset):
                            len(app.scrollback) - app.scroll_offset]

    for i, line in enumerate(lines):
        text = line.render()[: w - 1]
        try:
            stdscr.addstr(i, 0, text, COLOR_MAP.get(line.level, curses.A_NORMAL))
        except curses.error:
            pass

    try:
        stdscr.addstr(feed_h, 0, "─" * (w - 1))
    except curses.error:
        pass

    status = f" target={app.target or '-'}  domain={app.domain or '-'} username={app.username} password={app.password}  host={app.hostname or '-'}  lines={len(app.scrollback)} "
    try:
        stdscr.addstr(feed_h + 1, 0, status[: w - 1], curses.A_DIM)
    except curses.error:
        pass

    prompt = "> "
    try:
        stdscr.addstr(h - 1, 0, (prompt + input_buf)[: w - 1], curses.color_pair(4))
    except curses.error:
        pass

    stdscr.refresh()


def dispatch_command(app: App, cmd: str):
    cmd = cmd.strip()
    if not cmd:
        return
    parts = cmd.split()
    verb = parts[0].lower()

    if verb in ("quit", "exit", "q"):
        app.running = False
        return

    if verb == "set" and len(parts) == 3 and parts[1] in ("target", "domain","username","password"):
        setattr(app, parts[1], parts[2])
        app.info(f"Set {parts[1]} = {parts[2]}")
        return

    if verb in TASKS:
        fn = TASKS[verb]
        t = threading.Thread(target=fn, args=(app, app.target, app.domain or ""), daemon=True)
        t.start()
        return

    app.warn(f"Unknown command: '{cmd}'  (try: smbnull, set domain <name>, quit)")


def main(stdscr, target_ip: str):
    curses.curs_set(1)
    stdscr.nodelay(True)
    init_colors()

    app = App(target_ip)
    app.info(f"AD Recon TUI ready. Target={target_ip}")

    # Kick off bootstrap immediately, in background, so UI is responsive
    # even while nxc is running.
    threading.Thread(target=task_bootstrap, args=(app, target_ip), daemon=True).start()

    input_buf = ""

    while app.running:
        while True:
            try:
                line = app.log_q.get_nowait()
            except queue.Empty:
                break
            with app.lock:
                app.scrollback.append(line)

        draw(stdscr, app, input_buf)

        try:
            ch = stdscr.getch()
        except curses.error:
            ch = -1

        if ch == -1:
            time.sleep(0.05)
            continue

        if ch in (curses.KEY_ENTER, 10, 13):
            dispatch_command(app, input_buf)
            input_buf = ""
        elif ch in (curses.KEY_BACKSPACE, 127, 8):
            input_buf = input_buf[:-1]
        elif ch == curses.KEY_UP:
            app.scroll_offset += 1
        elif ch == curses.KEY_DOWN:
            app.scroll_offset = max(0, app.scroll_offset - 1)
        elif 32 <= ch <= 126:
            input_buf += chr(ch)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AD Recon TUI")
    parser.add_argument("-t", "--target", required=True, help="DC IP address")
    args = parser.parse_args()

    curses.wrapper(main, args.target)