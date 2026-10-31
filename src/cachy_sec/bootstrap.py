"""Entry point / supervisor: starts the app, preferring a verified downloaded update.

If an updated version crashes right after start it is discarded and the packaged version runs.
Exit code 75 from the app means "restart me" (used to apply an update).
"""
from __future__ import annotations

import os
import subprocess
import sys
import time

from . import __version__, updater

CRASH_WINDOW_S = 30


def main() -> int:
    while True:
        env = dict(os.environ, **{updater.SUPERVISED_ENV: "1"})  # tells the app it may exit with 75 to be restarted
        overlay = updater.installed_overlay()
        use = bool(overlay and (updater.parse_version(overlay[0]) or ()) > (updater.parse_version(__version__) or ()))
        if use:
            env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(overlay[1]), env.get("PYTHONPATH", "")]))
        elif overlay:
            updater.discard_overlay()  # packaged version caught up or passed it
        started = time.monotonic()
        rc = subprocess.run([sys.executable, "-m", "cachy_sec"], env=env).returncode
        if rc == updater.RESTART_EXIT_CODE:
            continue
        if use and rc != 0 and time.monotonic() - started < CRASH_WINDOW_S:
            updater.discard_overlay()
            continue
        return rc


if __name__ == "__main__":
    sys.exit(main())
