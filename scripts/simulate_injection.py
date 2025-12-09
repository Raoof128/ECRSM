#!/usr/bin/env python3
"""Synthetic ptrace attach demo for triggering injection rule.
This script is safe: it attaches to its own PID, pokes a register, and detaches.
"""

import os
import ctypes
import ctypes.util
import time

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
PTRACE_ATTACH = 16
PTRACE_DETACH = 17

pid = os.getpid()
print(f"[demo] self-ptrace attach to pid {pid}")

ret = libc.ptrace(PTRACE_ATTACH, pid, None, None)
if ret != 0:
    err = ctypes.get_errno()
    print(f"ptrace attach failed: {os.strerror(err)}")
else:
    # give kernel time to emit event
    time.sleep(0.5)
    print("detaching")
    libc.ptrace(PTRACE_DETACH, pid, None, None)

print("done")
