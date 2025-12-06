"""perf_counter.py

Provides an in-process CPU cycle counter using Linux perf_event_open (via ctypes).
Supports x86_64 and ARM (ARMv7/ARMv8) architectures. Raises an error on unsupported
architectures.

API:
  PerfCounter(arch=None).measure_callable(func, *args, **kwargs) -> (cycles, retval)
  
  arch: optional string to override architecture detection. Supported: "x86_64", "armv7", "armv8"

Notes:
 - Uses kernel perf_event_open syscall for accurate cycle counting.
 - Cycle counts are returned as integers.
 - Raises RuntimeError if the platform is not x86_64, ARMv7, or ARMv8.
 - Pass arch parameter to override auto-detection, e.g., PerfCounter(arch="x86_64")
"""
from __future__ import annotations
import ctypes
import os
import time
import sys
import typing
import platform

try:
    import psutil
except Exception:
    psutil = None

libc = ctypes.CDLL("libc.so.6", use_errno=True)

# Common constants
PERF_TYPE_HARDWARE = 0
PERF_COUNT_HW_CPU_CYCLES = 0

# Detect architecture and set correct syscall number for perf_event_open
def _get_perf_event_open_syscall(arch: typing.Optional[str] = None) -> int:
    """Return the correct perf_event_open syscall number for the given architecture.
    
    Args:
        arch: optional architecture string. If None, uses platform.machine().
              Supported: "x86_64", "armv7", "armv8"
    
    Returns:
        syscall number (int)
    
    Raises:
        RuntimeError if architecture is unsupported.
    """
    if arch is None:
        machine = platform.machine()
    else:
        machine = arch.lower()
    
    if machine in ("x86_64", "amd64"):
        return 298  # x86_64
    elif machine in ("armv7l", "armv7"):
        return 364  # ARMv7 (32-bit)
    elif machine in ("aarch64", "arm64", "armv8"):
        return 241  # ARMv8 (64-bit)
    else:
        raise RuntimeError(
            f"Unsupported architecture: {machine}. "
            f"perf_counter only supports x86_64, armv7, and armv8."
        )

# Default: detect from platform
SYS_perf_event_open = _get_perf_event_open_syscall()

class perf_event_attr(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint32),
        ("size", ctypes.c_uint32),
        ("config", ctypes.c_uint64),
        ("sample_period", ctypes.c_uint64),
        ("sample_type", ctypes.c_uint64),
        ("read_format", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
        ("wakeup_events", ctypes.c_uint32),
        ("bp_type", ctypes.c_uint32),
        ("bp_addr", ctypes.c_uint64),
        ("bp_len", ctypes.c_uint64),
    ]


class PerfCounter:
    """In-process CPU cycle counter using perf_event_open.

    Usage:
      pc = PerfCounter(arch="x86_64")  # or "armv7", "armv8"
      cycles, result = pc.measure_callable(func, *args, **kwargs)

    Uses kernel perf_event_open syscall to count CPU cycles. Supports x86_64 and ARM.
    Raises RuntimeError if the platform is unsupported.
    
    Args:
        arch: optional architecture string to override auto-detection.
              Supported: "x86_64", "armv7", "armv8"
    """

    def __init__(self, arch: typing.Optional[str] = None) -> None:
        self.fd: typing.Optional[int] = None
        # Allow runtime override of architecture
        if arch is not None:
            self.sys_perf_event_open = _get_perf_event_open_syscall(arch)
        else:
            self.sys_perf_event_open = SYS_perf_event_open


    def _open_counter(self) -> int:
        # Build perf_event_attr with minimal fields filled
        attr = perf_event_attr()
        ctypes.memset(ctypes.byref(attr), 0, ctypes.sizeof(attr))
        attr.type = PERF_TYPE_HARDWARE
        attr.size = ctypes.sizeof(attr)
        attr.config = PERF_COUNT_HW_CPU_CYCLES
        # pid 0 -> current process; cpu -1 -> any; group_fd -1
        fd = libc.syscall(self.sys_perf_event_open, ctypes.byref(attr), 0, -1, -1, 0)
        if fd == -1:
            err = ctypes.get_errno()
            raise OSError(err, "perf_event_open syscall failed")
        return int(fd)

    def _read_fd(self, fd: int) -> int:
        # read 8 bytes from fd
        data = os.read(fd, 8)
        if not data or len(data) < 8:
            raise OSError("short read from perf fd")
        return int.from_bytes(data, "little")

    def measure_callable(self, func: typing.Callable, *args, **kwargs):
        """Measure cycles spent executing func(*args, **kwargs).

        Returns (cycles, retval). Uses perf_event_open if available, otherwise
        falls back to cycle estimation from wall time and CPU frequency.
        """
        try:
            fd = self._open_counter()
            try:
                # read initial counter
                before = self._read_fd(fd)
                retval = func(*args, **kwargs)
                after = self._read_fd(fd)
                cycles = after - before
                return cycles, retval
            finally:
                try:
                    os.close(fd)
                except Exception:
                    pass
        except (OSError, PermissionError) as e:
            # perf_event_open failed; fall back to estimation
            print(
                f"perf_event_open failed ({e}); falling back to cycle estimation",
                file=sys.stderr,
            )
            return self._estimate_cycles(func, *args, **kwargs)

    def _estimate_cycles(self, func: typing.Callable, *args, **kwargs):
        """Estimate cycles from wall time and CPU frequency."""
        t0 = time.perf_counter()
        retval = func(*args, **kwargs)
        t1 = time.perf_counter()
        elapsed = t1 - t0
        freq = None
        if psutil:
            try:
                cf = psutil.cpu_freq()
                if cf and cf.current:
                    freq = cf.current * 1e6
            except Exception:
                freq = None
        if not freq:
            # Fallback: assume 2.5 GHz
            freq = 2.5e9
        cycles = int(elapsed * freq)
        return cycles, retval


# Convenience function
def measure_callable(func: typing.Callable, *args, **kwargs):
    pc = PerfCounter()
    return pc.measure_callable(func, *args, **kwargs)
