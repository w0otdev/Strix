"""Small, cancellable paint animations. Geometry never participates in motion."""

import ctypes
import math
import os
import sys
import time
import tkinter as tk
import weakref
from contextlib import suppress

DURATIONS = {"quick": 90, "standard": 180, "slow": 320}
_preferences = weakref.WeakKeyDictionary()


def system_reduced_motion():
    override = os.environ.get("STRIX_REDUCED_MOTION")
    if override is not None:
        return override.lower() in {"1", "true", "yes"}
    if sys.platform == "win32":
        animations = ctypes.c_int(1)
        if ctypes.windll.user32.SystemParametersInfoW(
            0x1042, 0, ctypes.byref(animations), 0
        ):
            return not bool(animations.value)
    return False


def set_reduced_motion(root, reduced):
    _preferences[root] = bool(reduced)


def reduced_motion(widget):
    root = widget
    while root.master is not None:
        root = root.master
    if root not in _preferences:
        _preferences[root] = system_reduced_motion()
    return _preferences[root]


def ease_out(value):
    return 1 - (1 - max(0.0, min(1.0, value))) ** 3


def mix(start, end, amount):
    a = tuple(int(start[index : index + 2], 16) for index in (1, 3, 5))
    b = tuple(int(end[index : index + 2], 16) for index in (1, 3, 5))
    return "#" + "".join(
        f"{round(x + (y - x) * amount):02x}" for x, y in zip(a, b, strict=True)
    )


class ColorTransition:
    def __init__(self, widget):
        self.widget = widget
        self.pending = None
        widget.bind("<Destroy>", lambda _event: self.cancel(), add="+")

    def cancel(self):
        if self.pending is not None:
            with suppress(tk.TclError):
                self.widget.after_cancel(self.pending)
            self.pending = None

    def to(self, colors, duration=DURATIONS["quick"]):
        self.cancel()
        if reduced_motion(self.widget) or duration == 0:
            self.widget.configure(**colors)
            return
        initial = {name: self.widget.cget(name) for name in colors}
        started = time.monotonic()

        def paint():
            self.pending = None
            if not self.widget.winfo_exists():
                return
            progress = min(1.0, (time.monotonic() - started) * 1000 / duration)
            if reduced_motion(self.widget):
                progress = 1.0
            self.widget.configure(
                **{
                    name: mix(initial[name], color, ease_out(progress))
                    for name, color in colors.items()
                }
            )
            if progress < 1:
                self.pending = self.widget.after(16, paint)

        paint()


class MotionProgress(tk.Canvas):
    """Reserved progress strip: eased fill, a moving light tip, and a quiet track pulse."""

    def __init__(self, parent, colors):
        super().__init__(
            parent,
            bg=colors["background"],
            height=6,
            highlightthickness=0,
            borderwidth=0,
        )
        self.colors = colors
        self.phase = "idle"
        self.current = 0.0
        self.target = 0.0
        self.from_value = 0.0
        self.changed = time.monotonic()
        self.started = self.changed
        self.pending = None
        self.bind("<Configure>", lambda _event: self._draw())
        self.bind("<Destroy>", lambda _event: self._cancel())

    def _cancel(self):
        if self.pending is not None:
            with suppress(tk.TclError):
                self.after_cancel(self.pending)
            self.pending = None

    def start(self, *, indeterminate):
        self._cancel()
        self.phase = "indeterminate" if indeterminate else "determinate"
        self.current = self.target = self.from_value = 0.0
        self.started = self.changed = time.monotonic()
        self._tick()

    def update_progress(self, done, total):
        self.from_value = self.current
        self.target = max(0.0, min(1.0, done / max(1, total)))
        self.changed = time.monotonic()
        if self.pending is None:
            self._tick()

    def finish(self, *, success):
        self._cancel()
        self.from_value = self.current
        self.target = 1.0 if success else self.current
        self.phase = "success" if success else "stopped"
        self.changed = time.monotonic()
        self._tick()

    def refresh_motion(self):
        self._cancel()
        self._tick()

    def _tick(self):
        self.pending = None
        self._draw()
        if self.phase != "idle":
            if reduced_motion(self) and self.phase in {"determinate", "indeterminate"}:
                return
            delay = 120 if reduced_motion(self) else 16
            self.pending = self.after(delay, self._tick)

    def _draw(self):
        self.delete("all")
        if self.phase == "idle":
            return
        now = time.monotonic()
        elapsed = now - self.changed
        reduced = reduced_motion(self)
        width = max(1, self.winfo_width())
        height = self.winfo_height()
        background, ink = self.colors["background"], self.colors["accent"]
        # The ambient layer stays inside the reserved strip, never behind controls.
        pulse = (
            0.0 if reduced else (math.sin((now - self.started) * math.pi) + 1) * 0.025
        )
        track = mix(background, self.colors["line"], 0.35 + pulse)
        self.create_rectangle(0, 0, width, height, fill=track, outline="")
        fade = 1.0
        if self.phase in {"success", "stopped"}:
            if elapsed > 0.9:
                self.phase = "idle"
                self.delete("all")
                return
            fade = max(0.0, 1 - max(0.0, elapsed - 0.45) / 0.45)
        if self.phase == "indeterminate":
            if reduced:
                return  # Static track plus the textual busy state, with no autoplay.
            span = max(18, width * 0.18)
            head = ((now - self.started) % 1.8) / 1.8 * (width + span)
            for index in range(12):
                left = max(0, head - span + span * index / 12)
                right = min(width, head - span + span * (index + 1) / 12)
                if right > left:
                    self.create_rectangle(
                        left,
                        0,
                        right,
                        height,
                        fill=mix(track, ink, (index + 1) / 12),
                        outline="",
                    )
            return
        progress = 1.0 if reduced else ease_out(min(1.0, elapsed / 0.18))
        self.current = self.from_value + (self.target - self.from_value) * progress
        end = width * self.current
        self.create_rectangle(
            0, 0, end, height, fill=mix(background, ink, fade * 0.8), outline=""
        )
        if end > 0:
            self.create_rectangle(
                max(0, end - 8),
                0,
                end,
                height,
                fill=mix(background, ink, fade),
                outline="",
            )
