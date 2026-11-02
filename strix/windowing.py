"""Custom frameless Win32 windowing without WNDPROC subclassing."""

import ctypes
import sys
from ctypes import wintypes

_DRAG_STATE: dict[int, tuple[int, int]] = {}
_NORMAL_GEOM: dict[int, str] = {}

if sys.platform == "win32":
    _user32 = ctypes.WinDLL("user32", use_last_error=True)
    _dwmapi = ctypes.WinDLL("dwmapi", use_last_error=True)

    _user32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
    _user32.GetAncestor.restype = wintypes.HWND
    _user32.GetWindowLongW.argtypes = [wintypes.HWND, ctypes.c_int]
    _user32.GetWindowLongW.restype = wintypes.LONG
    _user32.SetWindowLongW.argtypes = [wintypes.HWND, ctypes.c_int, wintypes.LONG]
    _user32.SetWindowLongW.restype = wintypes.LONG
    _user32.SetWindowPos.argtypes = [
        wintypes.HWND,
        wintypes.HWND,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.UINT,
    ]
    _user32.SetWindowPos.restype = wintypes.BOOL
    _user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    _user32.ShowWindow.restype = wintypes.BOOL
    _user32.SystemParametersInfoW.argtypes = [
        wintypes.UINT,
        wintypes.UINT,
        ctypes.c_void_p,
        wintypes.UINT,
    ]
    _user32.SystemParametersInfoW.restype = wintypes.BOOL
    _dwmapi.DwmSetWindowAttribute.argtypes = [
        wintypes.HWND,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    _dwmapi.DwmSetWindowAttribute.restype = ctypes.c_long


def _root_hwnd(window) -> int:
    if sys.platform != "win32":
        return 0
    try:
        if not window.winfo_exists():
            return 0
        win_id = window.winfo_id()
    except Exception:  # noqa: BLE001
        return 0
    return int(_user32.GetAncestor(win_id, 2) or 0)


def start_window_drag(window, event):
    """Record pointer offset at the start of a header drag."""
    key = id(window)
    if key in _NORMAL_GEOM:
        return
    _DRAG_STATE[key] = (
        event.x_root - window.winfo_x(),
        event.y_root - window.winfo_y(),
    )


def move_window_drag(window, event):
    """Move the window smoothly during header drag."""
    key = id(window)
    if key in _NORMAL_GEOM or key not in _DRAG_STATE:
        return
    dx, dy = _DRAG_STATE[key]
    x = event.x_root - dx
    y = event.y_root - dy
    window.geometry(f"+{x}+{y}")


def drag_window(window, event=None):
    if event is not None:
        start_window_drag(window, event)


def minimize_window(window):
    try:
        window.overrideredirect(False)
        window.iconify()
    except Exception:  # noqa: BLE001
        hwnd = _root_hwnd(window)
        if hwnd:
            _user32.ShowWindow(wintypes.HWND(hwnd), 6)  # SW_MINIMIZE


def is_window_maximized(window) -> bool:
    return id(window) in _NORMAL_GEOM


def toggle_maximize_window(window) -> bool:
    key = id(window)
    if key in _NORMAL_GEOM:
        window.geometry(_NORMAL_GEOM.pop(key))
        return False
    _NORMAL_GEOM[key] = (
        f"{window.winfo_width()}x{window.winfo_height()}+{window.winfo_x()}+{window.winfo_y()}"
    )
    if sys.platform == "win32":
        work = wintypes.RECT()
        if _user32.SystemParametersInfoW(0x0030, 0, ctypes.byref(work), 0):  # SPI_GETWORKAREA
            w = work.right - work.left
            h = work.bottom - work.top
            window.geometry(f"{w}x{h}+{work.left}+{work.top}")
            return True
    sw, sh = window.winfo_screenwidth(), window.winfo_screenheight() - 48
    window.geometry(f"{sw}x{sh}+0+0")
    return True


def native_caption(window, *, background="#202020", foreground="#cccccc", frameless=None):
    if sys.platform != "win32":
        return False
    try:
        if not window.winfo_exists() or not window.winfo_ismapped():
            return False
    except Exception:  # noqa: BLE001
        return False
    if frameless is None:
        frameless = window.winfo_toplevel() is window and window.master is None
    hwnd = _root_hwnd(window)
    if not hwnd:
        return False

    def set_attribute(attribute, value):
        data = wintypes.DWORD(value)
        return (
            _dwmapi.DwmSetWindowAttribute(
                wintypes.HWND(hwnd), attribute, ctypes.byref(data), ctypes.sizeof(data)
            )
            == 0
        )

    def colorref(color):
        red, green, blue = (int(color[index : index + 2], 16) for index in (1, 3, 5))
        return red | (green << 8) | (blue << 16)

    if frameless:
        if not window.overrideredirect():
            window.overrideredirect(True)
            window.update_idletasks()
            hwnd = _root_hwnd(window)
            if not hwnd:
                return False
        exstyle = _user32.GetWindowLongW(wintypes.HWND(hwnd), -20)
        # Ensure Taskbar & Alt+Tab presence (WS_EX_APPWINDOW = 0x00040000, ~WS_EX_TOOLWINDOW = ~0x80)
        new_exstyle = (exstyle & ~0x00000080) | 0x00040000
        if new_exstyle != exstyle:
            _user32.SetWindowLongW(wintypes.HWND(hwnd), -20, new_exstyle)
            _user32.SetWindowPos(wintypes.HWND(hwnd), 0, 0, 0, 0, 0, 0x0027)

    dark = set_attribute(20, 1)  # DWMWA_USE_IMMERSIVE_DARK_MODE
    set_attribute(33, 2)  # DWMWA_WINDOW_CORNER_PREFERENCE = DWMWCP_ROUND
    set_attribute(34, colorref("#383838"))  # DWMWA_BORDER_COLOR
    set_attribute(35, colorref(background))  # DWMWA_CAPTION_COLOR
    set_attribute(36, colorref(foreground))  # DWMWA_TEXT_COLOR
    return dark


def install_native_caption(window):
    """Apply after every map, including restoration or recreation of Tk's frame."""

    def mapped(event):
        if event.widget is window:
            native_caption(window)

    window.bind("<Map>", mapped, add="+")
    if window.winfo_ismapped():
        native_caption(window)
