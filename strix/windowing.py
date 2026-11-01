"""Theme the real Windows caption without replacing its controls or hit testing."""

import ctypes
import sys
from ctypes import wintypes


def native_caption(window, *, background="#202020", foreground="#cccccc"):
    if sys.platform != "win32" or not window.winfo_ismapped():
        return False
    try:
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        dwmapi = ctypes.WinDLL("dwmapi", use_last_error=True)
    except OSError:
        return False
    user32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
    user32.GetAncestor.restype = wintypes.HWND
    dwmapi.DwmSetWindowAttribute.argtypes = [
        wintypes.HWND,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    dwmapi.DwmSetWindowAttribute.restype = ctypes.c_long
    # Tk's client HWND is not the native top-level frame HWND.
    hwnd = user32.GetAncestor(window.winfo_id(), 2)  # GA_ROOT
    if not hwnd:
        return False

    def set_attribute(attribute, value):
        data = wintypes.DWORD(value)
        return (
            dwmapi.DwmSetWindowAttribute(
                hwnd, attribute, ctypes.byref(data), ctypes.sizeof(data)
            )
            == 0
        )

    def colorref(color):
        red, green, blue = (int(color[index : index + 2], 16) for index in (1, 3, 5))
        return red | (green << 8) | (blue << 16)

    dark = set_attribute(20, 1)  # DWMWA_USE_IMMERSIVE_DARK_MODE
    # Older Windows versions can reject these colors and still keep a native caption.
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
