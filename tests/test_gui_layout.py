import ctypes
import sys
import tempfile
import time
import tkinter as tk
import unittest
from ctypes import wintypes
from pathlib import Path

from strix.desktop import scan_project
from strix.gui import StrixApp
from strix.motion import ease_out, mix


class GuiLayoutTests(unittest.TestCase):
    def setUp(self):
        try:
            self.root = tk.Tk()
        except tk.TclError as error:
            self.skipTest(str(error))
        # Allocate real widget geometry without displaying a test window to the user.
        self.root.withdraw()
        self.root.attributes("-alpha", 0)
        self.app = StrixApp(self.root)
        self.root.geometry("1120x760+10000+10000")
        self.root.deiconify()
        self.root.update()
        self.errors = []
        self.root.report_callback_exception = lambda *error: self.errors.append(error)

    def tearDown(self):
        if hasattr(self, "root"):
            self.app.close()

    def settle(self):
        self.root.update()
        self.app._responsive_layout()
        self.root.update_idletasks()

    def controls(self):
        return [
            self.app.source_entry,
            self.app.browse,
            self.app.folder_button,
            self.app.output_entry,
            self.app.save_as,
            self.app.open_button,
            self.app.cancel_button,
            self.app.build_button,
            self.app.preview,
            *self.app.mode_buttons,
            *(button for button, _ in self.app.style_buttons),
            *(switch.button for switch in self.app.switches),
        ]

    def boxes(self):
        return [
            (
                widget.winfo_rootx() - self.root.winfo_rootx(),
                widget.winfo_rooty() - self.root.winfo_rooty(),
                widget.winfo_width(),
                widget.winfo_height(),
            )
            for widget in self.controls()
        ]

    def test_supported_sizes_keep_controls_inside_window_and_stable(self):
        for width, height in ((760, 650), (960, 680), (1120, 760), (1440, 1000)):
            with self.subTest(width=width, height=height):
                self.root.geometry(f"{width}x{height}+10000+10000")
                self.settle()
                baseline = self.boxes()
                for left, top, box_width, box_height in baseline:
                    self.assertGreaterEqual(left, 0)
                    self.assertGreaterEqual(top, 0)
                    self.assertLessEqual(left + box_width, self.root.winfo_width())
                    self.assertLessEqual(top + box_height, self.root.winfo_height())
                    self.assertGreater(box_width, 20)
                    self.assertGreater(box_height, 18)
                for mode in (1, 2, 3):
                    self.app.mode.set(mode)
                    self.app.build_button._enter(None)
                    self.app._set_busy(True)
                    self.app.progress.start(indeterminate=True)
                    self.app.status.set(
                        "Obfuscating a project with a longer status message."
                    )
                    self.settle()
                    self.assertEqual(self.boxes(), baseline)
                    self.app._set_busy(False)
                    self.app.progress.finish(success=True)
                    self.app.open_button.configure(state="normal")
                    self.settle()
                    self.assertEqual(self.boxes(), baseline)
        self.assertEqual(self.errors, [])

    def test_file_folder_switch_does_not_reflow_controls(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "project"
            source.mkdir()
            script = source / "main.py"
            script.write_text("print('hello')\n", encoding="utf-8")
            for width in (760, 1120):
                self.root.geometry(f"{width}x760+10000+10000")
                self.app.source.set(str(script))
                self.app.load_source()
                self.settle()
                baseline = self.boxes()
                self.app.source.set(str(source))
                self.app.load_source()
                self.app._show_project(source, scan_project(source))
                self.settle()
                self.assertEqual(self.boxes(), baseline)
        self.assertEqual(self.errors, [])

    def test_reduced_motion_stops_continuous_animation_and_preserves_progress(self):
        self.app.reduced_motion.set(True)
        self.app.build_button._enter(None)
        self.assertIsNone(self.app.build_button.transition.pending)
        self.app.progress.start(indeterminate=True)
        self.assertIsNone(self.app.progress.pending)
        self.app.progress.start(indeterminate=False)
        self.app.progress.update_progress(3, 4)
        self.assertEqual(self.app.progress.current, 0.75)
        self.assertIsNone(self.app.progress.pending)
        self.app.reduced_motion.set(False)
        self.app.progress.start(indeterminate=True)
        self.assertIsNotNone(self.app.progress.pending)
        self.app.reduced_motion.set(True)
        self.assertIsNone(self.app.progress.pending)

    def test_animation_completes_without_geometry_changes(self):
        self.app.reduced_motion.set(False)
        baseline = self.boxes()
        self.app.build_button._enter(None)
        deadline = time.monotonic() + 0.3
        while time.monotonic() < deadline:
            self.root.update()
            time.sleep(0.005)
        self.assertEqual(self.boxes(), baseline)
        self.assertIsNone(self.app.build_button.transition.pending)
        self.assertEqual(self.errors, [])

    @unittest.skipUnless(sys.platform == "win32", "Windows native caption")
    def test_native_caption_preserves_window_controls_and_restoration(self):
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        dwmapi = ctypes.WinDLL("dwmapi", use_last_error=True)
        user32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
        user32.GetAncestor.restype = wintypes.HWND
        user32.GetWindowLongW.argtypes = [wintypes.HWND, ctypes.c_int]
        user32.GetWindowLongW.restype = wintypes.LONG
        dwmapi.DwmGetWindowAttribute.argtypes = [
            wintypes.HWND,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        dwmapi.DwmGetWindowAttribute.restype = ctypes.c_long

        def check_caption():
            hwnd = user32.GetAncestor(self.root.winfo_id(), 2)
            style = user32.GetWindowLongW(hwnd, -16)
            for flag in (0x00C00000, 0x00080000, 0x00040000, 0x00020000, 0x00010000):
                self.assertEqual(style & flag, flag)
            dark = wintypes.BOOL()
            status = dwmapi.DwmGetWindowAttribute(
                hwnd, 20, ctypes.byref(dark), ctypes.sizeof(dark)
            )
            self.assertEqual(status, 0)
            self.assertTrue(dark.value)
            self.assertFalse(self.root.overrideredirect())

        check_caption()
        self.root.iconify()
        self.root.update()
        self.root.deiconify()
        self.root.update()
        check_caption()


class MotionMathTests(unittest.TestCase):
    def test_easing_and_palette_stay_bounded(self):
        values = [ease_out(index / 100) for index in range(101)]
        self.assertEqual(values, sorted(values))
        self.assertEqual((values[0], values[-1]), (0, 1))
        for value in values:
            color = mix("#202020", "#cccccc", value)
            self.assertEqual(color[1:3], color[3:5])
            self.assertEqual(color[3:5], color[5:7])
            self.assertNotIn(color, ("#000000", "#ffffff"))


if __name__ == "__main__":
    unittest.main()
