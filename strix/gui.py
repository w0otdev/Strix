# Copyright (c) 2026 w0otdev (Strix modifications)
# Licensed under the Apache License, Version 2.0.

"""A silent, achromatic workspace for files and Python projects."""

import ast
import os
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
import tokenize
from contextlib import suppress
from pathlib import Path
from tkinter import filedialog, ttk

from .context import VER
from .desktop import ROOT, BuildRequest, default_output, run_build, scan_project
from .motion import (
    ColorTransition,
    MotionProgress,
    mix,
    reduced_motion,
    set_reduced_motion,
    system_reduced_motion,
)
from .windowing import install_native_caption

PALETTE = {
    "background": "#202020",
    "panel": "#282828",
    "field": "#242424",
    "line": "#4a4a4a",
    "text": "#cccccc",
    "muted": "#aaaaaa",
    "accent": "#cccccc",
    "ink": "#202020",
    "band": "#282828",
}
SANS = "Segoe UI"
MONO = "Consolas"


def label(parent, text="", *, muted=False, size=11, mono=False, **options):
    return tk.Label(
        parent,
        text=text,
        bg=parent.cget("bg"),
        fg=PALETTE["muted" if muted else "text"],
        font=(MONO if mono else SANS, size),
        anchor="w",
        **options,
    )


class Action(tk.Button):
    def __init__(self, parent, text, command, *, primary=False, **options):
        self.primary = primary
        super().__init__(
            parent,
            text=text,
            command=command,
            relief="flat",
            borderwidth=0,
            bg=PALETTE["accent" if primary else "band"],
            fg=PALETTE["ink" if primary else "text"],
            activebackground=PALETTE["text"],
            activeforeground=PALETTE["ink"],
            disabledforeground=PALETTE["muted"],
            highlightthickness=1,
            highlightbackground=PALETTE["line"],
            highlightcolor=PALETTE["text"],
            font=(SANS, 10),
            cursor="hand2",
            padx=14,
            pady=7,
            takefocus=True,
            **options,
        )
        self.bind("<Enter>", self._enter)
        self.bind("<Leave>", self._leave)
        self.transition = ColorTransition(self)
        self.sync()

    def _enter(self, _event):
        if self.cget("state") != "disabled":
            self.transition.to({"bg": "#d4d4d4" if self.primary else PALETTE["line"]})

    def _leave(self, _event=None):
        self.sync(animate=True)

    def sync(self, *, animate=False):
        disabled = self.cget("state") == "disabled"
        colors = {
            "bg": PALETTE["accent" if self.primary and not disabled else "band"],
            "fg": PALETTE["muted" if disabled else "ink" if self.primary else "text"],
            "highlightbackground": PALETTE["line"],
        }
        # Switch polarity atomically; fading text and fill together loses contrast.
        if animate and self.cget("fg") != colors["fg"]:
            self.transition.cancel()
            self.configure(**colors)
            self.configure(highlightbackground=PALETTE["accent"])
            self.transition.to({"highlightbackground": PALETTE["line"]}, duration=180)
        else:
            self.transition.to(colors, duration=90 if animate else 0)


class Switch(tk.Frame):
    def __init__(self, parent, text, variable):
        super().__init__(parent, bg=parent.cget("bg"))
        self.variable = variable
        self.title = label(self, text, size=10)
        self.title.pack(side="left")
        self.button = Action(self, "", self.toggle, width=3)
        self.button.configure(padx=5, pady=4)
        self.button.pack(side="right")
        variable.trace_add("write", self.refresh)
        self.refresh()

    def toggle(self):
        self.variable.set(not self.variable.get())

    def refresh(self, *_args):
        self.button.primary = self.variable.get()
        self.button.configure(text="On" if self.variable.get() else "Off")
        self.button._leave()


class StrixApp:
    def __init__(
        self,
        root: tk.Tk,
        *,
        initial_file=None,
        output=None,
        mode=2,
        style="mine",
        protect=True,
        hide=True,
        more=True,
    ):
        self.root = root
        self.reduced_motion = tk.BooleanVar(root, system_reduced_motion())
        set_reduced_motion(root, self.reduced_motion.get())
        self.reduced_motion.trace_add("write", self._motion_changed)
        self.events = queue.Queue()
        self.cancel = threading.Event()
        self.process = None
        self.busy = False
        self.scanning = False
        self.scan_serial = 0
        self.is_folder = False
        self.saved_guards = protect
        self.started = 0.0
        self.last_output = None
        self.loaded_path = None
        self.messages = []
        self.record = None
        self.log_window = None
        self.source = tk.StringVar(root)
        self.output = tk.StringVar(root, output or "")
        self.mode = tk.IntVar(root, mode)
        self.style = tk.StringVar(root, style)
        self.protect = tk.BooleanVar(root, protect)
        self.hide = tk.BooleanVar(root, hide)
        self.more = tk.BooleanVar(root, more)
        self.status = tk.StringVar(root, "Choose a file or a project folder.")
        self.file_meta = tk.StringVar(root)
        self.output_label = tk.StringVar(root, "Output file")
        self.preview_title = tk.StringVar(root, "Preview")
        self.mode_hint = tk.StringVar(root)
        self.root.title("Strix")
        self.root.configure(bg=PALETTE["background"])
        self.root.geometry("1120x760")
        self.root.minsize(760, 650)
        self.root.tk.eval("proc bell {args} {}")
        self._theme()
        self._layout()
        self.mode.trace_add("write", self._mode_changed)
        self.style.trace_add("write", self._mode_changed)
        self.more.trace_add("write", self._mode_changed)
        self._mode_changed()
        self._resize_pending = None
        self._compact = None
        self.root.bind("<Configure>", self._schedule_layout, add="+")
        self.root.after_idle(self._responsive_layout)
        self.root.bind("<Control-o>", lambda _event: self.choose_source())
        self.root.bind("<Control-Shift-O>", lambda _event: self.choose_folder())
        self.root.bind("<Control-Shift-S>", lambda _event: self.choose_output())
        self.root.bind("<Control-Return>", lambda _event: self.build())
        self.root.bind("<Escape>", lambda _event: self.cancel_build())
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self._poll_handle = self.root.after(80, self._poll)
        install_native_caption(self.root)
        self.root.deiconify()
        self.root.lift()
        self.root.attributes("-topmost", True)
        self.root.after(200, lambda: self.root.attributes("-topmost", False))
        self.root.focus_force()
        if initial_file:
            self.source.set(str(initial_file))
            self.load_source(reset_output=not output)

    def _theme(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(
            "Strix.Horizontal.TProgressbar",
            troughcolor=PALETTE["field"],
            background=PALETTE["accent"],
            bordercolor=PALETTE["line"],
            lightcolor=PALETTE["accent"],
            darkcolor=PALETTE["accent"],
        )
        style.configure(
            "Strix.Vertical.TScrollbar",
            background=PALETTE["panel"],
            troughcolor=PALETTE["field"],
            bordercolor=PALETTE["field"],
            arrowcolor=PALETTE["text"],
            lightcolor=PALETTE["panel"],
            darkcolor=PALETTE["panel"],
        )
        style.map("Strix.Vertical.TScrollbar", background=[("active", PALETTE["line"])])
        style.configure(
            "Strix.Treeview",
            background=PALETTE["field"],
            fieldbackground=PALETTE["field"],
            foreground=PALETTE["text"],
            borderwidth=0,
            font=(SANS, 10),
            rowheight=26,
        )
        style.map(
            "Strix.Treeview",
            background=[("selected", PALETTE["accent"])],
            foreground=[("selected", PALETTE["ink"])],
        )

    def _entry(self, parent, variable):
        return tk.Entry(
            parent,
            textvariable=variable,
            bg=PALETTE["field"],
            fg=PALETTE["text"],
            insertbackground=PALETTE["text"],
            relief="flat",
            highlightthickness=1,
            highlightbackground=PALETTE["line"],
            highlightcolor=PALETTE["accent"],
            selectbackground=PALETTE["accent"],
            selectforeground=PALETTE["ink"],
            font=(SANS, 11),
            borderwidth=8,
        )

    def _text(self, parent, **options):
        return tk.Text(
            parent,
            wrap="word",
            bg=PALETTE["field"],
            fg=PALETTE["text"],
            insertbackground=PALETTE["text"],
            relief="flat",
            borderwidth=0,
            selectbackground=PALETTE["accent"],
            selectforeground=PALETTE["ink"],
            highlightthickness=1,
            highlightbackground=PALETTE["line"],
            highlightcolor=PALETTE["accent"],
            font=(MONO, 10),
            padx=12,
            pady=12,
            state="disabled",
            width=1,
            **options,
        )

    def _layout(self):
        shell = tk.Frame(self.root, bg=PALETTE["background"])
        shell.pack(fill="both", expand=True, padx=24, pady=18)
        shell.columnconfigure(0, weight=1)
        shell.rowconfigure(2, weight=1)
        toolbar = tk.Frame(shell, bg=PALETTE["background"])
        toolbar.grid(row=0, column=0, sticky="ew", pady=(0, 18))
        asset = ROOT / "assets" / "strix-logo-transparent.png"
        if asset.is_file():
            self.logo = tk.PhotoImage(file=str(asset))
            self.logo_small = self.logo.subsample(
                max(1, ( max(self.logo.width(), self.logo.height()) + 55) // 56)
            )
            tk.Label(
                toolbar, image=self.logo_small, bg=PALETTE["background"], borderwidth=0
            ).pack(side="left")
            self.root.iconphoto(True, self.logo_small)
        else:
            label(toolbar, "STRIX", size=22).pack(side="left")
        Action(toolbar, "Help", self.show_help).pack(side="right")
        Action(toolbar, "Build log", self.show_log).pack(side="right", padx=(0, 8))

        source = tk.Frame(shell, bg=PALETTE["background"])
        source.grid(row=1, column=0, sticky="ew", pady=(0, 16))
        source.columnconfigure(0, weight=1)
        label(source, "Source").grid(row=0, column=0, sticky="w", pady=(0, 6))
        label(source, textvariable=self.file_meta, size=10, muted=True, width=29).grid(
            row=0, column=1, columnspan=2, sticky="e"
        )
        self.source_entry = self._entry(source, self.source)
        self.source_entry.grid(row=1, column=0, sticky="ew", padx=(0, 8))
        self.source_entry.bind("<Return>", lambda _event: self.load_source())
        self.browse = Action(source, "Choose file", self.choose_source)
        self.browse.grid(row=1, column=1, padx=(0, 8))
        self.folder_button = Action(source, "Choose folder", self.choose_folder)
        self.folder_button.grid(row=1, column=2)

        workspace = tk.Frame(shell, bg=PALETTE["background"])
        self.workspace = workspace
        workspace.grid(row=2, column=0, sticky="nsew", pady=(0, 16))
        workspace.columnconfigure(0, weight=1)
        workspace.rowconfigure(0, weight=1)
        content = tk.Frame(workspace, bg=PALETTE["background"])
        self.content = content
        content.grid(row=0, column=0, sticky="nsew", padx=(0, 20))
        content.columnconfigure(0, weight=1)
        content.rowconfigure(1, weight=1)
        label(content, textvariable=self.preview_title, size=10, muted=True).grid(
            row=0, column=0, sticky="w", pady=(0, 8)
        )
        self.preview_container = tk.Frame(content, bg=PALETTE["background"])
        self.preview_container.grid(row=1, column=0, sticky="nsew")
        self.preview_container.columnconfigure(1, weight=1)
        self.preview_container.rowconfigure(0, weight=1)
        self.tree_frame = tk.Frame(self.preview_container, bg=PALETTE["field"])
        self.tree_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self.tree_frame.rowconfigure(0, weight=1)
        self.tree_frame.columnconfigure(0, weight=1)
        self.tree = ttk.Treeview(
            self.tree_frame, show="tree", selectmode="browse", style="Strix.Treeview"
        )
        self.tree.column("#0", width=180, minwidth=120)
        self.tree.grid(row=0, column=0, sticky="nsew")
        tree_scroll = ttk.Scrollbar(
            self.tree_frame, command=self.tree.yview, style="Strix.Vertical.TScrollbar"
        )
        tree_scroll.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=tree_scroll.set)
        self.tree.insert("", "end", iid="__empty__", text="No files selected")
        self.tree.bind("<<TreeviewSelect>>", self._tree_selected)
        self.preview = self._text(self.preview_container, height=1)
        self.preview_transition = ColorTransition(self.preview)
        self.preview.grid(row=0, column=1, sticky="nsew")
        scroll = ttk.Scrollbar(
            self.preview_container,
            command=self.preview.yview,
            style="Strix.Vertical.TScrollbar",
        )
        scroll.grid(row=0, column=2, sticky="ns")
        self.preview.configure(yscrollcommand=scroll.set)
        self._replace_text(
            self.preview,
            "Choose a Python file or project folder to preview its source.",
        )
        self._profile(workspace)

        destination = tk.Frame(shell, bg=PALETTE["background"])
        destination.grid(row=3, column=0, sticky="ew", pady=(0, 14))
        destination.columnconfigure(0, weight=1)
        label(destination, textvariable=self.output_label).grid(
            row=0, column=0, sticky="w", pady=(0, 6)
        )
        self.output_entry = self._entry(destination, self.output)
        self.output_entry.grid(row=1, column=0, sticky="ew", padx=(0, 8))
        self.save_as = Action(destination, "Choose...", self.choose_output)
        self.save_as.grid(row=1, column=1)

        actions = tk.Frame(shell, bg=PALETTE["background"])
        actions.grid(row=4, column=0, sticky="ew")
        actions.columnconfigure(0, weight=1)
        self.status_widget = label(
            actions,
            textvariable=self.status,
            size=10,
            muted=True,
            wraplength=420,
            height=2,
            width=1,
        )
        self.status_widget.grid(row=0, column=0, sticky="ew", padx=(0, 12))
        self.cancel_button = Action(
            actions, "Cancel", self.cancel_build, state="disabled", width=7
        )
        self.cancel_button.grid(row=0, column=2, padx=(0, 8))
        self.build_button = Action(
            actions, "Obfuscate", self.build, primary=True, width=13
        )
        self.build_button.grid(row=0, column=3)
        self.open_button = Action(
            actions, "Open output", self.open_output, state="disabled", width=10
        )
        self.open_button.grid(row=0, column=1, padx=(0, 8))
        self.progress = MotionProgress(shell, PALETTE)
        self.progress.grid(row=5, column=0, sticky="ew", pady=(10, 0))

    def _profile(self, parent):
        self.profile = tk.Frame(parent, bg=PALETTE["background"])
        self.mode_group = tk.Frame(self.profile, bg=PALETTE["background"])
        self.style_group = tk.Frame(self.profile, bg=PALETTE["background"])
        self.toggle_group = tk.Frame(self.profile, bg=PALETTE["background"])
        label(self.mode_group, "Protection").pack(anchor="w", pady=(0, 8))
        modes = tk.Frame(self.mode_group, bg=PALETTE["background"])
        modes.pack(fill="x")
        self.mode_buttons = []
        for index, title in enumerate(("Light", "Full", "Mega"), 1):
            button = Action(
                modes, title, lambda value=index: self.mode.set(value), width=6
            )
            button.configure(padx=6, pady=6)
            button.pack(
                side="left", expand=True, fill="x", padx=(0 if index == 1 else 5, 0)
            )
            self.mode_buttons.append(button)
        self.hint_widget = label(
            self.mode_group,
            textvariable=self.mode_hint,
            size=10,
            muted=True,
            wraplength=260,
            height=2,
            width=1,
            justify="left",
        )
        self.hint_widget.pack(fill="x", pady=(6, 0))
        label(self.style_group, "Runtime style", size=10, muted=True).pack(
            anchor="w", pady=(0, 8)
        )
        styles = tk.Frame(self.style_group, bg=PALETTE["background"])
        styles.pack(fill="x")
        self.style_buttons = []
        for title, value in (("Mineral", "mine"), ("Classic", "legacy")):
            button = Action(
                styles, title, lambda item=value: self.style.set(item), width=8
            )
            button.configure(padx=9, pady=6)
            button.pack(
                side="left",
                expand=True,
                fill="x",
                padx=(0 if value == "mine" else 6, 0),
            )
            self.style_buttons.append((button, value))
        self.switches = []
        for title, variable in (
            ("Runtime guards", self.protect),
            ("Hide builtins", self.hide),
            ("Extra obfuscation", self.more),
        ):
            self.switches.append(Switch(self.toggle_group, title, variable))

    def _schedule_layout(self, event):
        if event.widget is not self.root:
            return
        if self._resize_pending is not None:
            self.root.after_cancel(self._resize_pending)
        self._resize_pending = self.root.after(32, self._responsive_layout)

    def _responsive_layout(self):
        self._resize_pending = None
        compact = self.root.winfo_width() < 1000
        if compact != self._compact:
            self._compact = compact
            self.workspace.columnconfigure(1, minsize=0 if compact else 276)
            self.content.grid_configure(padx=(0, 0 if compact else 20))
            self.profile.grid(
                row=1 if compact else 0,
                column=0 if compact else 1,
                sticky="ew" if compact else "new",
                pady=(12, 0) if compact else 0,
            )
            self.profile.columnconfigure(0, weight=1)
            self.profile.columnconfigure(1, weight=1 if compact else 0)
            self.mode_group.grid(
                row=0, column=0, sticky="new", padx=(0, 16) if compact else 0
            )
            self.style_group.grid(
                row=0 if compact else 1,
                column=1 if compact else 0,
                sticky="new",
                pady=0 if compact else (12, 12),
            )
            self.toggle_group.grid(
                row=1 if compact else 2,
                column=0,
                columnspan=2 if compact else 1,
                sticky="ew",
                pady=(8, 0) if compact else 0,
            )
            for index, switch in enumerate(self.switches):
                self.toggle_group.columnconfigure(
                    index, weight=1 if compact or index == 0 else 0
                )
                switch.grid(
                    row=0 if compact else index,
                    column=index if compact else 0,
                    sticky="ew",
                    pady=4,
                    padx=(0, 14) if compact and index < 2 else 0,
                )
            self.tree.column("#0", width=150 if compact else 180)
        self.root.after_idle(self._wrap_text)

    def _wrap_text(self):
        self.hint_widget.configure(
            wraplength=max(180, self.mode_group.winfo_width() - 4)
        )
        self.status_widget.configure(
            wraplength=max(130, self.status_widget.winfo_width() - 4)
        )

    def _motion_changed(self, *_args):
        set_reduced_motion(self.root, self.reduced_motion.get())
        if hasattr(self, "progress"):
            self.progress.refresh_motion()
            pending: list[tk.Misc] = [self.root]
            while pending:
                widget = pending.pop()
                if isinstance(widget, Action):
                    widget.sync()
                pending.extend(widget.winfo_children())
            self.preview_transition.cancel()
            self.preview.configure(
                fg=PALETTE["text"], highlightbackground=PALETTE["line"]
            )

    def _mode_changed(self, *_args):
        if not self.more.get() or self.mode.get() == 1:
            hint = "Lightweight constant encoding."
        elif self.is_folder:
            hint = "Preserves imports and annotations. Runtime guards are off."
        elif self.mode.get() == 2:
            hint = "Encodes literals and transforms identifiers."
        else:
            hint = (
                "Fragments literals and applies extra transformations. Larger output."
            )
        self.mode_hint.set(hint)
        for index, button in enumerate(self.mode_buttons, 1):
            button.primary = index == self.mode.get()
            button._leave()
        for button, value in self.style_buttons:
            button.primary = value == self.style.get()
            button._leave()

    def choose_source(self):
        if self.busy:
            return
        path = filedialog.askopenfilename(
            parent=self.root,
            title="Choose Python file",
            filetypes=[("Python source", "*.py *.pyw"), ("All files", "*")],
        )
        if path:
            self.source.set(path)
            self.load_source()

    def choose_folder(self):
        if self.busy:
            return
        path = filedialog.askdirectory(
            parent=self.root, title="Choose project folder", mustexist=True
        )
        if path:
            self.source.set(path)
            self.load_source()

    def load_source(self, *, reset_output=True):
        self.scan_serial += 1
        self.scanning = False
        try:
            path = Path(self.source.get().strip().strip('"')).expanduser().resolve()
            if not path.is_file() and not path.is_dir():
                raise ValueError("Choose an existing file or folder.")
            folder = path.is_dir()
            if folder != self.is_folder:
                if folder:
                    self.saved_guards = self.protect.get()
                    self.protect.set(False)
                else:
                    self.protect.set(self.saved_guards)
            self.is_folder = folder
            self.loaded_path = path
            self.source.set(str(path))
            if reset_output:
                self.output.set(str(default_output(path)))
            self.output_label.set("Output folder" if folder else "Output file")
            self.switches[0].button.configure(state="disabled" if folder else "normal")
            self.switches[0].button.sync()
            self._mode_changed()
            if folder:
                self.scanning = True
                self.build_button.configure(state="disabled")
                self.status.set("Reading project files...")
                self.file_meta.set("")
                self._replace_text(self.preview, "Reading project files...")
                threading.Thread(
                    target=self._scan, args=(path, self.scan_serial), daemon=True
                ).start()
            else:
                self.tree.delete(*self.tree.get_children())
                self.tree.insert("", "end", iid=path.name, text=path.name)
                self.tree.selection_set(path.name)
                self._preview_file(path)
                self.status.set("Ready to obfuscate.")
                self.build_button.configure(state="normal")
        except (OSError, UnicodeError, SyntaxError, ValueError) as error:
            self._error(str(error))

    def _scan(self, path, serial):
        try:
            self.events.put(("scan", (serial, path, scan_project(path))))
        except OSError as error:
            self.events.put(("scan_error", (serial, str(error))))

    def _show_project(self, path, manifest):
        self.scanning = False
        self.build_button.configure(state="normal")
        self.tree.delete(*self.tree.get_children())
        inserted = set()
        for relative in manifest.python_files:
            parent = ""
            for index, part in enumerate(relative.parts):
                iid = Path(*relative.parts[: index + 1]).as_posix()
                if iid not in inserted:
                    self.tree.insert(parent, "end", iid=iid, text=part, open=index == 0)
                    inserted.add(iid)
                parent = iid
        count = len(manifest.python_files)
        self.file_meta.set(
            f"{count:,} Python files · {len(manifest.files) - count:,} other files"
        )
        if count:
            first = manifest.python_files[0].as_posix()
            self.tree.selection_set(first)
            self.tree.see(first)
            try:
                self._preview_file(path / manifest.python_files[0])
                self.status.set(
                    "Ready. Folder structure and supporting files will be preserved."
                )
            except (OSError, UnicodeError, SyntaxError) as error:
                self._replace_text(self.preview, str(error))
                self._error(str(error))
        else:
            self._replace_text(
                self.preview, "This folder contains no Python source files."
            )
            self.status.set("Choose a folder containing .py or .pyw files.")
            self.build_button.configure(state="disabled")

    def _tree_selected(self, _event):
        selected = self.tree.selection()
        if selected and self.loaded_path and self.is_folder:
            path = self.loaded_path / selected[0]
            if path.is_file():
                try:
                    self._preview_file(path)
                except (OSError, UnicodeError, SyntaxError) as error:
                    self._error(str(error))

    def _preview_file(self, path):
        with tokenize.open(path) as stream:
            source = stream.read()
        ast.parse(source, filename=str(path))
        text = source[:40000]
        if len(source) > 40000:
            text += "\n\nPreview shortened. The complete file will be compiled."
        self._replace_text(self.preview, text or "Empty Python file")
        if not reduced_motion(self.preview):
            self.preview.configure(
                fg=mix(PALETTE["field"], PALETTE["text"], 0.8),
                highlightbackground=mix(PALETTE["line"], PALETTE["accent"], 0.3),
            )
            self.preview_transition.to(
                {"fg": PALETTE["text"], "highlightbackground": PALETTE["line"]},
                duration=180,
            )
        self.preview_title.set(
            str(path.relative_to(self.loaded_path)) if self.is_folder else path.name
        )
        if not self.is_folder:
            self.file_meta.set(
                f"{len(source.splitlines()):,} lines · {path.stat().st_size:,} bytes"
            )

    def choose_output(self):
        if self.busy:
            return
        current = Path(self.output.get()) if self.output.get() else None
        if self.is_folder:
            path = filedialog.askdirectory(
                parent=self.root,
                title="Choose where to save the protected folder",
                mustexist=True,
            )
            if path and self.loaded_path:
                candidate = Path(path) / ("strix-" + self.loaded_path.name)
                index = 2
                while candidate.exists():
                    candidate = Path(path) / f"strix-{self.loaded_path.name}-{index}"
                    index += 1
                self.output.set(str(candidate))
            return
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Choose output file",
            defaultextension=".py",
            filetypes=[("Python script", "*.py")],
            confirmoverwrite=False,
            initialdir=str(current.parent) if current else None,
            initialfile=current.name if current else "protected.py",
        )
        if path:
            self.output.set(path)

    def build(self):
        if self.busy or self.scanning:
            return
        if not self.source.get().strip():
            self.status.set("Choose a file or project folder first.")
            self.source_entry.focus_set()
            return
        source = Path(self.source.get().strip().strip('"')).expanduser().resolve()
        if self.loaded_path != source:
            self.load_source(reset_output=not self.output.get().strip())
            if self.scanning:
                return
        try:
            if not self.output.get().strip():
                raise ValueError("Choose an output path.")
            output = Path(self.output.get().strip().strip('"')).expanduser().resolve()
            request = BuildRequest(
                source,
                output,
                self.mode.get(),
                self.style.get(),
                self.protect.get(),
                self.hide.get(),
                self.more.get(),
            )
            request.validate()
        except (OSError, ValueError) as error:
            self._error(str(error))
            return
        self.cancel.clear()
        self.busy = True
        self.process = None
        self.started = time.monotonic()
        self._set_busy(True)
        self.open_button.configure(state="disabled")
        self.open_button.sync()
        self.status.set("Obfuscating...")
        self.progress.start(indeterminate=not self.is_folder)
        self.log("Build", str(source))
        threading.Thread(
            target=run_build, args=(request, self.events, self.cancel), daemon=True
        ).start()

    def _set_busy(self, busy):
        state = "disabled" if busy else "normal"
        widgets = [
            self.build_button,
            self.browse,
            self.folder_button,
            self.save_as,
            self.source_entry,
            self.output_entry,
            *self.mode_buttons,
            *(button for button, _ in self.style_buttons),
            *(switch.button for switch in self.switches),
        ]
        for widget in widgets:
            widget.configure(state=state)
            if isinstance(widget, Action):
                widget.sync()
        if self.is_folder:
            self.switches[0].button.configure(state="disabled")
            self.switches[0].button.sync()
        self.cancel_button.configure(state="normal" if busy else "disabled")
        self.build_button.configure(text="Obfuscating..." if busy else "Obfuscate")
        self.cancel_button.sync()

    def cancel_build(self):
        if not self.busy:
            return
        self.cancel.set()
        if self.process is not None and self.process.poll() is None:
            with suppress(OSError):
                self.process.terminate()
        self.status.set("Cancelling. No unfinished build will be published.")

    def _poll(self):
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == "scan":
                    serial, path, manifest = value
                    if serial == self.scan_serial:
                        self._show_project(path, manifest)
                elif kind == "scan_error":
                    serial, message = value
                    if serial == self.scan_serial:
                        self.scanning = False
                        self.build_button.configure(state="normal")
                        self._error(message)
                elif kind == "process":
                    self.process = value
                    if self.cancel.is_set() and value.poll() is None:
                        with suppress(OSError):
                            value.terminate()
                elif kind == "log":
                    self.log("Engine", value)
                elif kind == "progress":
                    done, total, path = value
                    self.progress.update_progress(done, total)
                    if not self.cancel.is_set():
                        self.status.set(f"{done} of {total} files · {Path(path).name}")
                elif kind in ("done", "error", "cancelled"):
                    self.busy = False
                    self.process = None
                    self.progress.finish(success=kind == "done")
                    self._set_busy(False)
                    if kind == "done":
                        self.last_output = value
                        self.status.set(
                            f"Saved {value.name} · {time.monotonic() - self.started:.1f}s"
                        )
                        self.log("Saved", str(value))
                        self.open_button.configure(state="normal")
                        self.open_button.sync()
                    elif kind == "error":
                        self._error(value)
                    else:
                        self.status.set("Cancelled. No build was published.")
                        self.log("Cancelled", "Unfinished build discarded.")
        except queue.Empty:
            pass
        self._poll_handle = self.root.after(80, self._poll)

    def _error(self, message):
        summary = str(message).splitlines()[0]
        self.status.set(
            summary if len(summary) < 95 else "Build failed. See Build log for details."
        )
        self.log("Error", str(message))

    def log(self, kind, message):
        line = f"{time.strftime('%H:%M:%S')}  {kind}  {message}\n"
        self.messages.append(line)
        self.messages = self.messages[-500:]
        if self.record is not None:
            self._replace_text(self.record, "".join(self.messages))
            self.record.see("end")

    @staticmethod
    def _replace_text(widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def show_log(self):
        if self.log_window is not None and self.log_window.winfo_exists():
            self.log_window.deiconify()
            self.log_window.lift()
            return
        window = self.log_window = tk.Toplevel(self.root)
        install_native_caption(window)
        window.title("Build log")
        window.geometry("800x360")
        window.configure(bg=PALETTE["background"])
        window.protocol("WM_DELETE_WINDOW", window.withdraw)
        self.record = self._text(window)
        self.record.pack(fill="both", expand=True, padx=16, pady=(16, 8))
        self._replace_text(self.record, "".join(self.messages) or "No builds yet.")
        Action(window, "Copy log", self.copy_log).pack(
            anchor="e", padx=16, pady=(0, 12)
        )

    def show_help(self):
        window = tk.Toplevel(self.root)
        install_native_caption(window)
        window.title("Help")
        window.geometry("620x380")
        window.configure(bg=PALETTE["background"])
        text = self._text(window)
        text.configure(font=(SANS, 11))
        text.pack(fill="both", expand=True, padx=18, pady=18)
        self._replace_text(
            text,
            "Choose a file or a project folder, select an output path, then Obfuscate.\n\n"
            "Folder builds preserve directory structure, supporting files, module names, exports and annotations. Virtual environments, version control, build output and caches are excluded. Symbolic links are skipped. Single-file runtime guards are off for folders.\n\n"
            f"Run generated files with Python {VER}. Editing their contents invalidates the payload. Existing output paths are never overwritten.\n\n"
            "Ctrl+O: file    Ctrl+Shift+O: folder\nCtrl+Shift+S: output    Ctrl+Enter: obfuscate    Esc: cancel",
        )
        Switch(window, "Reduce motion", self.reduced_motion).pack(
            fill="x", padx=18, pady=(0, 18)
        )

    def copy_log(self):
        self.root.clipboard_clear()
        self.root.clipboard_append("".join(self.messages))

    def open_output(self):
        if self.last_output:
            folder = str(
                self.last_output
                if self.last_output.is_dir()
                else self.last_output.parent
            )
            try:
                if sys.platform == "win32":
                    os.startfile(folder)
                else:
                    subprocess.Popen(
                        ["open" if sys.platform == "darwin" else "xdg-open", folder]
                    )
            except OSError as error:
                self._error(str(error))

    def close(self):
        self.cancel_build()
        self.root.after_cancel(self._poll_handle)
        if self._resize_pending is not None:
            self.root.after_cancel(self._resize_pending)
        self.root.destroy()


def launch_gui(**options):
    root = tk.Tk()
    StrixApp(root, **options)
    root.mainloop()


if __name__ == "__main__":
    launch_gui()
