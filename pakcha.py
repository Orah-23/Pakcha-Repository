# ====================================================================
# Author: Francois Oratie Kgatlhanye
# Date: 2026-09-03
# Description: Personalised Packet Capture Application for Windows
# ====================================================================

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from scapy.all import (
    AsyncSniffer,
    conf,
    ARP,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    DNS,
    DNSQR,
    get_if_addr,
    rdpcap,
    wrpcap,
)
import threading
import queue
from datetime import datetime


# COLOR PALETTE
COLOR_BG = "#FBF3E4"
COLOR_BG_ALT = "#F3E5CC"
COLOR_PRIMARY = "#A9773F"
COLOR_PRIMARY_DARK = "#7C5527"
COLOR_PRIMARY_LIGHT = "#D9B77C"
COLOR_ACCENT = "#C98F3B"
COLOR_TEXT = "#3E2C17"
COLOR_TEXT_MUTED = "#7A6A52"
COLOR_HEADER_BG = "#8C6437"
COLOR_HEADER_TEXT = "#FFF8EC"
COLOR_ROW_ALT = "#F6E9D3"
COLOR_SELECT_BG = "#E4B96A"
COLOR_BORDER = "#D8C09A"
COLOR_WHITE_PANEL = "#FFFDF8"


class PakchaApp:

    # INITIALIZATION
    def __init__(self, root):

        self.root = root

        self.root.title("Pakcha - Network Packet Capture")
        self.root.geometry("1250x750")
        self.root.minsize(950, 600)
        self.root.configure(bg=COLOR_BG)

        # Application state
        self.sniffer = None

        self.capturing = False
        self.stopping = False

        self.packet_number = 0

        self.packets = []

        self.packet_queue = queue.Queue()

        self.lock = threading.RLock()

        self.interfaces = []

        self.current_pcap_path = None

        # Build application
        self.configure_styles()
        self.build_menu()
        self.build_ui()

        self.load_interfaces()

        # Process packets waiting for GUI
        self.root.after(
            50,
            self.process_packet_queue
        )

        # Clean shutdown
        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.on_close
        )

    # STYLES
    def configure_styles(self):

        style = ttk.Style(self.root)

        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        default_font = ("Segoe UI", 10)
        heading_font = ("Segoe UI Semibold", 10)
        title_font = ("Segoe UI Semibold", 11)

        self.root.option_add(
            "*Font",
            default_font
        )

        # Base
        style.configure(
            ".",
            background=COLOR_BG,
            foreground=COLOR_TEXT,
            font=default_font
        )

        # Frames
        style.configure(
            "TFrame",
            background=COLOR_BG
        )

        style.configure(
            "Card.TFrame",
            background=COLOR_BG,
            relief="flat"
        )

        # Labels
        style.configure(
            "TLabel",
            background=COLOR_BG,
            foreground=COLOR_TEXT,
            font=default_font
        )

        style.configure(
            "Header.TLabel",
            background=COLOR_BG,
            foreground=COLOR_PRIMARY_DARK,
            font=title_font
        )

        # Buttons
        style.configure(
            "TButton",
            background=COLOR_PRIMARY,
            foreground=COLOR_HEADER_TEXT,
            borderwidth=0,
            focusthickness=0,
            focuscolor=COLOR_PRIMARY,
            padding=(14, 7),
            font=heading_font
        )

        style.map(
            "TButton",
            background=[
                ("disabled", "#DCCBA8"),
                ("pressed", COLOR_PRIMARY_DARK),
                ("active", COLOR_ACCENT)
            ],
            foreground=[
                ("disabled", "#8A7A5E")
            ]
        )

        style.configure(
            "Stop.TButton",
            background="#B5502F",
            foreground=COLOR_HEADER_TEXT
        )

        style.map(
            "Stop.TButton",
            background=[
                ("disabled", "#DCCBA8"),
                ("pressed", "#8C3C22"),
                ("active", "#C96237")
            ]
        )

        style.configure(
            "Ghost.TButton",
            background=COLOR_BG_ALT,
            foreground=COLOR_PRIMARY_DARK
        )

        style.map(
            "Ghost.TButton",
            background=[
                ("disabled", COLOR_BG_ALT),
                ("pressed", COLOR_PRIMARY_LIGHT),
                ("active", COLOR_PRIMARY_LIGHT)
            ]
        )

        # Combobox
        style.configure(
            "TCombobox",
            fieldbackground=COLOR_WHITE_PANEL,
            background=COLOR_WHITE_PANEL,
            foreground=COLOR_TEXT,
            arrowcolor=COLOR_PRIMARY_DARK,
            bordercolor=COLOR_BORDER,
            lightcolor=COLOR_WHITE_PANEL,
            darkcolor=COLOR_WHITE_PANEL,
            padding=6,
            relief="flat"
        )

        style.map(
            "TCombobox",
            fieldbackground=[
                ("readonly", COLOR_WHITE_PANEL)
            ],
            foreground=[
                ("readonly", COLOR_TEXT)
            ],
            selectbackground=[
                ("readonly", COLOR_WHITE_PANEL)
            ],
            selectforeground=[
                ("readonly", COLOR_TEXT)
            ]
        )

        # Entry
        style.configure(
            "TEntry",
            fieldbackground=COLOR_WHITE_PANEL,
            foreground=COLOR_TEXT,
            bordercolor=COLOR_BORDER,
            lightcolor=COLOR_WHITE_PANEL,
            darkcolor=COLOR_WHITE_PANEL,
            padding=7,
            relief="flat"
        )

        style.map(
            "TEntry",
            bordercolor=[
                ("focus", COLOR_PRIMARY)
            ]
        )

        # Treeview
        style.configure(
            "Treeview",
            background=COLOR_WHITE_PANEL,
            fieldbackground=COLOR_WHITE_PANEL,
            foreground=COLOR_TEXT,
            rowheight=26,
            borderwidth=0,
            relief="flat",
            font=default_font
        )

        style.configure(
            "Treeview.Heading",
            background=COLOR_HEADER_BG,
            foreground=COLOR_HEADER_TEXT,
            relief="flat",
            font=heading_font,
            padding=(8, 8)
        )

        style.map(
            "Treeview.Heading",
            background=[
                ("active", COLOR_PRIMARY_DARK)
            ]
        )

        style.map(
            "Treeview",
            background=[
                ("selected", COLOR_SELECT_BG)
            ],
            foreground=[
                ("selected", COLOR_TEXT)
            ]
        )

        # Scrollbars
        style.configure(
            "Vertical.TScrollbar",
            background=COLOR_PRIMARY_LIGHT,
            troughcolor=COLOR_BG_ALT,
            bordercolor=COLOR_BG_ALT,
            arrowcolor=COLOR_PRIMARY_DARK,
            relief="flat"
        )

        style.configure(
            "Horizontal.TScrollbar",
            background=COLOR_PRIMARY_LIGHT,
            troughcolor=COLOR_BG_ALT,
            bordercolor=COLOR_BG_ALT,
            arrowcolor=COLOR_PRIMARY_DARK,
            relief="flat"
        )

        style.map(
            "Vertical.TScrollbar",
            background=[
                ("active", COLOR_ACCENT)
            ]
        )

        style.map(
            "Horizontal.TScrollbar",
            background=[
                ("active", COLOR_ACCENT)
            ]
        )

        style.configure(
            "TSeparator",
            background=COLOR_BORDER
        )

    # GUI
    def build_ui(self):

        # TOP CONTROL BAR
        top = ttk.Frame(
            self.root,
            padding=(16, 14, 16, 8)
        )

        top.pack(
            fill="x"
        )

        ttk.Label(
            top,
            text="🌐  Network Interface",
            style="Header.TLabel"
        ).pack(
            side="left",
            padx=(0, 10)
        )

        self.interface_combo = ttk.Combobox(
            top,
            state="readonly",
            width=75
        )

        self.interface_combo.pack(
            side="left",
            padx=(0, 10),
            fill="x",
            expand=True
        )

        self.refresh_button = ttk.Button(
            top,
            text="⟳ Refresh",
            command=self.load_interfaces,
            style="Ghost.TButton"
        )

        self.refresh_button.pack(
            side="left",
            padx=3
        )

        self.start_button = ttk.Button(
            top,
            text="▶ Start Capture",
            command=self.start_capture,
            style="TButton"
        )

        self.start_button.pack(
            side="left",
            padx=3
        )

        self.stop_button = ttk.Button(
            top,
            text="■ Stop Capture",
            command=self.stop_capture,
            style="Stop.TButton"
        )

        self.stop_button.pack(
            side="left",
            padx=3
        )

        self.clear_button = ttk.Button(
            top,
            text="🗑 Clear",
            command=self.clear_packets,
            style="Ghost.TButton"
        )

        self.clear_button.pack(
            side="left",
            padx=3
        )

        # PCAP BUTTONS
        ttk.Separator(
            top,
            orient="vertical"
        ).pack(
            side="left",
            fill="y",
            padx=8
        )

        self.open_pcap_button = ttk.Button(
            top,
            text="📂 Open PCAP",
            command=self.open_pcap,
            style="Ghost.TButton"
        )

        self.open_pcap_button.pack(
            side="left",
            padx=3
        )

        self.save_pcap_button = ttk.Button(
            top,
            text="💾 Save As PCAP",
            command=self.save_pcap_as,
            style="Ghost.TButton"
        )

        self.save_pcap_button.pack(
            side="left",
            padx=3
        )

        # FILTER
        filter_frame = ttk.Frame(
            self.root,
            padding=(16, 0, 16, 12)
        )

        filter_frame.pack(
            fill="x"
        )

        ttk.Label(
            filter_frame,
            text="🔍  Filter",
            style="Header.TLabel"
        ).pack(
            side="left",
            padx=(0, 10)
        )

        self.filter_var = tk.StringVar()

        self.filter_entry = ttk.Entry(
            filter_frame,
            textvariable=self.filter_var
        )

        self.filter_entry.pack(
            side="left",
            fill="x",
            expand=True
        )

        self.filter_var.trace_add(
            "write",
            lambda *args: self.apply_filter()
        )

        ttk.Separator(
            self.root,
            orient="horizontal"
        ).pack(
            fill="x",
            padx=16
        )

        # PACKET TABLE
        table_frame = ttk.Frame(
            self.root,
            padding=(16, 12, 16, 8)
        )

        table_frame.pack(
            fill="both",
            expand=True
        )

        columns = (
            "No",
            "Time",
            "Source",
            "Destination",
            "Protocol",
            "Length",
            "Info"
        )

        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse"
        )

        self.tree.heading(
            "No",
            text="No"
        )

        self.tree.heading(
            "Time",
            text="Time"
        )

        self.tree.heading(
            "Source",
            text="Source"
        )

        self.tree.heading(
            "Destination",
            text="Destination"
        )

        self.tree.heading(
            "Protocol",
            text="Protocol"
        )

        self.tree.heading(
            "Length",
            text="Length"
        )

        self.tree.heading(
            "Info",
            text="Info"
        )

        self.tree.column(
            "No",
            width=60,
            anchor="center"
        )

        self.tree.column(
            "Time",
            width=110,
            anchor="center"
        )

        self.tree.column(
            "Source",
            width=180
        )

        self.tree.column(
            "Destination",
            width=180
        )

        self.tree.column(
            "Protocol",
            width=100,
            anchor="center"
        )

        self.tree.column(
            "Length",
            width=80,
            anchor="center"
        )

        self.tree.column(
            "Info",
            width=400
        )

        # Row styling
        self.tree.tag_configure(
            "evenrow",
            background=COLOR_WHITE_PANEL
        )

        self.tree.tag_configure(
            "oddrow",
            background=COLOR_ROW_ALT
        )

        self.tree.tag_configure(
            "proto_tcp",
            foreground="#7C5527"
        )

        self.tree.tag_configure(
            "proto_udp",
            foreground="#5E7A3E"
        )

        self.tree.tag_configure(
            "proto_arp",
            foreground="#B5502F"
        )

        self.tree.tag_configure(
            "proto_dns",
            foreground="#4E6E8C"
        )

        self.tree.tag_configure(
            "proto_icmp",
            foreground="#8C4E8C"
        )

        # Scrollbars
        scrollbar_y = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.tree.yview
        )

        scrollbar_x = ttk.Scrollbar(
            table_frame,
            orient="horizontal",
            command=self.tree.xview
        )

        self.tree.configure(
            yscrollcommand=scrollbar_y.set,
            xscrollcommand=scrollbar_x.set
        )

        self.tree.grid(
            row=0,
            column=0,
            sticky="nsew"
        )

        scrollbar_y.grid(
            row=0,
            column=1,
            sticky="ns"
        )

        scrollbar_x.grid(
            row=1,
            column=0,
            sticky="ew"
        )

        table_frame.rowconfigure(
            0,
            weight=1
        )

        table_frame.columnconfigure(
            0,
            weight=1
        )

        self.tree.bind(
            "<<TreeviewSelect>>",
            self.show_packet_details
        )

        # PACKET DETAILS
        details_label = ttk.Label(
            self.root,
            text="📋  Packet Details",
            style="Header.TLabel",
            padding=(16, 8, 16, 4)
        )

        details_label.pack(
            anchor="w"
        )

        details_outer = tk.Frame(
            self.root,
            bg=COLOR_BORDER,
            padx=1,
            pady=1
        )

        details_outer.pack(
            fill="both",
            expand=True,
            padx=16,
            pady=(0, 12)
        )

        details_frame = ttk.Frame(
            details_outer
        )

        details_frame.pack(
            fill="both",
            expand=True
        )

        self.details_text = tk.Text(
            details_frame,
            height=12,
            wrap="none",
            bg=COLOR_WHITE_PANEL,
            fg=COLOR_TEXT,
            insertbackground=COLOR_TEXT,
            relief="flat",
            padx=10,
            pady=8,
            font=("Consolas", 10),
            selectbackground=COLOR_SELECT_BG,
            selectforeground=COLOR_TEXT
        )

        details_scroll_y = ttk.Scrollbar(
            details_frame,
            orient="vertical",
            command=self.details_text.yview
        )

        details_scroll_x = ttk.Scrollbar(
            details_frame,
            orient="horizontal",
            command=self.details_text.xview
        )

        self.details_text.configure(
            yscrollcommand=details_scroll_y.set,
            xscrollcommand=details_scroll_x.set
        )

        self.details_text.grid(
            row=0,
            column=0,
            sticky="nsew"
        )

        details_scroll_y.grid(
            row=0,
            column=1,
            sticky="ns"
        )

        details_scroll_x.grid(
            row=1,
            column=0,
            sticky="ew"
        )

        details_frame.rowconfigure(
            0,
            weight=1
        )

        details_frame.columnconfigure(
            0,
            weight=1
        )

        # STATUS BAR
        self.status_var = tk.StringVar(
            value="Ready"
        )

        status = tk.Label(
            self.root,
            textvariable=self.status_var,
            bg=COLOR_PRIMARY_DARK,
            fg=COLOR_HEADER_TEXT,
            anchor="w",
            padx=16,
            pady=6,
            font=("Segoe UI", 9)
        )

        status.pack(
            fill="x",
            side="bottom"
        )

        self.stop_button.config(
            state="disabled"
        )

    # MENU
    def build_menu(self):

        menubar = tk.Menu(
            self.root,
            bg=COLOR_BG_ALT,
            fg=COLOR_TEXT,
            activebackground=COLOR_PRIMARY,
            activeforeground=COLOR_HEADER_TEXT,
            tearoff=False
        )

        file_menu = tk.Menu(
            menubar,
            tearoff=False,
            bg=COLOR_BG_ALT,
            fg=COLOR_TEXT,
            activebackground=COLOR_PRIMARY,
            activeforeground=COLOR_HEADER_TEXT
        )

        file_menu.add_command(
            label="Open PCAP...",
            accelerator="Ctrl+O",
            command=self.open_pcap
        )

        file_menu.add_separator()

        file_menu.add_command(
            label="Save As PCAP...",
            accelerator="Ctrl+Shift+S",
            command=self.save_pcap_as
        )

        file_menu.add_separator()

        file_menu.add_command(
            label="Exit",
            command=self.on_close
        )

        menubar.add_cascade(
            label="File",
            menu=file_menu
        )

        self.root.config(
            menu=menubar
        )

        self.root.bind(
            "<Control-o>",
            lambda event: self.open_pcap()
        )

        self.root.bind(
            "<Control-Shift-S>",
            lambda event: self.save_pcap_as()
        )

        # Additional Ctrl+S shortcut
        self.root.bind(
            "<Control-s>",
            lambda event: self.save_pcap_as()
        )

    # PACKET STORAGE
    def get_all_packets(self):

        with self.lock:
            return [
                item["packet"]
                for item in self.packets
            ]

    # SAVE PCAP
    def save_pcap_as(self):

        if self.capturing or self.stopping:

            messagebox.showinfo(
                "Capture Running",
                "Stop the capture before saving the PCAP file."
            )

            return

        packets = self.get_all_packets()

        if not packets:

            messagebox.showinfo(
                "No Packets",
                "There are no packets available to save."
            )

            return

        path = filedialog.asksaveasfilename(
            title="Save Capture As PCAP",
            defaultextension=".pcap",
            filetypes=[
                ("PCAP capture", "*.pcap"),
                ("All files", "*.*")
            ],
            initialfile="capture.pcap"
        )

        if not path:
            return

        try:

            wrpcap(
                path,
                packets
            )

            self.current_pcap_path = path

            self.status_var.set(
                f"  Saved {len(packets)} packets to {path}"
            )

            messagebox.showinfo(
                "PCAP Saved",
                f"Capture saved successfully.\n\n"
                f"Packets: {len(packets)}\n\n"
                f"File:\n{path}"
            )

        except Exception as e:

            messagebox.showerror(
                "PCAP Save Error",
                f"Could not save the PCAP file:\n\n{e}"
            )

    # OPEN PCAP
    def open_pcap(self):

        if self.capturing or self.stopping:

            messagebox.showinfo(
                "Capture Running",
                "Stop the current capture before opening a PCAP file."
            )

            return

        path = filedialog.askopenfilename(
            title="Open PCAP Capture",
            filetypes=[
                (
                    "Packet captures",
                    "*.pcap *.pcapng *.cap"
                ),
                (
                    "PCAP",
                    "*.pcap"
                ),
                (
                    "PCAPNG",
                    "*.pcapng"
                ),
                (
                    "CAP",
                    "*.cap"
                ),
                (
                    "All files",
                    "*.*"
                )
            ]
        )

        if not path:
            return

        try:

            self.status_var.set(
                "  Loading PCAP..."
            )

            self.root.update_idletasks()

            loaded_packets = rdpcap(
                path
            )

            # Completely reset current packet data
            with self.lock:

                self.packets.clear()

                self.packet_number = 0

            # Clear GUI
            self.clear_treeview()

            self.details_text.delete(
                "1.0",
                "end"
            )

            self.current_pcap_path = path

            # Add loaded packets to application storage
            for packet in loaded_packets:

                with self.lock:

                    self.packet_number += 1

                    number = self.packet_number

                self.add_packet_to_gui(
                    number,
                    packet,
                    update_status=False
                )

            # Re-apply current filter
            self.apply_filter()

            self.status_var.set(
                f"  Opened PCAP: "
                f"{path} | "
                f"{len(loaded_packets)} packets"
            )

        except Exception as e:

            self.status_var.set(
                "  Failed to open PCAP"
            )

            messagebox.showerror(
                "PCAP Open Error",
                f"Could not open the PCAP file:\n\n{e}"
            )

    # CLEAR TREEVIEW
    def clear_treeview(self):

        for item in self.tree.get_children():

            try:
                self.tree.delete(item)
            except tk.TclError:
                pass

    # INTERFACES
    def load_interfaces(self):

        if self.capturing or self.stopping:
            return

        old_index = self.interface_combo.current()

        self.interfaces.clear()

        display_names = []

        try:

            for iface in conf.ifaces.values():

                try:

                    name = str(
                        getattr(
                            iface,
                            "name",
                            ""
                        )
                    )

                    description = str(
                        getattr(
                            iface,
                            "description",
                            ""
                        )
                    )

                    index = getattr(
                        iface,
                        "index",
                        ""
                    )

                    try:

                        ip = get_if_addr(
                            iface
                        )

                    except Exception:

                        ip = ""

                    display = (
                        f"{description or name}"
                        f" | IPv4: {ip or 'N/A'}"
                        f" | Index: {index}"
                    )

                    self.interfaces.append(
                        iface
                    )

                    display_names.append(
                        display
                    )

                except Exception:

                    continue

            self.interface_combo["values"] = (
                display_names
            )

            # Prefer Realtek Wi-Fi
            preferred_index = None

            for i, iface in enumerate(
                self.interfaces
            ):

                description = str(
                    getattr(
                        iface,
                        "description",
                        ""
                    )
                ).lower()

                name = str(
                    getattr(
                        iface,
                        "name",
                        ""
                    )
                ).lower()

                if (
                    "realtek" in description
                    and "wi-fi" in description
                ):

                    preferred_index = i
                    break

                if (
                    "realtek" in description
                    and "wifi" in description
                ):

                    preferred_index = i
                    break

                if (
                    "wi-fi" in description
                    and "npf" in name
                ):

                    preferred_index = i

            # Restore previous selection
            if (
                preferred_index is not None
            ):

                self.interface_combo.current(
                    preferred_index
                )

            elif (
                old_index >= 0
                and old_index < len(self.interfaces)
            ):

                self.interface_combo.current(
                    old_index
                )

            elif self.interfaces:

                self.interface_combo.current(
                    0
                )

            self.status_var.set(
                f"  {len(self.interfaces)} interfaces found"
            )

        except Exception as e:

            self.status_var.set(
                "  Failed to load interfaces"
            )

            messagebox.showerror(
                "Interface Error",
                f"Could not load network interfaces:\n\n{e}"
            )

    # SELECTED INTERFACE
    def get_selected_interface(self):

        position = self.interface_combo.current()

        if position < 0:
            return None

        if position >= len(
            self.interfaces
        ):
            return None

        return self.interfaces[position]

    # START CAPTURE
    def start_capture(self):

        if self.capturing:
            return

        if self.stopping:
            return

        iface = self.get_selected_interface()

        if iface is None:

            messagebox.showwarning(
                "No Interface",
                "Please select a network interface."
            )

            return

        try:

            description = str(
                getattr(
                    iface,
                    "description",
                    ""
                )
            )

            name = str(
                getattr(
                    iface,
                    "name",
                    ""
                )
            )

            index = getattr(
                iface,
                "index",
                ""
            )

            print()
            print("=" * 70)
            print("STARTING PACKET CAPTURE")
            print("=" * 70)
            print(
                f"Description : {description}"
            )
            print(
                f"Name        : {name}"
            )
            print(
                f"Index       : {index}"
            )

            try:

                print(
                    f"IPv4        : "
                    f"{get_if_addr(iface)}"
                )

            except Exception:
                pass

            print("=" * 70)

            # Create Scapy sniffer
            self.sniffer = AsyncSniffer(
                iface=iface,
                prn=self.packet_callback,
                store=False
            )

            # Set application state BEFORE starting sniffer
            self.capturing = True
            self.stopping = False

            self.start_button.config(
                state="disabled"
            )

            self.stop_button.config(
                state="normal"
            )

            self.refresh_button.config(
                state="disabled"
            )

            self.interface_combo.config(
                state="disabled"
            )

            self.open_pcap_button.config(
                state="disabled"
            )

            self.save_pcap_button.config(
                state="disabled"
            )

            self.status_var.set(
                "  ● Capturing packets..."
            )

            # Start capture
            self.sniffer.start()

            print(
                "Capture started successfully."
            )

            print()

        except Exception as e:

            self.sniffer = None

            self.capturing = False
            self.stopping = False

            self.start_button.config(
                state="normal"
            )

            self.stop_button.config(
                state="disabled"
            )

            self.refresh_button.config(
                state="normal"
            )

            self.interface_combo.config(
                state="readonly"
            )

            self.open_pcap_button.config(
                state="normal"
            )

            self.save_pcap_button.config(
                state="normal"
            )

            self.status_var.set(
                "  Capture failed"
            )

            print()
            print("CAPTURE ERROR:")
            print(e)
            print()

            messagebox.showerror(
                "Capture Error",
                "Could not start packet capture:\n\n"
                f"{e}\n\n"
                "On Windows, make sure Npcap is installed "
                "and the application is running with the "
                "required permissions."
            )

    # PACKET CALLBACK
    def packet_callback(self, packet):

        if not self.capturing:
            return

        try:

            with self.lock:

                self.packet_number += 1

                number = self.packet_number

            self.packet_queue.put(
                (
                    number,
                    packet
                )
            )

            print(
                f"[{number}] "
                f"{packet.summary()}"
            )

        except Exception as e:

            print(
                f"Packet processing error: {e}"
            )

    # PROCESS PACKET QUEUE
    def process_packet_queue(self):

        processed = 0

        try:

            while processed < 100:

                try:

                    number, packet = (
                        self.packet_queue.get_nowait()
                    )

                except queue.Empty:

                    break

                self.add_packet_to_gui(
                    number,
                    packet
                )

                processed += 1

        except Exception as e:

            print(
                f"GUI queue error: {e}"
            )

        finally:

            try:

                self.root.after(
                    50,
                    self.process_packet_queue
                )

            except tk.TclError:
                pass

    # ADD PACKET TO GUI
    def add_packet_to_gui(
        self,
        number,
        packet,
        update_status=True
    ):

        try:

            # Timestamp
            try:

                timestamp = datetime.fromtimestamp(
                    float(packet.time)
                ).strftime(
                    "%H:%M:%S.%f"
                )[:-3]

            except Exception:

                timestamp = datetime.now().strftime(
                    "%H:%M:%S.%f"
                )[:-3]

            source = ""
            destination = ""

            protocol = "OTHER"

            info = ""

            # ARP
            if packet.haslayer(ARP):

                arp = packet[ARP]

                source = str(
                    arp.psrc
                )

                destination = str(
                    arp.pdst
                )

                protocol = "ARP"

                if arp.op == 1:

                    info = (
                        f"Who has "
                        f"{arp.pdst}? "
                        f"Tell "
                        f"{arp.psrc}"
                    )

                elif arp.op == 2:

                    info = (
                        f"{arp.psrc} "
                        f"is at "
                        f"{arp.hwsrc}"
                    )

            # IPv4
            elif packet.haslayer(IP):

                ip = packet[IP]

                source = str(
                    ip.src
                )

                destination = str(
                    ip.dst
                )

                # TCP
                if packet.haslayer(TCP):

                    protocol = "TCP"

                    tcp = packet[TCP]

                    info = (
                        f"{tcp.sport} → "
                        f"{tcp.dport}"
                    )

                    flags = str(
                        tcp.flags
                    )

                    if flags:

                        info += (
                            f" [{flags}]"
                        )

                # UDP
                elif packet.haslayer(UDP):

                    protocol = "UDP"

                    udp = packet[UDP]

                    info = (
                        f"{udp.sport} → "
                        f"{udp.dport}"
                    )

                # ICMP
                elif packet.haslayer(ICMP):

                    protocol = "ICMP"

                    icmp = packet[ICMP]

                    info = (
                        f"Type={icmp.type} "
                        f"Code={icmp.code}"
                    )

                else:

                    protocol = str(
                        ip.proto
                    )

                    info = (
                        f"IPv4 protocol "
                        f"{ip.proto}"
                    )

            # IPv6
            elif packet.haslayer(IPv6):

                ipv6 = packet[IPv6]

                source = str(
                    ipv6.src
                )

                destination = str(
                    ipv6.dst
                )

                if packet.haslayer(TCP):

                    protocol = "TCP"

                    tcp = packet[TCP]

                    info = (
                        f"{tcp.sport} → "
                        f"{tcp.dport}"
                    )

                    flags = str(
                        tcp.flags
                    )

                    if flags:

                        info += (
                            f" [{flags}]"
                        )

                elif packet.haslayer(UDP):

                    protocol = "UDP"

                    udp = packet[UDP]

                    info = (
                        f"{udp.sport} → "
                        f"{udp.dport}"
                    )

                elif packet.haslayer(ICMP):

                    protocol = "ICMP"

                    info = "ICMPv6"

                else:

                    protocol = "IPv6"

                    info = (
                        f"Next Header: "
                        f"{ipv6.nh}"
                    )

            # DNS is checked AFTER IP/TCP/UDP
            if packet.haslayer(DNS):

                protocol = "DNS"

                dns = packet[DNS]

                if dns.qr == 0:

                    if packet.haslayer(DNSQR):

                        try:

                            query = packet[
                                DNSQR
                            ].qname.decode(
                                errors="ignore"
                            ).rstrip(".")

                            info = (
                                f"Query: "
                                f"{query}"
                            )

                        except Exception:

                            info = "DNS Query"

                    else:

                        info = "DNS Query"

                else:

                    info = "DNS Response"

            # Defaults
            if not source:

                source = "N/A"

            if not destination:

                destination = "N/A"

            source = str(source)
            destination = str(destination)
            protocol = str(protocol)
            info = str(info)

            try:

                length = len(packet)

            except Exception:

                length = 0

            # Create packet record
            packet_data = {

                "number": number,

                "time": timestamp,

                "source": source,

                "destination": destination,

                "protocol": protocol,

                "length": length,

                "info": info,

                "packet": packet
            }

            with self.lock:

                self.packets.append(
                    packet_data
                )

            # Display if filter allows it
            if self.packet_matches_filter(
                packet_data
            ):

                self.insert_packet_row(
                    packet_data
                )

            if update_status:

                with self.lock:

                    count = len(
                        self.packets
                    )

                self.status_var.set(
                    f"  ● Captured packets: "
                    f"{count}"
                )

        except Exception as e:

            print(
                f"GUI packet error: {e}"
            )

    # INSERT PACKET ROW
    def insert_packet_row(
        self,
        packet_data
    ):

        number = packet_data["number"]

        # Avoid duplicate Treeview IDs
        iid = str(number)

        if self.tree.exists(iid):

            try:
                self.tree.delete(iid)
            except tk.TclError:
                pass

        # Alternate row
        row_tag = (
            "evenrow"
            if number % 2 == 0
            else "oddrow"
        )

        # Protocol styling
        protocol_tag_map = {

            "TCP": "proto_tcp",

            "UDP": "proto_udp",

            "ARP": "proto_arp",

            "DNS": "proto_dns",

            "ICMP": "proto_icmp"
        }

        tags = [
            row_tag
        ]

        proto_tag = protocol_tag_map.get(
            packet_data["protocol"]
        )

        if proto_tag:

            tags.append(
                proto_tag
            )

        # Insert
        self.tree.insert(
            "",
            "end",
            iid=iid,
            values=(

                packet_data["number"],

                packet_data["time"],

                packet_data["source"],

                packet_data["destination"],

                packet_data["protocol"],

                packet_data["length"],

                packet_data["info"]
            ),
            tags=tuple(tags)
        )

    # FILTER MATCH
    def packet_matches_filter(
        self,
        packet_data
    ):

        filter_text = (
            self.filter_var
            .get()
            .strip()
            .lower()
        )

        if not filter_text:

            return True

        packet = packet_data[
            "packet"
        ]

        # Protocol filters
        if filter_text == "tcp":

            return packet.haslayer(
                TCP
            )

        if filter_text == "udp":

            return packet.haslayer(
                UDP
            )

        if filter_text == "icmp":

            return packet.haslayer(
                ICMP
            )

        if filter_text == "arp":

            return packet.haslayer(
                ARP
            )

        if filter_text == "ipv6":

            return packet.haslayer(
                IPv6
            )

        if filter_text == "dns":

            return packet.haslayer(
                DNS
            )

        if filter_text == "ip":

            return packet.haslayer(
                IP
            )

        if filter_text.startswith(
            "host "
        ):

            host = (
                filter_text[5:]
                .strip()
                .lower()
            )

            return (
                host
                == packet_data[
                    "source"
                ].lower()
                or
                host
                == packet_data[
                    "destination"
                ].lower()
            )

        # src X
        if filter_text.startswith(
            "src "
        ):

            src = (
                filter_text[4:]
                .strip()
                .lower()
            )

            return (
                src
                == packet_data[
                    "source"
                ].lower()
            )

        # dst X
        if filter_text.startswith(
            "dst "
        ):

            dst = (
                filter_text[4:]
                .strip()
                .lower()
            )

            return (
                dst
                == packet_data[
                    "destination"
                ].lower()
            )

        # port X
        if filter_text.startswith(
            "port "
        ):

            port = (
                filter_text[5:]
                .strip()
            )

            try:

                port_number = int(
                    port
                )

            except ValueError:

                return False

            if packet.haslayer(TCP):

                tcp = packet[TCP]

                return (
                    tcp.sport
                    == port_number
                    or
                    tcp.dport
                    == port_number
                )

            if packet.haslayer(UDP):

                udp = packet[UDP]

                return (
                    udp.sport
                    == port_number
                    or
                    udp.dport
                    == port_number
                )

            return False

        # Generic search
        searchable = " ".join(
            [
                str(
                    packet_data[
                        "number"
                    ]
                ),

                str(
                    packet_data[
                        "time"
                    ]
                ),

                str(
                    packet_data[
                        "source"
                    ]
                ),

                str(
                    packet_data[
                        "destination"
                    ]
                ),

                str(
                    packet_data[
                        "protocol"
                    ]
                ),

                str(
                    packet_data[
                        "length"
                    ]
                ),

                str(
                    packet_data[
                        "info"
                    ]
                )
            ]
        ).lower()

        return (
            filter_text
            in searchable
        )

    # APPLY FILTER
    def apply_filter(self):

        try:

            self.clear_treeview()

            with self.lock:

                packets_copy = list(
                    self.packets
                )

            for packet_data in packets_copy:

                if self.packet_matches_filter(
                    packet_data
                ):

                    self.insert_packet_row(
                        packet_data
                    )

        except Exception as e:

            print(
                f"Filter error: {e}"
            )

    # STOP CAPTURE
    def stop_capture(self):

        if not self.capturing:
            return

        if self.stopping:
            return

        print()
        print("=" * 70)
        print("STOPPING PACKET CAPTURE")
        print("=" * 70)

        self.stopping = True

        self.stop_button.config(
            state="disabled"
        )

        self.start_button.config(
            state="disabled"
        )

        self.status_var.set(
            "  Stopping capture..."
        )

        sniffer = self.sniffer

        threading.Thread(
            target=self.stop_sniffer_worker,
            args=(sniffer,),
            daemon=True
        ).start()

    # STOP WORKER
    def stop_sniffer_worker(
        self,
        sniffer
    ):

        try:

            if sniffer is not None:

                print(
                    "Stopping Scapy sniffer..."
                )

                try:

                    sniffer.stop()

                except Exception as e:

                    print(
                        f"Sniffer stop error: {e}"
                    )

            print(
                "Scapy sniffer stopped."
            )

        except Exception as e:

            print(
                f"Stop worker error: {e}"
            )

        finally:

            try:

                self.root.after(
                    0,
                    self.capture_stopped
                )

            except tk.TclError:
                pass

    # CAPTURE STOPPED
    def capture_stopped(self):

        self.sniffer = None

        self.capturing = False
        self.stopping = False

        self.start_button.config(
            state="normal"
        )

        self.stop_button.config(
            state="disabled"
        )

        self.refresh_button.config(
            state="normal"
        )

        self.interface_combo.config(
            state="readonly"
        )

        self.open_pcap_button.config(
            state="normal"
        )

        self.save_pcap_button.config(
            state="normal"
        )

        with self.lock:

            count = len(
                self.packets
            )

        self.status_var.set(
            f"  Capture stopped. "
            f"Packets captured: "
            f"{count}"
        )

        print(
            "Capture stopped successfully."
        )

        print(
            f"Total packets: {count}"
        )

        print(
            "=" * 70
        )

        print()

    # CLEAR PACKETS
    def clear_packets(self):

        if self.capturing:

            messagebox.showinfo(
                "Capture Running",
                "Stop the capture before clearing packets."
            )

            return

        if self.stopping:

            return

        with self.lock:

            self.packets.clear()

            self.packet_number = 0

        # Clear queued packets
        while True:

            try:

                self.packet_queue.get_nowait()

            except queue.Empty:

                break

        self.clear_treeview()

        self.details_text.delete(
            "1.0",
            "end"
        )

        self.current_pcap_path = None

        self.status_var.set(
            "  Packet list cleared"
        )

    # PACKET DETAILS
    def show_packet_details(
        self,
        event=None
    ):

        selection = (
            self.tree.selection()
        )

        if not selection:

            return

        try:

            number = int(
                selection[0]
            )

        except Exception:

            return

        packet_data = None

        with self.lock:

            for item in self.packets:

                if (
                    item["number"]
                    == number
                ):

                    packet_data = item

                    break

        if packet_data is None:

            return

        packet = packet_data[
            "packet"
        ]

        self.details_text.delete(
            "1.0",
            "end"
        )

        try:

            details = packet.show(
                dump=True
            )

        except Exception as e:

            details = (
                "Unable to decode packet:\n\n"
                f"{e}"
            )

        # Add basic packet information above Scapy details
        header = (
            f"Packet #{packet_data['number']}\n"
            f"Time: {packet_data['time']}\n"
            f"Source: {packet_data['source']}\n"
            f"Destination: {packet_data['destination']}\n"
            f"Protocol: {packet_data['protocol']}\n"
            f"Length: {packet_data['length']} bytes\n"
            f"Info: {packet_data['info']}\n"
            f"\n"
            f"{'=' * 70}\n\n"
        )

        self.details_text.insert(
            "1.0",
            header + details
        )

    # CLOSE APPLICATION
    def on_close(self):

        if self.capturing or self.stopping:

            self.stopping = True

            sniffer = self.sniffer

            if sniffer is not None:

                try:

                    threading.Thread(
                        target=self.force_stop_on_close,
                        args=(sniffer,),
                        daemon=True
                    ).start()

                except Exception:
                    pass

        # Destroy immediately.
        # The worker is daemonized.
        try:

            self.root.destroy()

        except Exception:
            pass

    # FORCE STOP
    def force_stop_on_close(
        self,
        sniffer
    ):

        try:

            if sniffer is not None:

                sniffer.stop()

        except Exception:

            pass


# MAIN
def main():

    root = tk.Tk()
    app = PakchaApp(
        root
    )

    root.mainloop()


if __name__ == "__main__":

    main()
    