#!/usr/bin/env python3
"""
NetScope - passive sniffer + LAN device profiler in one GUI.

  Devices tab   : ARP scan -> MAC vendor, hostname, open ports, banners, TTL OS guess
  Capture tab   : live packet capture with BPF filter, colour-coded rows, packet
                  details + hex dump, optional live .pcap writing, export
  Statistics tab: protocol breakdown, top talkers, DNS names learned from traffic

Only use on networks/devices you own or are authorised to test.

Setup:
    pip install scapy
    (Linux: sudo apt install python3-tk   |  Windows: install Npcap)

Run (needs raw-socket privileges):
    sudo python3 netscope.py            # Linux / macOS
    python netscope.py                  # Windows, from an Administrator prompt
"""

import csv
import ipaddress
import json
import os
import queue
import re
import socket
import sys
import threading
import tkinter as tk
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont

try:
    from scapy.all import (
        AsyncSniffer, PcapWriter, wrpcap, hexdump, srp, sr1, conf,
        get_if_addr, get_if_list,
        Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw,
    )
    conf.verb = 0
except ImportError:
    _r = tk.Tk()
    _r.withdraw()
    messagebox.showerror("Missing dependency", "scapy is not installed.\n\nRun:  pip install scapy")
    sys.exit(1)

# ───────────────────────────── palette ─────────────────────────────
BG, PANEL, PANEL2 = "#0f1419", "#161c25", "#1d2530"
FG, MUTED, BORDER = "#e6edf3", "#8b98a9", "#2a3441"
ACCENT, ACCENT_H = "#4c8dff", "#6ba0ff"
GREEN, RED, AMBER, PURPLE, TEAL = "#3fb950", "#f85149", "#d29922", "#b388ff", "#39c5cf"

MAX_ROWS = 4000          # packet rows kept in the table
MAX_PKTS = 4000          # packets kept in memory for details / export
ALL_IFACES = "All interfaces"

# ───────────────────────────── backend data ─────────────────────────────
DEFAULT_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 554: "RTSP (camera)",
    631: "IPP (printer)", 3389: "RDP", 5353: "mDNS",
    8008: "Cast (HTTP)", 8009: "Cast (control)", 8443: "HTTPS-alt",
    9100: "JetDirect (printer)",
}

BUILTIN_OUI = {
    "F8:5C:B8": "Google", "F4:F5:D8": "Google", "DA:A1:19": "Google",
    "3C:5A:B4": "Google", "54:60:09": "Google", "00:1A:11": "Google",
    "AC:63:BE": "Amazon", "F0:D2:F1": "Amazon", "FC:65:DE": "Amazon", "A4:77:33": "Amazon",
    "A8:51:AB": "Apple", "3C:22:FB": "Apple", "F0:18:98": "Apple",
    "DC:A6:32": "Raspberry Pi", "B8:27:EB": "Raspberry Pi", "D8:3A:DD": "Raspberry Pi",
    "00:1D:D8": "Microsoft", "7C:1E:52": "Microsoft",
    "00:0C:29": "VMware", "08:00:27": "VirtualBox",
    "18:FE:34": "Espressif (IoT)", "24:0A:C4": "Espressif (IoT)",
    "30:AE:A4": "Espressif (IoT)", "84:F3:EB": "Espressif (IoT)",
    "EC:FA:BC": "Espressif (IoT)", "A0:20:A6": "Espressif (IoT)",
    "00:17:88": "Philips Hue", "EC:B5:FA": "Philips",
    "B0:7F:B9": "Ubiquiti", "24:5A:4C": "Ubiquiti",
    "50:C7:BF": "TP-Link", "98:DA:C4": "TP-Link", "AC:84:C6": "TP-Link",
    "00:11:32": "Synology",
    "F4:5E:AB": "Samsung", "88:36:6C": "Samsung",
}


def load_oui_file(path):
    table = dict(BUILTIN_OUI)
    try:
        with open(path) as f:
            for line in f:
                parts = line.strip().split(",", 1)
                if len(parts) == 2:
                    table[parts[0].upper().replace("-", ":")] = parts[1]
    except FileNotFoundError:
        pass
    return table


def mac_vendor(mac, table):
    return table.get(mac.upper()[0:8], "Unknown")


def guess_subnet(iface=None):
    iface = iface or conf.iface
    try:
        ip = get_if_addr(iface)
    except Exception:
        ip = None
    if not ip or ip == "0.0.0.0":
        for i in get_if_list():
            try:
                a = get_if_addr(i)
            except Exception:
                continue
            if a and a != "0.0.0.0" and not a.startswith("127."):
                ip = a
                break
    if not ip or ip == "0.0.0.0":
        raise RuntimeError("Could not detect a local IPv4 address - enter a target manually")
    return ".".join(ip.split(".")[:3]) + ".0/24"


def arp_scan(target, iface=None, timeout=3):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
    kw = {"timeout": timeout, "verbose": False}
    if iface:
        kw["iface"] = iface
    answered, _ = srp(pkt, **kw)
    return [{"ip": r.psrc, "mac": r.hwsrc} for _, r in answered]


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def netbios_name(ip, timeout=1):
    query = (
        b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
        b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00"
        b"\x00\x21\x00\x01"
    )
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(query, (ip, 137))
        data, _ = s.recvfrom(1024)
        s.close()
        if len(data) > 56:
            raw = data[57:72]
            return raw.split(b"\x00")[0].split(b" ")[0].decode(errors="ignore").strip()
    except Exception:
        pass
    return ""


def ping_ttl(ip, timeout=1):
    try:
        reply = sr1(IP(dst=ip) / ICMP(), timeout=timeout, verbose=False)
        if reply:
            return reply.ttl
    except Exception:
        pass
    return None


def guess_os(ttl):
    if ttl is None:
        return "no reply"
    if ttl <= 64:
        return f"Linux/Android/iOS-like (ttl={ttl})"
    if ttl <= 128:
        return f"Windows-like (ttl={ttl})"
    return f"Network device / other (ttl={ttl})"


def scan_ports(ip, ports, timeout=0.6):
    found = {}
    for port, label in ports.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    found[port] = label
        except Exception:
            pass
    return found


def grab_banner(ip, port, timeout=1.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            if port in (80, 8008, 8080, 8443, 443):
                try:
                    s.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
                except Exception:
                    pass
            data = s.recv(256)
            return re.sub(r"\s+", " ", data.decode(errors="ignore").strip())[:120]
    except Exception:
        return ""


def profile_device(dev, ports, oui, do_banners, do_ttl):
    ip, mac = dev["ip"], dev["mac"]
    r = {"ip": ip, "mac": mac, "vendor": mac_vendor(mac, oui),
         "hostname": reverse_dns(ip) or netbios_name(ip)}
    r["open_ports"] = scan_ports(ip, ports)
    r["banners"] = ({p: grab_banner(ip, p) for p in r["open_ports"]}
                    if do_banners and r["open_ports"] else {})
    r["os_guess"] = guess_os(ping_ttl(ip)) if do_ttl else ""
    return r


def discover_my_addrs():
    addrs = set()
    for iface in get_if_list():
        try:
            a = get_if_addr(iface)
            if a and a != "0.0.0.0":
                addrs.add(a)
        except Exception:
            pass
    try:
        addrs.add(socket.gethostbyname(socket.gethostname()))
    except Exception:
        pass
    return addrs


def is_admin():
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return True


def printable(data, limit=60):
    chunk = data[:limit]
    ok = sum(32 <= b < 127 or b in (9, 10, 13) for b in chunk)
    if chunk and ok / len(chunk) > 0.9:
        return repr(chunk.decode("ascii", errors="replace")) + ("..." if len(data) > limit else "")
    return chunk[: limit // 2].hex() + " (binary)"


def ip_key(s):
    try:
        return tuple(int(x) for x in s.split("."))
    except Exception:
        return (999, s)


# ───────────────────────────── application ─────────────────────────────
class NetScope(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NetScope - Network Sniffer & Device Profiler")
        self.geometry("1280x800")
        self.minsize(1000, 640)
        self.configure(bg=BG)

        fams = set(tkfont.families())
        pick = lambda opts, fb: next((f for f in opts if f in fams), fb)
        self.f_ui = pick(("Segoe UI", "SF Pro Text", "Helvetica Neue", "Ubuntu", "Cantarell", "DejaVu Sans"), "TkDefaultFont")
        self.f_mono = pick(("Consolas", "SF Mono", "Menlo", "DejaVu Sans Mono", "Ubuntu Mono"), "Courier")

        # state
        self.q = queue.Queue()
        self.my_addrs = discover_my_addrs()
        self.oui = load_oui_file("oui.csv") if os.path.exists("oui.csv") else dict(BUILTIN_OUI)
        self.devices = {}
        self.scanning = False
        self.sniffer = None
        self.writer = None
        self.paused = False
        self.seq = 0
        self.pkts = {}
        self.stats = Counter()          # "proto:scope" -> packets
        self.proto_totals = Counter()   # proto -> packets
        self.talkers = Counter()        # ip -> bytes
        self.total_pkts = 0
        self.ip_to_name = {}
        self.hide_acks_flag = True
        self._last_stats = 0

        self._style()
        self._build()
        self._autodetect(silent=True)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(60, self._poll)

    # ── styling ──
    def _style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        ui = (self.f_ui, 10)
        self.option_add("*TCombobox*Listbox.background", PANEL2)
        self.option_add("*TCombobox*Listbox.foreground", FG)
        self.option_add("*TCombobox*Listbox.selectBackground", ACCENT)
        self.option_add("*Font", ui)

        s.configure(".", background=BG, foreground=FG, font=ui, bordercolor=BORDER,
                    lightcolor=BORDER, darkcolor=BORDER, troughcolor=PANEL, focuscolor=BG)
        s.configure("TFrame", background=BG)
        s.configure("Panel.TFrame", background=PANEL)
        s.configure("TLabel", background=BG, foreground=FG)
        s.configure("Panel.TLabel", background=PANEL, foreground=FG)
        s.configure("Muted.TLabel", background=PANEL, foreground=MUTED)
        s.configure("Title.TLabel", background=BG, foreground=FG, font=(self.f_ui, 16, "bold"))
        s.configure("Sub.TLabel", background=BG, foreground=MUTED)
        s.configure("Warn.TLabel", background=BG, foreground=AMBER)
        s.configure("Status.TLabel", background=PANEL, foreground=MUTED, padding=(10, 5))
        s.configure("Card.TLabel", background=PANEL2, foreground=FG, font=(self.f_ui, 18, "bold"))
        s.configure("CardCap.TLabel", background=PANEL2, foreground=MUTED, font=(self.f_ui, 9))

        s.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(0, 0, 0, 0))
        s.configure("TNotebook.Tab", background=BG, foreground=MUTED, padding=(20, 9),
                    borderwidth=0, font=(self.f_ui, 10, "bold"))
        s.map("TNotebook.Tab", background=[("selected", PANEL)], foreground=[("selected", FG)])

        s.configure("TButton", background=PANEL2, foreground=FG, padding=(12, 6), borderwidth=0, relief="flat")
        s.map("TButton", background=[("active", BORDER), ("disabled", PANEL)], foreground=[("disabled", MUTED)])
        s.configure("Accent.TButton", background=ACCENT, foreground="white", font=(self.f_ui, 10, "bold"))
        s.map("Accent.TButton", background=[("active", ACCENT_H), ("disabled", PANEL2)], foreground=[("disabled", MUTED)])
        s.configure("Danger.TButton", background=RED, foreground="white", font=(self.f_ui, 10, "bold"))
        s.map("Danger.TButton", background=[("active", "#ff6b63"), ("disabled", PANEL2)], foreground=[("disabled", MUTED)])

        s.configure("TEntry", fieldbackground=PANEL2, foreground=FG, insertcolor=FG, padding=5, bordercolor=BORDER)
        s.configure("TCombobox", fieldbackground=PANEL2, background=PANEL2, foreground=FG,
                    arrowcolor=MUTED, padding=4, bordercolor=BORDER)
        s.map("TCombobox", fieldbackground=[("readonly", PANEL2)], foreground=[("readonly", FG)])
        s.configure("TCheckbutton", background=PANEL, foreground=FG)
        s.map("TCheckbutton", background=[("active", PANEL)])
        s.configure("TSpinbox", fieldbackground=PANEL2, foreground=FG, arrowcolor=MUTED, padding=4)

        s.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=FG,
                    rowheight=25, borderwidth=0, font=(self.f_ui, 10))
        s.map("Treeview", background=[("selected", "#27406b")], foreground=[("selected", "white")])
        s.configure("Treeview.Heading", background=PANEL2, foreground=MUTED, relief="flat",
                    padding=(8, 6), font=(self.f_ui, 9, "bold"))
        s.map("Treeview.Heading", background=[("active", BORDER)])
        s.configure("Horizontal.TProgressbar", background=ACCENT, troughcolor=PANEL2, borderwidth=0, thickness=6)
        for o in ("Vertical", "Horizontal"):
            s.configure(f"{o}.TScrollbar", background=PANEL2, troughcolor=PANEL, arrowcolor=MUTED,
                        borderwidth=0, bordercolor=PANEL)
            s.map(f"{o}.TScrollbar", background=[("active", BORDER)])
        s.configure("TPanedwindow", background=BG)

    # ── layout ──
    def _build(self):
        head = ttk.Frame(self, padding=(18, 14, 18, 8))
        head.pack(fill="x")
        left = ttk.Frame(head)
        left.pack(side="left")
        ttk.Label(left, text="◉  NetScope", style="Title.TLabel").pack(anchor="w")
        ttk.Label(left, text="Passive sniffer + LAN device profiler", style="Sub.TLabel").pack(anchor="w")

        right = ttk.Frame(head)
        right.pack(side="right")
        ttk.Label(right, text="Interface", style="Sub.TLabel").pack(side="left", padx=(0, 6))
        self.iface_var = tk.StringVar(value=ALL_IFACES)
        ttk.Combobox(right, textvariable=self.iface_var, state="readonly", width=26,
                     values=[ALL_IFACES] + list(get_if_list())).pack(side="left")

        if not is_admin():
            ttk.Label(self, text="⚠  Not running with admin/root privileges - scanning and capture will likely fail.",
                      style="Warn.TLabel", padding=(18, 0, 18, 6)).pack(fill="x")

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=14, pady=(0, 0))
        t1, t2, t3 = (ttk.Frame(self.nb, style="Panel.TFrame") for _ in range(3))
        self.nb.add(t1, text="  Devices  ")
        self.nb.add(t2, text="  Live Capture  ")
        self.nb.add(t3, text="  Statistics  ")
        self._build_devices(t1)
        self._build_capture(t2)
        self._build_stats(t3)

        bar = ttk.Frame(self, style="Panel.TFrame")
        bar.pack(fill="x", side="bottom")
        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(bar, textvariable=self.status_var, style="Status.TLabel").pack(side="left")
        self.counter_var = tk.StringVar(value="0 devices  ·  0 packets")
        ttk.Label(bar, textvariable=self.counter_var, style="Status.TLabel").pack(side="right")

    def _tree(self, parent, cols, widths, height=None, anchors=None):
        """Treeview + scrollbars helper. cols = [(id, heading)]"""
        wrap = ttk.Frame(parent, style="Panel.TFrame")
        tv = ttk.Treeview(wrap, columns=[c for c, _ in cols], show="headings", selectmode="browse",
                          **({"height": height} if height else {}))
        for (cid, head), w in zip(cols, widths):
            tv.heading(cid, text=head, command=lambda c=cid, t=tv: self._sort(t, c, False))
            tv.column(cid, width=w, minwidth=40, anchor=(anchors or {}).get(cid, "w"))
        vs = ttk.Scrollbar(wrap, orient="vertical", command=tv.yview)
        hs = ttk.Scrollbar(wrap, orient="horizontal", command=tv.xview)
        tv.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        tv.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)
        return wrap, tv

    def _text(self, parent, height=8):
        wrap = ttk.Frame(parent, style="Panel.TFrame")
        t = tk.Text(wrap, height=height, bg=PANEL2, fg=FG, insertbackground=FG, relief="flat",
                    font=(self.f_mono, 10), padx=12, pady=10, wrap="word", state="disabled",
                    highlightthickness=0, selectbackground="#27406b")
        vs = ttk.Scrollbar(wrap, orient="vertical", command=t.yview)
        t.configure(yscrollcommand=vs.set)
        t.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        t.tag_configure("h", foreground=ACCENT, font=(self.f_mono, 10, "bold"))
        t.tag_configure("k", foreground=MUTED)
        t.tag_configure("good", foreground=GREEN)
        t.tag_configure("warn", foreground=AMBER)
        return wrap, t

    def _set_text(self, widget, parts):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        for txt, tag in parts:
            widget.insert("end", txt, tag)
        widget.configure(state="disabled")

    # ── Devices tab ──
    def _build_devices(self, parent):
        bar = ttk.Frame(parent, style="Panel.TFrame", padding=12)
        bar.pack(fill="x")
        ttk.Label(bar, text="Target", style="Panel.TLabel").grid(row=0, column=0, padx=(0, 6))
        self.target_var = tk.StringVar()
        ttk.Entry(bar, textvariable=self.target_var, width=20).grid(row=0, column=1)
        ttk.Button(bar, text="Auto-detect", command=self._autodetect).grid(row=0, column=2, padx=6)
        ttk.Label(bar, text="Ports", style="Panel.TLabel").grid(row=0, column=3, padx=(14, 6))
        self.ports_var = tk.StringVar()
        ttk.Entry(bar, textvariable=self.ports_var, width=22).grid(row=0, column=4)
        ttk.Label(bar, text="(blank = common)", style="Muted.TLabel").grid(row=0, column=5, padx=6)
        self.banner_var = tk.BooleanVar(value=True)
        self.ttl_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="Banners", variable=self.banner_var).grid(row=0, column=6, padx=(14, 4))
        ttk.Checkbutton(bar, text="OS guess", variable=self.ttl_var).grid(row=0, column=7, padx=4)
        self.scan_btn = ttk.Button(bar, text="▶  Scan network", style="Accent.TButton", command=self.start_scan)
        self.scan_btn.grid(row=0, column=8, padx=(16, 0))
        bar.columnconfigure(9, weight=1)
        ttk.Button(bar, text="Export…", command=self.export_devices).grid(row=0, column=10)

        self.progress = ttk.Progressbar(parent, mode="determinate")
        self.progress.pack(fill="x", padx=12, pady=(0, 6))

        pw = ttk.PanedWindow(parent, orient="vertical")
        pw.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        cols = [("ip", "IP address"), ("mac", "MAC"), ("vendor", "Vendor"), ("host", "Hostname"),
                ("os", "OS guess"), ("ports", "Open ports")]
        wrap, self.dev_tree = self._tree(pw, cols, [130, 140, 140, 200, 210, 300])
        pw.add(wrap, weight=3)
        self.dev_tree.bind("<<TreeviewSelect>>", self._on_dev_select)
        self.dev_tree.bind("<Double-1>", lambda e: self.capture_selected())

        lower = ttk.Frame(pw, style="Panel.TFrame")
        pw.add(lower, weight=2)
        top = ttk.Frame(lower, style="Panel.TFrame")
        top.pack(fill="x", pady=(6, 4))
        ttk.Label(top, text="Device details", style="Muted.TLabel").pack(side="left")
        ttk.Button(top, text="Capture this device →", command=self.capture_selected).pack(side="right")
        wrap, self.dev_text = self._text(lower, 8)
        wrap.pack(fill="both", expand=True)
        self._set_text(self.dev_text, [("Run a scan, then select a device to see ports and banners.\n"
                                        "Double-click a device to jump to Live Capture filtered to it.", "k")])

    def _autodetect(self, silent=False):
        iface = self.iface_var.get()
        try:
            self.target_var.set(guess_subnet(None if iface == ALL_IFACES else iface))
        except Exception as e:
            if not silent:
                messagebox.showwarning("Auto-detect", str(e))

    def start_scan(self):
        if self.scanning:
            return
        target = self.target_var.get().strip()
        if not target:
            self._autodetect()
            target = self.target_var.get().strip()
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            messagebox.showerror("Invalid target", f"'{target}' isn't a valid IP or subnet (e.g. 192.168.1.0/24).")
            return
        if net.num_addresses > 1024 and not messagebox.askyesno(
                "Large scan", f"{target} contains {net.num_addresses:,} addresses. Scan anyway?"):
            return
        if self.ports_var.get().strip():
            try:
                ports = {int(x): DEFAULT_PORTS.get(int(x), "custom")
                         for x in self.ports_var.get().replace(" ", "").split(",") if x}
            except ValueError:
                messagebox.showerror("Invalid ports", "Ports must be comma-separated numbers, e.g. 22,80,443")
                return
        else:
            ports = DEFAULT_PORTS

        iface = self.iface_var.get()
        iface = None if iface == ALL_IFACES else iface
        self.dev_tree.delete(*self.dev_tree.get_children())
        self.devices.clear()
        self._set_text(self.dev_text, [("Scanning…", "k")])
        self.scanning = True
        self.scan_btn.configure(state="disabled", text="Scanning…")
        self.progress.configure(mode="indeterminate")
        self.progress.start(12)
        self.status_var.set(f"ARP scanning {net} …")
        threading.Thread(target=self._scan_worker, daemon=True,
                         args=(str(net), iface, ports, self.banner_var.get(), self.ttl_var.get())).start()

    def _scan_worker(self, target, iface, ports, banners, ttl):
        try:
            devs = arp_scan(target, iface=iface)
            self.q.put(("arp_done", devs))
            if devs:
                with ThreadPoolExecutor(max_workers=20) as pool:
                    futs = [pool.submit(profile_device, d, ports, self.oui, banners, ttl) for d in devs]
                    for f in as_completed(futs):
                        try:
                            self.q.put(("dev", f.result()))
                        except Exception:
                            pass
            self.q.put(("scan_done", None))
        except PermissionError:
            self.q.put(("scan_err", "Permission denied - run as root / Administrator."))
        except Exception as e:
            self.q.put(("scan_err", str(e)))

    def _fmt_ports(self, d):
        return ", ".join(f"{p}/{l.split()[0]}" for p, l in sorted(d["open_ports"].items())) or "-"

    def _on_dev_select(self, _e=None):
        sel = self.dev_tree.selection()
        d = self.devices.get(sel[0]) if sel else None
        if not d or "open_ports" not in d:
            return
        parts = [(f"{d['ip']}\n", "h"),
                 ("MAC       ", "k"), (f"{d['mac']}\n", ""),
                 ("Vendor    ", "k"), (f"{d['vendor']}\n", ""),
                 ("Hostname  ", "k"), (f"{d['hostname'] or '-'}\n", ""),
                 ("OS guess  ", "k"), (f"{d['os_guess'] or '-'}\n\n", "")]
        if d["open_ports"]:
            parts.append(("Open ports\n", "h"))
            for p, l in sorted(d["open_ports"].items()):
                parts.append((f"  {p:<6}", "good"))
                parts.append((f"{l}", ""))
                b = d["banners"].get(p)
                if b:
                    parts.append((f"   {b}", "k"))
                parts.append(("\n", ""))
                if p in (21, 23, 139, 445, 3389):
                    parts.append(("        ↳ commonly exposed service - worth reviewing\n", "warn"))
        else:
            parts.append(("No open ports found (of the ports checked).\n", "k"))
        self._set_text(self.dev_text, parts)

    def capture_selected(self):
        sel = self.dev_tree.selection()
        if not sel:
            messagebox.showinfo("Capture", "Select a device first.")
            return
        self.filter_var.set(f"host {sel[0]}")
        self.nb.select(1)
        self.status_var.set(f"Filter set to host {sel[0]} - press Start. "
                            "(You'll only see its traffic if this machine can actually observe it.)")

    def export_devices(self):
        rows = [d for d in self.devices.values() if "open_ports" in d]
        if not rows:
            messagebox.showinfo("Export", "Nothing to export yet - run a scan first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                            filetypes=[("JSON", "*.json"), ("CSV", "*.csv")])
        if not path:
            return
        if path.lower().endswith(".csv"):
            with open(path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["ip", "mac", "vendor", "hostname", "os_guess", "open_ports", "banners"])
                for d in rows:
                    w.writerow([d["ip"], d["mac"], d["vendor"], d["hostname"], d["os_guess"],
                                self._fmt_ports(d), json.dumps(d["banners"])])
        else:
            with open(path, "w") as f:
                json.dump(rows, f, indent=2)
        self.status_var.set(f"Exported {len(rows)} devices → {path}")

    # ── Capture tab ──
    def _build_capture(self, parent):
        bar = ttk.Frame(parent, style="Panel.TFrame", padding=12)
        bar.pack(fill="x")
        ttk.Label(bar, text="BPF filter", style="Panel.TLabel").grid(row=0, column=0, padx=(0, 6))
        self.filter_var = tk.StringVar()
        ttk.Entry(bar, textvariable=self.filter_var, width=30).grid(row=0, column=1)
        presets = {"Presets…": "", "HTTPS": "tcp port 443", "HTTP": "tcp port 80", "DNS": "udp port 53",
                   "mDNS": "udp port 5353", "ARP": "arp", "ICMP": "icmp", "DHCP": "udp port 67 or udp port 68"}
        cb = ttk.Combobox(bar, values=list(presets), state="readonly", width=10)
        cb.set("Presets…")
        cb.grid(row=0, column=2, padx=6)
        cb.bind("<<ComboboxSelected>>", lambda e: (self.filter_var.set(presets[cb.get()]), cb.set("Presets…")))
        ttk.Label(bar, text="Max pkts", style="Panel.TLabel").grid(row=0, column=3, padx=(12, 6))
        self.count_var = tk.StringVar(value="0")
        ttk.Spinbox(bar, from_=0, to=10_000_000, textvariable=self.count_var, width=8).grid(row=0, column=4)

        self.start_btn = ttk.Button(bar, text="▶  Start", style="Accent.TButton", command=self.start_capture)
        self.start_btn.grid(row=0, column=5, padx=(16, 4))
        self.stop_btn = ttk.Button(bar, text="■  Stop", style="Danger.TButton", command=self.stop_capture, state="disabled")
        self.stop_btn.grid(row=0, column=6, padx=4)
        self.pause_btn = ttk.Button(bar, text="Pause view", command=self.toggle_pause, state="disabled")
        self.pause_btn.grid(row=0, column=7, padx=4)

        opts = ttk.Frame(parent, style="Panel.TFrame", padding=(12, 0, 12, 8))
        opts.pack(fill="x")
        self.hide_acks_var = tk.BooleanVar(value=True)
        self.hide_acks_var.trace_add("write", lambda *a: setattr(self, "hide_acks_flag", self.hide_acks_var.get()))
        self.autoscroll_var = tk.BooleanVar(value=True)
        self.save_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="Hide bare TCP ACKs", variable=self.hide_acks_var).pack(side="left")
        ttk.Checkbutton(opts, text="Auto-scroll", variable=self.autoscroll_var).pack(side="left", padx=14)
        ttk.Checkbutton(opts, text="Write live to .pcap on start", variable=self.save_var).pack(side="left")
        ttk.Button(opts, text="Clear", command=self.clear_capture).pack(side="right")
        ttk.Button(opts, text="Export buffer (.pcap)…", command=self.export_pcap).pack(side="right", padx=6)

        pw = ttk.PanedWindow(parent, orient="vertical")
        pw.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        cols = [("time", "Time"), ("src", "Source"), ("dst", "Destination"), ("proto", "Protocol"),
                ("scope", "Scope"), ("len", "Len"), ("info", "Info")]
        wrap, self.pkt_tree = self._tree(pw, cols, [100, 150, 220, 90, 130, 60, 520], anchors={"len": "e"})
        pw.add(wrap, weight=4)
        for tag, color in (("tcp", "#8fb8ff"), ("udp", TEAL), ("dns", PURPLE), ("arp", AMBER),
                           ("icmp", RED), ("other", MUTED)):
            self.pkt_tree.tag_configure(tag, foreground=color)
        self.pkt_tree.bind("<<TreeviewSelect>>", self._on_pkt_select)

        wrap, self.pkt_text = self._text(pw, 8)
        pw.add(wrap, weight=2)
        self._set_text(self.pkt_text, [("Select a packet to inspect its layers and hex dump.", "k")])

    def start_capture(self):
        if self.sniffer is not None:
            return
        try:
            count = max(0, int(self.count_var.get() or 0))
        except ValueError:
            messagebox.showerror("Invalid value", "Max packets must be a number (0 = unlimited).")
            return
        iface = self.iface_var.get()
        iface = None if iface == ALL_IFACES else iface
        bpf = self.filter_var.get().strip() or None
        self.writer = None
        if self.save_var.get():
            path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP", "*.pcap")])
            if path:
                try:
                    self.writer = PcapWriter(path, append=True, sync=True)
                except Exception as e:
                    messagebox.showerror("pcap", str(e))
                    return
        self.paused = False
        self.pause_btn.configure(text="Pause view")
        try:
            self.sniffer = AsyncSniffer(iface=iface, filter=bpf, count=count, store=False, prn=self._on_packet)
            self.sniffer.start()
        except PermissionError:
            self.sniffer = None
            messagebox.showerror("Permission denied", "Run NetScope with sudo / as Administrator.")
            return
        except Exception as e:
            self.sniffer = None
            messagebox.showerror("Capture failed", str(e))
            return
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.pause_btn.configure(state="normal")
        self.status_var.set(f"Capturing on {iface or 'all interfaces'}" + (f"  ·  filter: {bpf}" if bpf else ""))

    def stop_capture(self, msg="Capture stopped."):
        sn, self.sniffer = self.sniffer, None
        if sn is not None:
            try:
                sn.stop()
            except Exception:
                pass
        if self.writer:
            try:
                self.writer.close()
            except Exception:
                pass
            self.writer = None
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.pause_btn.configure(state="disabled")
        self.status_var.set(msg)

    def toggle_pause(self):
        self.paused = not self.paused
        self.pause_btn.configure(text="Resume view" if self.paused else "Pause view")
        self.status_var.set("View paused - capture continues in the background." if self.paused else "Resumed.")

    def clear_capture(self):
        self.pkt_tree.delete(*self.pkt_tree.get_children())
        self.pkts.clear()
        self.stats.clear()
        self.proto_totals.clear()
        self.talkers.clear()
        self.total_pkts = 0
        self._set_text(self.pkt_text, [("Cleared.", "k")])
        self._refresh_stats()

    def export_pcap(self):
        if not self.pkts:
            messagebox.showinfo("Export", "No packets in the buffer.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP", "*.pcap")])
        if path:
            wrpcap(path, list(self.pkts.values()))
            self.status_var.set(f"Saved {len(self.pkts)} packets → {path}")

    # runs on the sniffer thread: parse, then hand off through the queue
    def _on_packet(self, pkt):
        try:
            self._process(pkt)
        except Exception:
            pass

    def _classify(self, src, dst):
        if src in self.my_addrs or dst in self.my_addrs:
            return "me"
        if dst.startswith(("224.", "239.", "ff")) or dst.endswith(".255"):
            return "broadcast/multicast"
        return "other-device"

    def _learn_dns(self, pkt):
        if not pkt.haslayer(DNS):
            return
        d = pkt[DNS]
        if d.qr != 1 or not d.an:
            return
        for i in range(d.ancount):
            try:
                rr = d.an[i]
                if rr.type in (1, 28):
                    self.ip_to_name[str(rr.rdata)] = rr.rrname.decode(errors="replace").rstrip(".")
            except Exception:
                break

    def _process(self, pkt):
        t = datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S.%f")[:-3]
        ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if self.writer:
            try:
                self.writer.write(pkt)
            except Exception:
                pass

        if ip is None:
            if pkt.haslayer(ARP):
                a = pkt[ARP]
                op = "who-has" if a.op == 1 else "is-at"
                self.q.put(("pkt", dict(t=t, src=a.psrc, dst=a.pdst, proto="ARP", scope="broadcast/multicast"
                                        if a.op == 1 else "lan", size=len(pkt),
                                        info=f"ARP {op} {a.pdst} (from {a.psrc})"), pkt))
            return

        self._learn_dns(pkt)
        src, dst = ip.src, ip.dst
        scope = self._classify(src, dst)
        proto, detail = "Other", ""

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            proto, detail = "TCP", f"{tcp.sport} → {tcp.dport} [{tcp.flags}]"
            if self.hide_acks_flag and not pkt.haslayer(Raw) and str(tcp.flags) == "A":
                self.q.put(("ack", dict(src=src, proto=proto, scope=scope, size=len(pkt))))
                return
        elif pkt.haslayer(UDP):
            u = pkt[UDP]
            proto, detail = "UDP", f"{u.sport} → {u.dport}"
        elif pkt.haslayer(ICMP):
            ic = pkt[ICMP]
            proto, detail = "ICMP", f"type={ic.type} code={ic.code}"

        if pkt.haslayer(DNS):
            d = pkt[DNS]
            if d.qr == 0 and pkt.haslayer(DNSQR):
                detail += f" | DNS query: {pkt[DNSQR].qname.decode(errors='replace')}"
            else:
                ans = []
                for n in range(d.ancount):
                    try:
                        ans.append(str(d.an[n].rdata))
                    except Exception:
                        break
                detail += f" | DNS answer: {', '.join(ans) or 'none'}"
            proto += "/DNS"
        elif pkt.haslayer(Raw):
            detail += f" | {printable(pkt[Raw].load)}"

        name = self.ip_to_name.get(dst) or self.ip_to_name.get(src)
        dst_label = f"{dst}" + (f" ({name})" if name and self.ip_to_name.get(dst) else "")
        self.q.put(("pkt", dict(t=t, src=src, dst=dst_label, proto=proto, scope=scope,
                                size=len(pkt), info=detail), pkt))

    # ── packet table / details (UI thread) ──
    def _add_packet(self, rec, pkt):
        self._count(rec)
        if self.paused:
            return
        self.seq += 1
        iid = str(self.seq)
        p = rec["proto"]
        tag = ("dns" if "DNS" in p else "tcp" if p.startswith("TCP") else "udp" if p.startswith("UDP")
               else "arp" if p == "ARP" else "icmp" if p.startswith("ICMP") else "other")
        self.pkt_tree.insert("", "end", iid=iid, tags=(tag,),
                             values=(rec["t"], rec["src"], rec["dst"], p, rec["scope"], rec["size"], rec["info"]))
        self.pkts[iid] = pkt
        if len(self.pkts) > MAX_PKTS:
            for old in list(self.pkts)[:200]:
                self.pkts.pop(old, None)
                if self.pkt_tree.exists(old):
                    self.pkt_tree.delete(old)
        if self.autoscroll_var.get():
            self.pkt_tree.see(iid)

    def _count(self, rec):
        self.total_pkts += 1
        self.stats[f"{rec['proto']}:{rec['scope']}"] += 1
        self.proto_totals[rec["proto"]] += 1
        self.talkers[rec["src"]] += rec["size"]

    def _on_pkt_select(self, _e=None):
        sel = self.pkt_tree.selection()
        pkt = self.pkts.get(sel[0]) if sel else None
        if pkt is None:
            return
        parts = [("Layers\n", "h"), (pkt.show(dump=True) + "\n", "")]
        try:
            parts += [("Hex dump\n", "h"), (hexdump(pkt, dump=True) + "\n", "k")]
        except Exception:
            pass
        self._set_text(self.pkt_text, parts)

    # ── Statistics tab ──
    def _build_stats(self, parent):
        cards = ttk.Frame(parent, style="Panel.TFrame", padding=12)
        cards.pack(fill="x")
        self.card_vars = {}
        for i, (key, cap) in enumerate((("pkts", "PACKETS"), ("protos", "PROTOCOLS"),
                                        ("talk", "TALKERS"), ("dns", "DNS NAMES LEARNED"))):
            f = tk.Frame(cards, bg=PANEL2, padx=18, pady=12)
            f.grid(row=0, column=i, padx=(0 if i == 0 else 10, 0), sticky="ew")
            cards.columnconfigure(i, weight=1)
            v = tk.StringVar(value="0")
            self.card_vars[key] = v
            ttk.Label(f, textvariable=v, style="Card.TLabel").pack(anchor="w")
            ttk.Label(f, text=cap, style="CardCap.TLabel").pack(anchor="w")

        body = ttk.Frame(parent, style="Panel.TFrame")
        body.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(1, weight=1)

        ttk.Label(body, text="Protocol breakdown", style="Muted.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 4))
        self.chart = tk.Canvas(body, bg=PANEL2, highlightthickness=0)
        self.chart.grid(row=1, column=0, sticky="nsew", padx=(0, 8))
        self.chart.bind("<Configure>", lambda e: self._refresh_stats())

        right = ttk.Frame(body, style="Panel.TFrame")
        right.grid(row=0, column=1, rowspan=2, sticky="nsew")
        right.rowconfigure(1, weight=1)
        right.rowconfigure(3, weight=1)
        right.columnconfigure(0, weight=1)
        ttk.Label(right, text="Top talkers (bytes sent, as seen)", style="Muted.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 4))
        wrap, self.talk_tree = self._tree(right, [("ip", "Address"), ("name", "Name"), ("bytes", "Bytes")],
                                          [150, 200, 90], anchors={"bytes": "e"})
        wrap.grid(row=1, column=0, sticky="nsew")
        ttk.Label(right, text="Scope breakdown", style="Muted.TLabel").grid(row=2, column=0, sticky="w", pady=(10, 4))
        wrap, self.scope_tree = self._tree(right, [("k", "Protocol : scope"), ("n", "Packets")], [260, 90],
                                           anchors={"n": "e"})
        wrap.grid(row=3, column=0, sticky="nsew")

    def _refresh_stats(self):
        self.card_vars["pkts"].set(f"{self.total_pkts:,}")
        self.card_vars["protos"].set(str(len(self.proto_totals)))
        self.card_vars["talk"].set(str(len(self.talkers)))
        self.card_vars["dns"].set(str(len(self.ip_to_name)))

        for tv in (self.talk_tree, self.scope_tree):
            tv.delete(*tv.get_children())
        for ip, b in self.talkers.most_common(15):
            self.talk_tree.insert("", "end", values=(ip, self.ip_to_name.get(ip, ""), f"{b:,}"))
        for k, n in self.stats.most_common(30):
            self.scope_tree.insert("", "end", values=(k, f"{n:,}"))

        c = self.chart
        c.delete("all")
        w, h = max(c.winfo_width(), 100), max(c.winfo_height(), 60)
        items = self.proto_totals.most_common(8)
        if not items:
            c.create_text(w / 2, h / 2, text="No traffic captured yet", fill=MUTED, font=(self.f_ui, 10))
            return
        top = items[0][1]
        row_h = min(34, (h - 20) / len(items))
        palette = {"TCP": "#8fb8ff", "UDP": TEAL, "ARP": AMBER, "ICMP": RED}
        for i, (p, n) in enumerate(items):
            y = 14 + i * row_h
            col = PURPLE if "DNS" in p else palette.get(p, MUTED)
            c.create_text(12, y + row_h / 2 - 3, text=p, anchor="w", fill=FG, font=(self.f_ui, 9, "bold"))
            x0, x1 = 100, w - 80
            bw = max(2, (x1 - x0) * n / top)
            c.create_rectangle(x0, y, x0 + bw, y + row_h - 10, fill=col, outline="")
            c.create_text(x0 + bw + 8, y + (row_h - 10) / 2, text=f"{n:,}", anchor="w", fill=MUTED, font=(self.f_ui, 9))

    # ── sorting ──
    def _sort(self, tree, col, reverse):
        rows = [(tree.set(k, col), k) for k in tree.get_children("")]
        if col == "ip":
            rows.sort(key=lambda r: ip_key(r[0]), reverse=reverse)
        else:
            def num(v):
                try:
                    return (0, float(v.replace(",", "")))
                except ValueError:
                    return (1, v.lower())
            rows.sort(key=lambda r: num(r[0]), reverse=reverse)
        for i, (_, k) in enumerate(rows):
            tree.move(k, "", i)
        tree.heading(col, command=lambda: self._sort(tree, col, not reverse))

    # ── main-thread event pump ──
    def _poll(self):
        try:
            for _ in range(400):
                kind, *payload = self.q.get_nowait()
                if kind == "pkt":
                    self._add_packet(*payload)
                elif kind == "ack":
                    self._count(payload[0])
                elif kind == "arp_done":
                    devs = payload[0]
                    for d in devs:
                        self.devices[d["ip"]] = dict(d)
                        self.dev_tree.insert("", "end", iid=d["ip"], values=(
                            d["ip"], d["mac"], mac_vendor(d["mac"], self.oui), "…", "…", "profiling…"))
                    self.progress.stop()
                    self.progress.configure(mode="determinate", maximum=max(len(devs), 1), value=0)
                    self.status_var.set(f"Found {len(devs)} device(s) - profiling ports, banners, TTL …")
                elif kind == "dev":
                    d = payload[0]
                    self.devices[d["ip"]] = d
                    self.dev_tree.item(d["ip"], values=(d["ip"], d["mac"], d["vendor"], d["hostname"] or "-",
                                                         d["os_guess"] or "-", self._fmt_ports(d)))
                    self.progress.step(1)
                elif kind == "scan_done":
                    self._finish_scan(f"Scan complete - {len(self.devices)} device(s).")
                    self._set_text(self.dev_text, [("Select a device to see ports and banners.", "k")])
                elif kind == "scan_err":
                    self._finish_scan("Scan failed.")
                    messagebox.showerror("Scan failed", payload[0])
        except queue.Empty:
            pass

        # detect a capture that ended by itself (count reached, bad filter, etc.)
        sn = self.sniffer
        if sn is not None and getattr(sn, "thread", None) is not None and not sn.thread.is_alive():
            err = getattr(sn, "exception", None)
            self.stop_capture("Capture finished." if not err else f"Capture error: {err}")
            if err:
                messagebox.showerror("Capture error", str(err))

        now = datetime.now().timestamp()
        if now - self._last_stats > 1.0:
            self._last_stats = now
            self._refresh_stats()
        self.counter_var.set(f"{len(self.devices)} devices  ·  {self.total_pkts:,} packets")
        self.after(50, self._poll)

    def _finish_scan(self, msg):
        self.scanning = False
        self.progress.stop()
        self.progress.configure(mode="determinate", value=0)
        self.scan_btn.configure(state="normal", text="▶  Scan network")
        self.status_var.set(msg)

    def _on_close(self):
        self.stop_capture()
        self.destroy()


if __name__ == "__main__":
    NetScope().mainloop()