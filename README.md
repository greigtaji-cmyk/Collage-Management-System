"""
School ERP + LMS (single-file, tkinter + ttk) - ready to run in VS Code / Visual Studio

Run:
  python main.py

Notes:
- Uses only the standard tkinter/ttk UI toolkit for the main interface.
- Optional features:
  - matplotlib is used for embedded analytics (pip install matplotlib)
  - reportlab is used for PDF export (pip install reportlab)
  - plyer is used for system notifications (pip install plyer)
  - bcrypt is optional; if not installed the app falls back to secure PBKDF2-SHA256 hashing.
- The app stores data in school_erp.db in the same folder.
"""

import binascii
import hashlib
import hmac
import secrets
import sqlite3
import tkinter as tk
from datetime import date, datetime
from tkinter import StringVar, Tk, messagebox
from tkinter import ttk

try:
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
except Exception:
    Figure = None
    FigureCanvasTkAgg = None

try:
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate
except Exception:
    getSampleStyleSheet = None
    Paragraph = None
    SimpleDocTemplate = None

try:
    from plyer import notification
except Exception:
    notification = None

try:
    import bcrypt

    _HAS_BCRYPT = True
except Exception:
    bcrypt = None
    _HAS_BCRYPT = False


DB_NAME = "school_erp.db"
FONT = "Segoe UI"
COLORS = {
    "background": "#f5f7fb",
    "card": "#ffffff",
    "card_alt": "#f8fafc",
    "sidebar": "#111827",
    "sidebar_hover": "#1f2937",
    "sidebar_active": "#2563eb",
    "accent": "#2563eb",
    "accent_dark": "#1d4ed8",
    "accent_soft": "#e0ecff",
    "teal": "#0f766e",
    "teal_soft": "#ccfbf1",
    "orange": "#ea580c",
    "orange_soft": "#ffedd5",
    "purple": "#7c3aed",
    "purple_soft": "#ede9fe",
    "success": "#16a34a",
    "warning": "#d97706",
    "danger": "#dc2626",
    "text": "#111827",
    "muted": "#64748b",
    "border": "#d8e0eb",
    "field": "#f8fafc",
}


# -------------------------
# Password hashing helpers
# -------------------------
def hash_password(password: str) -> str:
    if _HAS_BCRYPT:
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        return "bcrypt$" + hashed.decode("utf-8")

    iterations = 200_000
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
    )
    return f"pbkdf2${iterations}${salt}${binascii.hexlify(dk).decode('ascii')}"


def verify_password(password: str, stored) -> bool:
    """Supports the current prefixed format and older raw bcrypt rows."""
    if isinstance(stored, bytes):
        if _HAS_BCRYPT:
            try:
                return bcrypt.checkpw(password.encode("utf-8"), stored)
            except Exception:
                return False
        try:
            stored = stored.decode("utf-8")
        except Exception:
            return False

    if not isinstance(stored, str):
        return False

    if stored.startswith("bcrypt$") and _HAS_BCRYPT:
        hashed = stored.split("$", 1)[1].encode("utf-8")
        try:
            return bcrypt.checkpw(password.encode("utf-8"), hashed)
        except Exception:
            return False

    if stored.startswith("$2") and _HAS_BCRYPT:
        try:
            return bcrypt.checkpw(password.encode("utf-8"), stored.encode("utf-8"))
        except Exception:
            return False

    if stored.startswith("pbkdf2$"):
        try:
            _alg, iterations_s, salt, hashhex = stored.split("$", 3)
            iterations = int(iterations_s)
            dk = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                salt.encode("utf-8"),
                iterations,
            )
            actual = binascii.hexlify(dk).decode("ascii")
            return hmac.compare_digest(actual, hashhex)
        except Exception:
            return False

    return False


# -------------------------
# Database wrapper
# -------------------------
class Database:
    def __init__(self, db_path=DB_NAME):
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        self.create_tables()
        self.create_default_admin()
        self.seed_default_events()
        self.seed_default_courses()
        self.seed_default_library()
        self.seed_default_timetable()

    def create_tables(self):
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                role TEXT,
                fullname TEXT
            )
            """
        )
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS students(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id TEXT,
                fullname TEXT,
                course TEXT,
                gpa REAL,
                attendance REAL
            )
            """
        )
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS teachers(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                teacher_id TEXT,
                fullname TEXT,
                subject TEXT
            )
            """
        )
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS assignments(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                description TEXT,
                due_date TEXT
            )
            """
        )
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS fee_records(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id TEXT,
                student_name TEXT,
                amount REAL,
                status TEXT,
                due_date TEXT,
                paid_date TEXT,
                notes TEXT
            )
            """
        )
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS events(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                event_date TEXT,
                category TEXT,
                location TEXT,
                description TEXT
            )
            """
        )
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS courses(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT,
                title TEXT,
                teacher TEXT,
                room TEXT,
                credits REAL
            )
            """
        )
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS timetable(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                day_name TEXT,
                start_time TEXT,
                course TEXT,
                teacher TEXT,
                room TEXT
            )
            """
        )
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS library_books(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                accession_no TEXT,
                title TEXT,
                author TEXT,
                status TEXT,
                borrower_id TEXT,
                borrower_name TEXT,
                due_date TEXT
            )
            """
        )
        self.conn.commit()

    def create_default_admin(self):
        self.cursor.execute("SELECT * FROM users WHERE username=?", ("admin",))
        if not self.cursor.fetchone():
            pw = hash_password("admin123")
            self.cursor.execute(
                "INSERT INTO users(username,password,role,fullname) VALUES(?,?,?,?)",
                ("admin", pw, "admin", "System Admin"),
            )
            self.conn.commit()

    def seed_default_events(self):
        self.cursor.execute("SELECT COUNT(*) FROM events")
        if self.cursor.fetchone()[0]:
            return
        defaults = [
            (
                "Science Exhibition",
                "2026-06-12",
                "Academic",
                "Main Hall",
                "Project demos and STEM presentations.",
            ),
            (
                "Sports Day",
                "2026-07-05",
                "Sports",
                "Ground",
                "Track, field, and team events.",
            ),
            (
                "Annual Day",
                "2026-08-20",
                "Cultural",
                "Auditorium",
                "Performances, awards, and community celebration.",
            ),
        ]
        self.cursor.executemany(
            """
            INSERT INTO events(title,event_date,category,location,description)
            VALUES(?,?,?,?,?)
            """,
            defaults,
        )
        self.conn.commit()

    def seed_default_courses(self):
        self.cursor.execute("SELECT COUNT(*) FROM courses")
        if self.cursor.fetchone()[0]:
            return
        defaults = [
            ("MATH-101", "Mathematics", "Unassigned", "Room 101", 4),
            ("SCI-201", "Science", "Unassigned", "Lab 2", 4),
            ("CS-301", "Computer Science", "Unassigned", "ICT Lab", 3),
        ]
        self.cursor.executemany(
            "INSERT INTO courses(code,title,teacher,room,credits) VALUES(?,?,?,?,?)",
            defaults,
        )
        self.conn.commit()

    def seed_default_library(self):
        self.cursor.execute("SELECT COUNT(*) FROM library_books")
        if self.cursor.fetchone()[0]:
            return
        defaults = [
            ("BK-1001", "Introduction to Algorithms", "Cormen et al.", "Available", "", "", ""),
            ("BK-1002", "Concepts of Physics", "H. C. Verma", "Available", "", "", ""),
            ("BK-1003", "The Elements of Style", "Strunk and White", "Available", "", "", ""),
        ]
        self.cursor.executemany(
            """
            INSERT INTO library_books(accession_no,title,author,status,borrower_id,borrower_name,due_date)
            VALUES(?,?,?,?,?,?,?)
            """,
            defaults,
        )
        self.conn.commit()

    def seed_default_timetable(self):
        self.cursor.execute("SELECT COUNT(*) FROM timetable")
        if self.cursor.fetchone()[0]:
            return
        defaults = [
            ("Monday", "09:00", "MATH-101 - Mathematics", "Unassigned", "Room 101"),
            ("Monday", "10:00", "SCI-201 - Science", "Unassigned", "Lab 2"),
            ("Tuesday", "09:00", "CS-301 - Computer Science", "Unassigned", "ICT Lab"),
        ]
        self.cursor.executemany(
            "INSERT INTO timetable(day_name,start_time,course,teacher,room) VALUES(?,?,?,?,?)",
            defaults,
        )
        self.conn.commit()


# -------------------------
# UI helpers
# -------------------------
class ScrollableFrame(ttk.Frame):
    def __init__(self, container, background=None, *args, **kwargs):
        super().__init__(container, style="Surface.TFrame", *args, **kwargs)
        bg = background or COLORS["background"]
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, bd=0)
        self.scrollable_frame = ttk.Frame(self.canvas, style="Surface.TFrame")
        self.window_id = self.canvas.create_window(
            (0, 0),
            window=self.scrollable_frame,
            anchor="nw",
        )
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=scrollbar.set)

        self.scrollable_frame.bind("<Configure>", self._update_scroll_region)
        self.canvas.bind("<Configure>", self._fit_inner_width)
        self.canvas.bind("<Enter>", self._bind_mousewheel)
        self.canvas.bind("<Leave>", self._unbind_mousewheel)
        self.scrollable_frame.bind("<Enter>", self._bind_mousewheel)
        self.scrollable_frame.bind("<Leave>", self._unbind_mousewheel)

        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def _update_scroll_region(self, _event=None):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _fit_inner_width(self, event):
        self.canvas.itemconfigure(self.window_id, width=event.width)

    def _bind_mousewheel(self, _event=None):
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind_all("<Button-4>", self._on_linux_scroll)
        self.canvas.bind_all("<Button-5>", self._on_linux_scroll)

    def _unbind_mousewheel(self, _event=None):
        self.canvas.unbind_all("<MouseWheel>")
        self.canvas.unbind_all("<Button-4>")
        self.canvas.unbind_all("<Button-5>")

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _on_linux_scroll(self, event):
        direction = -1 if event.num == 4 else 1
        self.canvas.yview_scroll(direction, "units")


# -------------------------
# Main application
# -------------------------
class SchoolERP:
    def __init__(self, root):
        self.root = root
        self.root.title("EduCore ERP + LMS")
        self.root.geometry("1220x780")
        self.root.minsize(1040, 680)
        self.root.configure(bg=COLORS["background"])

        self.db = Database()
        self.current_user = None
        self.active_page = None
        self.nav_buttons = {}
        self.status_var = StringVar(value="Ready")
        self.header_title_var = StringVar(value="")
        self.header_subtitle_var = StringVar(value="")
        self.user_badge_var = StringVar(value="")

        self.configure_styles()

        self.sidebar_frame = tk.Frame(
            self.root,
            bg=COLORS["sidebar"],
            width=250,
            highlightthickness=0,
        )
        self.sidebar_frame.pack_propagate(False)

        self.main_frame = tk.Frame(self.root, bg=COLORS["background"])
        self.header_frame = tk.Frame(self.main_frame, bg=COLORS["background"])
        self.content_frame = tk.Frame(self.main_frame, bg=COLORS["background"])
        self.status_bar = tk.Label(
            self.main_frame,
            textvariable=self.status_var,
            bg="#e8eef7",
            fg=COLORS["muted"],
            anchor="w",
            padx=16,
            pady=7,
            font=(FONT, 9),
        )

        self.nav_items = [
            ("Dashboard", self.admin_dashboard, False),
            ("Students", self.students_page, False),
            ("Teachers", self.teachers_page, False),
            ("Courses", self.courses_page, False),
            ("Attendance", self.attendance_page, False),
            ("Timetable", self.timetable_page, False),
            ("Assignments", self.assignments_page, False),
            ("Library", self.library_page, False),
            ("Analytics", self.analytics_page, False),
            ("GPA Calculator", self.gpa_page, False),
            ("Events", self.events_page, False),
            ("Notifications", self.notification_center, False),
            ("Chat", self.chat_page, False),
            ("Fees", self.fees_page, False),
            ("AI Assistant", self.ai_assistant_page, False),
            ("Export PDF", self.export_pdf, True),
        ]

        self.build_header()
        self.login_page()

    # ---------------------
    # Styling and utilities
    # ---------------------
    def configure_styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure(
            ".",
            font=(FONT, 10),
            background=COLORS["background"],
            foreground=COLORS["text"],
        )
        style.configure("Surface.TFrame", background=COLORS["background"])
        style.configure("Card.TFrame", background=COLORS["card"])
        style.configure("TLabel", background=COLORS["background"], foreground=COLORS["text"])
        style.configure(
            "Muted.TLabel",
            background=COLORS["background"],
            foreground=COLORS["muted"],
            font=(FONT, 10),
        )
        style.configure(
            "Card.TLabel",
            background=COLORS["card"],
            foreground=COLORS["text"],
            font=(FONT, 10),
        )
        style.configure(
            "CardMuted.TLabel",
            background=COLORS["card"],
            foreground=COLORS["muted"],
            font=(FONT, 9),
        )
        style.configure(
            "TEntry",
            fieldbackground=COLORS["field"],
            bordercolor=COLORS["border"],
            lightcolor=COLORS["border"],
            darkcolor=COLORS["border"],
            padding=(8, 7),
        )
        style.configure(
            "TButton",
            font=(FONT, 10, "bold"),
            padding=(12, 8),
            borderwidth=0,
        )
        style.configure(
            "Accent.TButton",
            background=COLORS["accent"],
            foreground="#ffffff",
            borderwidth=0,
        )
        style.configure(
            "Secondary.TButton",
            background="#e2e8f0",
            foreground=COLORS["text"],
            borderwidth=0,
        )
        style.configure(
            "Danger.TButton",
            background=COLORS["danger"],
            foreground="#ffffff",
            borderwidth=0,
        )
        style.map(
            "Accent.TButton",
            background=[("active", COLORS["accent_dark"]), ("pressed", COLORS["accent_dark"])],
            foreground=[("disabled", "#dbeafe"), ("!disabled", "#ffffff")],
        )
        style.map(
            "Secondary.TButton",
            background=[("active", "#cbd5e1"), ("pressed", "#cbd5e1")],
        )
        style.map(
            "Danger.TButton",
            background=[("active", "#b91c1c"), ("pressed", "#b91c1c")],
            foreground=[("!disabled", "#ffffff")],
        )
        style.configure(
            "Treeview",
            background=COLORS["card"],
            fieldbackground=COLORS["card"],
            foreground=COLORS["text"],
            rowheight=34,
            borderwidth=0,
            font=(FONT, 10),
        )
        style.configure(
            "Treeview.Heading",
            background="#edf2f8",
            foreground=COLORS["text"],
            relief="flat",
            font=(FONT, 10, "bold"),
            padding=(8, 8),
        )
        style.map("Treeview", background=[("selected", COLORS["accent"])])
        style.configure(
            "Horizontal.TProgressbar",
            troughcolor="#e2e8f0",
            background=COLORS["teal"],
            bordercolor="#e2e8f0",
            lightcolor=COLORS["teal"],
            darkcolor=COLORS["teal"],
        )

    def clear_content(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def clear_sidebar(self):
        for widget in self.sidebar_frame.winfo_children():
            widget.destroy()

    def set_status(self, message):
        self.status_var.set(message)

    def scalar(self, query, params=()):
        self.db.cursor.execute(query, params)
        row = self.db.cursor.fetchone()
        return row[0] if row else 0

    def money(self, amount):
        return f"${float(amount or 0):,.2f}"

    def get_float(self, value, field_name, minimum=0, maximum=None):
        try:
            number = float(value)
        except Exception as exc:
            raise ValueError(f"{field_name} must be a number") from exc
        if number < minimum:
            raise ValueError(f"{field_name} must be at least {minimum}")
        if maximum is not None and number > maximum:
            raise ValueError(f"{field_name} must be no more than {maximum}")
        return number

    def selected_iid(self, tree, message="Select a row first"):
        selected = tree.selection()
        if not selected:
            messagebox.showwarning("Select row", message)
            return None
        return selected[0]

    def clear_text(self, box):
        box.delete("1.0", "end")

    def student_choices(self):
        self.db.cursor.execute("SELECT student_id, fullname FROM students ORDER BY fullname")
        return [f"{student_id} - {name}" for student_id, name in self.db.cursor.fetchall()]

    def teacher_choices(self):
        self.db.cursor.execute("SELECT fullname FROM teachers ORDER BY fullname")
        return [row[0] for row in self.db.cursor.fetchall()] or ["Unassigned"]

    def course_choices(self):
        self.db.cursor.execute("SELECT code, title FROM courses ORDER BY code, title")
        return [f"{code} - {title}" for code, title in self.db.cursor.fetchall()]

    def parse_student_choice(self, choice):
        if " - " not in choice:
            return "", ""
        student_id, student_name = choice.split(" - ", 1)
        return student_id.strip(), student_name.strip()

    def notify(self, title, message):
        self.set_status(f"{title}: {message}")
        if notification:
            try:
                notification.notify(title=title, message=message, timeout=4)
            except Exception:
                pass

    def card(self, parent, padding=16):
        return tk.Frame(
            parent,
            bg=COLORS["card"],
            highlightbackground=COLORS["border"],
            highlightthickness=1,
            bd=0,
            padx=padding,
            pady=padding,
        )

    def pill_label(self, parent, text, bg=None, fg=None):
        return tk.Label(
            parent,
            text=text,
            bg=bg or COLORS["accent_soft"],
            fg=fg or COLORS["accent_dark"],
            font=(FONT, 9, "bold"),
            padx=10,
            pady=5,
        )

    def text_area(self, parent, height=6, readonly=False):
        box = tk.Text(
            parent,
            height=height,
            bg=COLORS["field"],
            fg=COLORS["text"],
            insertbackground=COLORS["text"],
            relief="flat",
            bd=0,
            padx=12,
            pady=10,
            wrap="word",
            font=(FONT, 10),
        )
        if readonly:
            box.configure(state="disabled")
        return box

    def append_text(self, box, text):
        box.configure(state="normal")
        box.insert("end", text)
        box.see("end")
        box.configure(state="disabled")

    def empty_state(self, parent, title, body):
        frame = self.card(parent, padding=18)
        frame.pack(fill="x", pady=10)
        tk.Label(
            frame,
            text=title,
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT, 12, "bold"),
        ).pack(anchor="w")
        tk.Label(
            frame,
            text=body,
            bg=COLORS["card"],
            fg=COLORS["muted"],
            font=(FONT, 10),
            wraplength=720,
            justify="left",
        ).pack(anchor="w", pady=(5, 0))

    def create_tree(self, parent, columns, height=12):
        wrap = tk.Frame(parent, bg=COLORS["card"])
        wrap.pack(fill="both", expand=True, pady=(10, 0))
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)

        tree = ttk.Treeview(wrap, columns=columns, show="headings", height=height)
        ybar = ttk.Scrollbar(wrap, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=ybar.set)

        for column in columns:
            tree.heading(column, text=column)
            tree.column(column, width=140, minwidth=90, anchor="w")

        tree.grid(row=0, column=0, sticky="nsew")
        ybar.grid(row=0, column=1, sticky="ns")
        tree.tag_configure("even", background="#ffffff")
        tree.tag_configure("odd", background=COLORS["card_alt"])
        tree.tag_configure("success", foreground=COLORS["success"])
        tree.tag_configure("warning", foreground=COLORS["warning"])
        tree.tag_configure("danger", foreground=COLORS["danger"])
        return tree

    # ---------------------
    # App shell
    # ---------------------
    def build_header(self):
        self.header_frame.columnconfigure(0, weight=1)
        left = tk.Frame(self.header_frame, bg=COLORS["background"])
        left.grid(row=0, column=0, sticky="ew", padx=28, pady=(18, 16))

        tk.Label(
            left,
            textvariable=self.header_title_var,
            bg=COLORS["background"],
            fg=COLORS["text"],
            font=(FONT, 24, "bold"),
        ).pack(anchor="w")
        tk.Label(
            left,
            textvariable=self.header_subtitle_var,
            bg=COLORS["background"],
            fg=COLORS["muted"],
            font=(FONT, 10),
        ).pack(anchor="w", pady=(4, 0))

        right = tk.Frame(self.header_frame, bg=COLORS["background"])
        right.grid(row=0, column=1, sticky="e", padx=28, pady=(18, 16))
        tk.Label(
            right,
            textvariable=self.user_badge_var,
            bg=COLORS["accent_soft"],
            fg=COLORS["accent_dark"],
            font=(FONT, 9, "bold"),
            padx=12,
            pady=7,
        ).pack(anchor="e")

    def show_shell(self):
        self.main_frame.pack_forget()
        self.sidebar_frame.pack_forget()
        self.header_frame.pack_forget()
        self.content_frame.pack_forget()
        self.status_bar.pack_forget()

        self.sidebar_frame.pack(side="left", fill="y")
        self.main_frame.pack(side="right", fill="both", expand=True)
        self.header_frame.pack(fill="x")
        self.content_frame.pack(fill="both", expand=True, padx=28, pady=(0, 18))
        self.status_bar.pack(fill="x")

    def build_sidebar(self):
        self.clear_sidebar()
        self.nav_buttons = {}

        brand = tk.Frame(self.sidebar_frame, bg=COLORS["sidebar"])
        brand.pack(fill="x", padx=18, pady=(22, 14))
        tk.Label(
            brand,
            text="EduCore",
            bg=COLORS["sidebar"],
            fg="#ffffff",
            font=(FONT, 22, "bold"),
        ).pack(anchor="w")
        tk.Label(
            brand,
            text="School ERP + LMS",
            bg=COLORS["sidebar"],
            fg="#9ca3af",
            font=(FONT, 10),
        ).pack(anchor="w", pady=(2, 0))

        nav = tk.Frame(self.sidebar_frame, bg=COLORS["sidebar"])
        nav.pack(fill="both", expand=True, padx=12)
        for label, command, is_action in self.nav_items:
            btn = tk.Button(
                nav,
                text=label,
                anchor="w",
                relief="flat",
                bd=0,
                padx=14,
                pady=8,
                bg=COLORS["sidebar"],
                fg="#dbe6f7",
                activebackground=COLORS["sidebar_hover"],
                activeforeground="#ffffff",
                font=(FONT, 10, "bold"),
                cursor="hand2",
                command=lambda item=label, cmd=command, action=is_action: self.run_nav_item(
                    item,
                    cmd,
                    action,
                ),
            )
            btn.pack(fill="x", pady=2)
            btn.bind("<Enter>", lambda _event, b=btn, item=label: self.nav_hover(b, item, True))
            btn.bind("<Leave>", lambda _event, b=btn, item=label: self.nav_hover(b, item, False))
            self.nav_buttons[label] = btn

        user_box = tk.Frame(self.sidebar_frame, bg=COLORS["sidebar"])
        user_box.pack(fill="x", padx=18, pady=(10, 16))
        user_name = self.current_user[4] if self.current_user else "Not signed in"
        role = self.current_user[3].title() if self.current_user else "User"
        tk.Label(
            user_box,
            text=user_name,
            bg=COLORS["sidebar"],
            fg="#ffffff",
            font=(FONT, 10, "bold"),
            anchor="w",
        ).pack(fill="x")
        tk.Label(
            user_box,
            text=role,
            bg=COLORS["sidebar"],
            fg="#9ca3af",
            font=(FONT, 9),
            anchor="w",
        ).pack(fill="x", pady=(2, 8))
        tk.Button(
            user_box,
            text="Logout",
            command=self.logout,
            relief="flat",
            bd=0,
            padx=12,
            pady=9,
            bg=COLORS["danger"],
            fg="#ffffff",
            activebackground="#b91c1c",
            activeforeground="#ffffff",
            cursor="hand2",
            font=(FONT, 10, "bold"),
        ).pack(fill="x")

        self.update_nav_state()

    def run_nav_item(self, label, command, is_action):
        if is_action:
            command()
            return
        self.active_page = label
        command()

    def nav_hover(self, button, label, entering):
        if label == self.active_page:
            return
        button.configure(bg=COLORS["sidebar_hover"] if entering else COLORS["sidebar"])

    def update_nav_state(self):
        for label, button in self.nav_buttons.items():
            if label == self.active_page:
                button.configure(bg=COLORS["sidebar_active"], fg="#ffffff")
            else:
                button.configure(bg=COLORS["sidebar"], fg="#dbe6f7")

    def start_page(self, title, subtitle="", page_name=None, scroll=True):
        self.show_shell()
        self.active_page = page_name or title
        self.user_badge_var.set(f"Signed in as {self.current_user[4]}")
        self.header_title_var.set(title)
        self.header_subtitle_var.set(subtitle)
        self.update_nav_state()
        self.clear_content()

        if scroll:
            page = ScrollableFrame(self.content_frame, background=COLORS["background"])
            page.pack(fill="both", expand=True)
            container = page.scrollable_frame
        else:
            container = ttk.Frame(self.content_frame, style="Surface.TFrame")
            container.pack(fill="both", expand=True)

        container.columnconfigure(0, weight=1)
        return container

    def logout(self):
        self.current_user = None
        self.active_page = None
        self.clear_sidebar()
        self.login_page()

    # ---------------------
    # Login page
    # ---------------------
    def login_page(self):
        self.sidebar_frame.pack_forget()
        self.header_frame.pack_forget()
        self.status_bar.pack_forget()
        self.main_frame.pack_forget()
        self.content_frame.pack_forget()
        self.main_frame.pack(fill="both", expand=True)
        self.content_frame.pack(fill="both", expand=True)
        self.clear_content()
        self.set_status("Ready")

        shell = tk.Frame(self.content_frame, bg=COLORS["background"])
        shell.pack(fill="both", expand=True)

        hero = tk.Frame(shell, bg=COLORS["sidebar"])
        hero.pack(side="left", fill="both", expand=True)
        hero_inner = tk.Frame(hero, bg=COLORS["sidebar"])
        hero_inner.place(relx=0.5, rely=0.5, anchor="center")
        tk.Label(
            hero_inner,
            text="EduCore ERP",
            bg=COLORS["sidebar"],
            fg="#ffffff",
            font=(FONT, 34, "bold"),
        ).pack(anchor="w")
        tk.Label(
            hero_inner,
            text="A cleaner school management workspace for students, teachers, fees, and LMS tasks.",
            bg=COLORS["sidebar"],
            fg="#cbd5e1",
            font=(FONT, 12),
            wraplength=440,
            justify="left",
        ).pack(anchor="w", pady=(12, 24))

        hero_stats = tk.Frame(hero_inner, bg=COLORS["sidebar"])
        hero_stats.pack(anchor="w", fill="x")
        avg_attendance = self.scalar("SELECT COALESCE(AVG(attendance), 0) FROM students")
        hero_numbers = (
            (str(self.scalar("SELECT COUNT(*) FROM students")), "Students"),
            (str(self.scalar("SELECT COUNT(*) FROM teachers")), "Teachers"),
            (f"{avg_attendance:.0f}%", "Attendance"),
        )
        for value, label in hero_numbers:
            stat = tk.Frame(hero_stats, bg="#1f2937", padx=18, pady=12)
            stat.pack(side="left", padx=(0, 10))
            tk.Label(
                stat,
                text=value,
                bg="#1f2937",
                fg="#ffffff",
                font=(FONT, 17, "bold"),
            ).pack(anchor="w")
            tk.Label(
                stat,
                text=label,
                bg="#1f2937",
                fg="#cbd5e1",
                font=(FONT, 9),
            ).pack(anchor="w")

        login_panel = tk.Frame(
            shell,
            bg=COLORS["card"],
            padx=34,
            pady=34,
            highlightbackground=COLORS["border"],
            highlightthickness=1,
        )
        login_panel.pack(side="right", fill="y", padx=52, pady=58)

        tk.Label(
            login_panel,
            text="Welcome back",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT, 24, "bold"),
        ).pack(anchor="w")
        tk.Label(
            login_panel,
            text="Sign in to open the admin dashboard.",
            bg=COLORS["card"],
            fg=COLORS["muted"],
            font=(FONT, 10),
        ).pack(anchor="w", pady=(5, 26))

        tk.Label(
            login_panel,
            text="Username",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT, 10, "bold"),
        ).pack(anchor="w")
        self.username_var = StringVar()
        u_entry = ttk.Entry(login_panel, textvariable=self.username_var, width=34)
        u_entry.pack(anchor="w", fill="x", pady=(6, 16))

        tk.Label(
            login_panel,
            text="Password",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT, 10, "bold"),
        ).pack(anchor="w")
        self.password_var = StringVar()
        p_entry = ttk.Entry(login_panel, textvariable=self.password_var, show="*", width=34)
        p_entry.pack(anchor="w", fill="x", pady=(6, 20))

        ttk.Button(
            login_panel,
            text="Login",
            style="Accent.TButton",
            command=self.login,
        ).pack(fill="x")
        tk.Label(
            login_panel,
            text="Default login: admin / admin123",
            bg=COLORS["card"],
            fg=COLORS["muted"],
            font=(FONT, 9),
        ).pack(anchor="w", pady=(18, 0))

        u_entry.focus_set()
        u_entry.bind("<Return>", lambda _event: p_entry.focus_set())
        p_entry.bind("<Return>", lambda _event: self.login())

    def login(self):
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()

        if not username or not password:
            messagebox.showerror("Error", "Provide username and password")
            return

        self.db.cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        user = self.db.cursor.fetchone()
        if not user:
            messagebox.showerror("Error", "User not found")
            return

        if verify_password(password, user[2]):
            self.current_user = user
            self.build_sidebar()
            self.notify("Login successful", f"Welcome {user[4]}")
            self.admin_dashboard()
        else:
            messagebox.showerror("Error", "Invalid password")

    # ---------------------
    # Dashboard
    # ---------------------
    def admin_dashboard(self):
        container = self.start_page(
            "Admin Dashboard",
            "A steady view of daily school operations.",
            "Dashboard",
        )

        students = self.scalar("SELECT COUNT(*) FROM students")
        teachers = self.scalar("SELECT COUNT(*) FROM teachers")
        courses = self.scalar("SELECT COUNT(*) FROM courses")
        assignments = self.scalar("SELECT COUNT(*) FROM assignments")
        avg_attendance = self.scalar("SELECT COALESCE(AVG(attendance), 0) FROM students")
        pending_fees = self.scalar("SELECT COALESCE(SUM(amount), 0) FROM fee_records WHERE status!='Paid'")
        upcoming_events = self.scalar("SELECT COUNT(*) FROM events")
        timetable_slots = self.scalar("SELECT COUNT(*) FROM timetable")
        issued_books = self.scalar("SELECT COUNT(*) FROM library_books WHERE status='Issued'")

        metrics = tk.Frame(container, bg=COLORS["background"])
        metrics.pack(fill="x", pady=(0, 16))
        for index in range(4):
            metrics.columnconfigure(index, weight=1)

        self.metric_card(metrics, "Students", str(students), "Registered learners", 0)
        self.metric_card(metrics, "Teachers", str(teachers), "Faculty profiles", 1)
        self.metric_card(metrics, "Courses", str(courses), "Catalog entries", 2)
        self.metric_card(metrics, "Pending Fees", self.money(pending_fees), "Awaiting payment", 3)

        operations = tk.Frame(container, bg=COLORS["background"])
        operations.pack(fill="x", pady=(0, 16))
        for index in range(3):
            operations.columnconfigure(index, weight=1)
        self.metric_card(operations, "Attendance", f"{avg_attendance:.0f}%", "Average", 0)
        self.metric_card(operations, "Timetable Slots", str(timetable_slots), "Weekly schedule", 1)
        self.metric_card(operations, "Books Issued", str(issued_books), "Library circulation", 2)

        body = tk.Frame(container, bg=COLORS["background"])
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=2)
        body.columnconfigure(1, weight=1)

        activity = self.card(body)
        activity.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        tk.Label(
            activity,
            text="Recent Activity",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT, 14, "bold"),
        ).pack(anchor="w")
        box = self.text_area(activity, height=11, readonly=True)
        box.pack(fill="both", expand=True, pady=(12, 0))
        self.append_text(
            box,
            f"{assignments} assignments are currently in the LMS list.\n\n"
            f"{upcoming_events} events are on the school calendar.\n\n"
            f"{timetable_slots} timetable slots are scheduled for the week.\n\n"
            f"{issued_books} library books are currently issued.\n\n"
            f"{self.money(pending_fees)} is pending in the fee ledger.\n\n",
        )
        self.db.cursor.execute(
            """
            SELECT fullname, attendance
            FROM students
            WHERE attendance < 75
            ORDER BY attendance ASC, fullname
            LIMIT 5
            """
        )
        low_rows = self.db.cursor.fetchall()
        if low_rows:
            self.append_text(box, "Attendance follow-up:\n")
            for name, attendance in low_rows:
                self.append_text(box, f"- {name}: {float(attendance or 0):.0f}%\n")
        else:
            self.append_text(box, "No attendance alerts right now.\n")

        quick = self.card(body)
        quick.grid(row=0, column=1, sticky="nsew", padx=(12, 0))
        tk.Label(
            quick,
            text="Quick Actions",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT, 14, "bold"),
        ).pack(anchor="w")
        actions = [
            ("Add student", self.students_page),
            ("Manage courses", self.courses_page),
            ("Build timetable", self.timetable_page),
            ("Create assignment", self.assignments_page),
            ("Open library", self.library_page),
            ("Record fee", self.fees_page),
            ("Plan event", self.events_page),
            ("Open analytics", self.analytics_page),
            ("Export report", self.export_pdf),
        ]
        for label, command in actions:
            ttk.Button(quick, text=label, command=command).pack(fill="x", pady=(12, 0))

    def metric_card(self, parent, title, value, hint, column):
        card = self.card(parent, padding=18)
        card.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 8, 0))
        tk.Label(
            card,
            text=title,
            bg=COLORS["card"],
            fg=COLORS["muted"],
            font=(FONT, 10, "bold"),
        ).pack(anchor="w")
        tk.Label(
            card,
            text=value,
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT, 24, "bold"),
        ).pack(anchor="w", pady=(6, 2))
        tk.Label(
            card,
            text=hint,
            bg=COLORS["card"],
            fg=COLORS["muted"],
            font=(FONT, 9),
        ).pack(anchor="w")

    # ---------------------
    # Students
    # ---------------------
    def students_page(self):
        container = self.start_page(
            "Student Management",
            "Register, edit, and monitor student records.",
            "Students",
            scroll=False,
        )

        self.selected_student_db_id = None
        form = self.card(container)
        form.pack(fill="x", pady=(0, 16))
        for index in range(5):
            form.columnconfigure(index, weight=1)

        tk.Label(form, text="Name", bg=COLORS["card"], fg=COLORS["text"], font=(FONT, 10, "bold")).grid(
            row=0,
            column=0,
            sticky="w",
        )
        tk.Label(form, text="Course", bg=COLORS["card"], fg=COLORS["text"], font=(FONT, 10, "bold")).grid(
            row=0,
            column=1,
            sticky="w",
            padx=(12, 0),
        )
        tk.Label(form, text="GPA", bg=COLORS["card"], fg=COLORS["text"], font=(FONT, 10, "bold")).grid(
            row=0,
            column=2,
            sticky="w",
            padx=(12, 0),
        )
        tk.Label(
            form,
            text="Attendance %",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT, 10, "bold"),
        ).grid(row=0, column=3, sticky="w", padx=(12, 0))
        tk.Label(form, text="Search", bg=COLORS["card"], fg=COLORS["text"], font=(FONT, 10, "bold")).grid(
            row=0,
            column=4,
            sticky="w",
            padx=(12, 0),
        )

        self.s_name = StringVar()
        self.s_course = StringVar()
        self.s_gpa = StringVar(value="0.00")
        self.s_attendance = StringVar(value="0")
        self.student_search = StringVar()
        ttk.Entry(form, textvariable=self.s_name).grid(row=1, column=0, sticky="ew", pady=(6, 0))
        ttk.Combobox(form, textvariable=self.s_course, values=self.course_choices()).grid(
            row=1,
            column=1,
            sticky="ew",
            padx=(12, 0),
            pady=(6, 0),
        )
        ttk.Entry(form, textvariable=self.s_gpa).grid(
            row=1,
            column=2,
            sticky="ew",
            padx=(12, 0),
            pady=(6, 0),
        )
        ttk.Entry(form, textvariable=self.s_attendance).grid(
            row=1,
            column=3,
            sticky="ew",
            padx=(12, 0),
            pady=(6, 0),
        )
        ttk.Entry(form, textvariable=self.student_search).grid(
            row=1,
            column=4,
            sticky="ew",
            padx=(12, 0),
            pady=(6, 0),
        )

        buttons = tk.Frame(form, bg=COLORS["card"])
        buttons.grid(row=2, column=0, columnspan=5, sticky="ew", pady=(14, 0))
        ttk.Button(
            buttons,
            text="Add Student",
            style="Accent.TButton",
            command=self.add_student,
        ).pack(side="left")
        ttk.Button(
            buttons,
            text="Update Selected",
            style="Secondary.TButton",
            command=self.update_student,
        ).pack(side="left", padx=(10, 0))
        ttk.Button(
            buttons,
            text="Delete Selected",
            style="Danger.TButton",
            command=self.delete_student,
        ).pack(side="left", padx=(10, 0))
        ttk.Button(
            buttons,
            text="Clear Form",
            command=self.clear_student_form,
        ).pack(side="left", padx=(10, 0))
        self.student_search.trace_add("write", lambda *_args: self.load_students())

        table = self.card(container)
        table.pack(fill="both", expand=True)
        tk.Label(
            table,
            text="Student Directory",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT, 14, "bold"),
        ).pack(anchor="w")
        cols = ("ID", "Name", "Course", "GPA", "Attendance")
        self.student_tree = self.create_tree(table, cols, height=14)
        self.student_tree.column("Name", width=220)
        self.student_tree.column("Course", width=180)
        self.student_tree.bind("<<TreeviewSelect>>", self.select_student)
        self.load_students()

    def add_student(self):
        name = self.s_name.get().strip()
        course = self.s_course.get().strip()
        if not name or not course:
            messagebox.showerror("Error", "Fill all fields")
            return
        try:
            gpa = self.get_float(self.s_gpa.get().strip() or "0", "GPA", 0, 4)
            attendance = self.get_float(self.s_attendance.get().strip() or "0", "Attendance", 0, 100)
        except ValueError as exc:
            messagebox.showerror("Error", str(exc))
            return

        student_id = f"STD{datetime.now().strftime('%y%m%d%H%M%S')}"
        self.db.cursor.execute(
            "INSERT INTO students(student_id,fullname,course,gpa,attendance) VALUES(?,?,?,?,?)",
            (student_id, name, course, gpa, attendance),
        )
        self.db.conn.commit()
        self.notify("Student added", f"{name} added")
        self.clear_student_form()
        self.load_students()

    def select_student(self, _event=None):
        selected = self.student_tree.selection()
        if not selected:
            return
        self.selected_student_db_id = selected[0]
        values = self.student_tree.item(selected[0], "values")
        if not values:
            return
        self.s_name.set(values[1])
        self.s_course.set(values[2])
        self.s_gpa.set(values[3])
        self.s_attendance.set(values[4].replace("%", ""))

    def update_student(self):
        if not self.selected_student_db_id:
            self.selected_student_db_id = self.selected_iid(self.student_tree, "Select a student to update")
            if not self.selected_student_db_id:
                return
        name = self.s_name.get().strip()
        course = self.s_course.get().strip()
        if not name or not course:
            messagebox.showerror("Error", "Name and course are required")
            return
        try:
            gpa = self.get_float(self.s_gpa.get().strip() or "0", "GPA", 0, 4)
            attendance = self.get_float(self.s_attendance.get().strip() or "0", "Attendance", 0, 100)
        except ValueError as exc:
            messagebox.showerror("Error", str(exc))
            return

        self.db.cursor.execute(
            """
            UPDATE students
            SET fullname=?, course=?, gpa=?, attendance=?
            WHERE id=?
            """,
            (name, course, gpa, attendance, self.selected_student_db_id),
        )
        self.db.conn.commit()
        self.notify("Student updated", name)
        self.load_students()

    def delete_student(self):
        iid = self.selected_iid(self.student_tree, "Select a student to delete")
        if not iid:
            return
        values = self.student_tree.item(iid, "values")
        name = values[1] if values else "selected student"
        if not messagebox.askyesno("Delete student", f"Delete {name}?"):
            return
        self.db.cursor.execute("DELETE FROM students WHERE id=?", (iid,))
        self.db.conn.commit()
        self.notify("Student deleted", name)
        self.clear_student_form()
        self.load_students()

    def clear_student_form(self):
        self.selected_student_db_id = None
        self.s_name.set("")
        self.s_course.set("")
        self.s_gpa.set("0.00")
        self.s_attendance.set("0")
        if hasattr(self, "student_tree"):
            self.student_tree.selection_remove(self.student_tree.selection())

    def load_students(self):
        if not hasattr(self, "student_tree"):
            return
        for row in self.student_tree.get_children():
            self.student_tree.delete(row)

        search = self.student_search.get().strip() if hasattr(self, "student_search") else ""
        if search:
            like = f"%{search}%"
            self.db.cursor.execute(
                """
                SELECT * FROM students
                WHERE student_id LIKE ? OR fullname LIKE ? OR course LIKE ?
                ORDER BY id DESC
                """,
                (like, like, like),
            )
        else:
            self.db.cursor.execute("SELECT * FROM students ORDER BY id DESC")

        for index, student in enumerate(self.db.cursor.fetchall()):
            tag = "even" if index % 2 == 0 else "odd"
            attendance = f"{float(student[5] or 0):.0f}%"
            gpa = f"{float(student[4] or 0):.2f}"
            self.student_tree.insert(
                "",
                "end",
                iid=str(student[0]),
                values=(student[1], student[2], student[3], gpa, attendance),
                tags=(tag,),
            )

    # ---------------------
    # Teachers
    # ---------------------
    def teachers_page(self):
        container = self.start_page(
            "Teacher Management",
            "Manage faculty profiles and subject assignments.",
            "Teachers",
            scroll=False,
        )

        self.selected_teacher_db_id = None
        form = self.card(container)
        form.pack(fill="x", pady=(0, 16))
        for index in range(4):
            form.columnconfigure(index, weight=1)

        tk.Label(form, text="Name", bg=COLORS["card"], fg=COLORS["text"], font=(FONT, 10, "bold")).grid(
            row=0,
            column=0,
            sticky="w",
        )
        tk.Label(form, text="Subject", bg=COLORS["card"], fg=COLORS["text"], font=(FONT, 10, "bold")).grid(
            row=0,
            column=1,
            sticky="w",
            padx=(12, 0),
        )
        tk.Label(form, text="Search", bg=COLORS["card"], fg=COLORS["text"], font=(FONT, 10, "bold")).grid(
            row=0,
            column=2,
            sticky="w",
            padx=(12, 0),
        )

        self.t_name = StringVar()
        self.t_subject = StringVar()
        self.teacher_search = StringVar()
        ttk.Entry(form, textvariable=self.t_name).grid(row=1, column=0, sticky="ew", pady=(6, 0))
        ttk.Entry(form, textvariable=self.t_subject).grid(
            row=1,
            column=1,
            sticky="ew",
            padx=(12, 0),
            pady=(6, 0),
        )
        ttk.Entry(form, textvariable=self.teacher_search).grid(
            row=1,
            column=2,
            sticky="ew",
            padx=(12, 0),
            pady=(6, 0),
        )
        buttons = tk.Frame(form, bg=COLORS["card"])
        buttons.grid(row=2, column=0, columnspan=4, sticky="ew", pady=(14, 0))
        ttk.Button(
            buttons,
            text="Add Teacher",
            style="Accent.TButton",
            command=self.add_teacher,
        ).pack(side="left")
        ttk.Button(
            buttons,
            text="Update Selected",
            style="Secondary.TButton",
            command=self.update_teacher,
        ).pack(side="left", padx=(10, 0))
        ttk.Button(
            buttons,
            text="Delete Selected",
            style="Danger.TButton",
            command=self.delete_teacher,
        ).pack(side="left", padx=(10, 0))
        ttk.Button(
            buttons,
            text="Clear Form",
            command=self.clear_teacher_form,
        ).pack(side="left", padx=(10, 0))
        self.teacher_search.trace_add("write", lambda *_args: self.load_teachers())

        table = self.card(container)
        table.pack(fill="both", expand=True)
        tk.Label(
            table,
            text="Teacher Directory",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT, 14, "bold"),
        ).pack(anchor="w")
        self.teacher_tree = self.create_tree(table, ("ID", "Name", "Subject"), height=14)
        self.teacher_tree.column("Name", width=240)
        self.teacher_tree.bind("<<TreeviewSelect>>", self.select_teacher)
        self.load_teachers()

    def add_teacher(self):
        name = self.t_name.get().strip()
        subject = self.t_subject.get().strip()
        if not name or not subject:
            messagebox.showerror("Error", "Fill all fields")
            return

        teacher_id = f"TCH{datetime.now().strftime('%y%m%d%H%M%S')}"
        self.db.cursor.execute(
            "INSERT INTO teachers(teacher_id,fullname,subject) VALUES(?,?,?)",
            (teacher_id, name, subject),
        )
        self.db.conn.commit()
        self.clear_teacher_form()
        self.notify("Teacher added", f"{name} added")
        self.load_teachers()

    def select_teacher(self, _event=None):
        selected = self.teacher_tree.selection()
        if not selected:
            return
        self.selected_teacher_db_id = selected[0]
        values = self.teacher_tree.item(selected[0], "values")
        if not values:
            return
        self.t_name.set(values[1])
        self.t_subject.set(values[2])

    def update_teacher(self):
        if not self.selected_teacher_db_id:
            self.selected_teacher_db_id = self.selected_iid(self.teacher_tree, "Select a teacher to update")
            if not self.selected_teacher_db_id:
                return
        name = self.t_name.get().strip()
        subject = self.t_subject.get().strip()
        if not name or not subject:
            messagebox.showerror("Error", "Name and subject are required")
            return
        self.db.cursor.execute(
            "UPDATE teachers SET fullname=?, subject=? WHERE id=?",
            (name, subject, self.selected_teacher_db_id),
        )
        self.db.conn.commit()
        self.notify("Teacher updated", name)
        self.load_teachers()

    def delete_teacher(self):
        iid = self.selected_iid(self.teacher_tree, "Select a teacher to delete")
        if not iid:
            return
        values = self.teacher_tree.item(iid, "values")
        name = values[1] if values else "selected teacher"
        if not messagebox.askyesno("Delete teacher", f"Delete {name}?"):
            return
        self.db.cursor.execute("DELETE FROM teachers WHERE id=?", (iid,))
        self.db.conn.commit()
        self.notify("Teacher deleted", name)
        self.clear_teacher_form()
        self.load_teachers()

    def clear_teacher_form(self):
        self.selected_teacher_db_id = None
        self.t_name.set("")
        self.t_subject.set("")
        if hasattr(self, "teacher_tree"):
            self.teacher_tree.selection_remove(self.teacher_tree.selection())

    def load_teachers(self):
        if not hasattr(self, "teacher_tree"):
            return
        for row in self.teacher_tree.get_children():
            self.teacher_tree.delete(row)

        search = self.teacher_search.get().strip() if hasattr(self, "teacher_search") else ""
        if search:
            like = f"%{search}%"
            self.db.cursor.execute(
                """
                SELECT * FROM teachers
                WHERE teacher_id LIKE ? OR fullname LIKE ? OR subject LIKE ?
                ORDER BY id DESC
                """,
                (like, like, like),
            )
        else:
            self.db.cursor.execute("SELECT * FROM teachers ORDER BY id DESC")

        for index, teacher in enumerate(self.db.cursor.fetchall()):
            tag = "even" if index % 2 == 0 else "odd"
            self.teacher_tree.insert(
                "",
                "end",
                iid=str(teacher[0]),
                values=(teacher[1], teacher[2], teacher[3]),
                tags=(tag,),
            )

    # ---------------------
    # Courses
    # ---------------------
    def courses_page(self):
        container = self.start_page(
            "Course Catalog",
            "Manage courses, rooms, credits, and teacher ownership.",
            "Courses",
            scroll=False,
        )

        self.selected_course_db_id = None
        form = self.card(container)
        form.pack(fill="x", pady=(0, 16))
        for index in range(6):
            form.columnconfigure(index, weight=1)

        self.course_code_var = StringVar()
        self.course_title_var = StringVar()
        self.course_teacher_var = StringVar(value="Unassigned")
        self.course_room_var = StringVar()
        self.course_credits_var = StringVar(value="3")
        self.course_search_var = StringVar()

        fields = (
            ("Code", self.course_code_var, "entry"),
            ("Course Name", self.course_title_var, "entry"),
            ("Teacher", self.course_teacher_var, "teacher"),
            ("Room", self.course_room_var, "entry"),
            ("Credits", self.course_credits_var, "entry"),
            ("Search", self.course_search_var, "entry"),
        )
        for index, (label, variable, kind) in enumerate(fields):
            tk.Label(
                form,
                text=label,
                bg=COLORS["card"],
                fg=COLORS["text"],
                font=(FONT, 10, "bold"),
            ).grid(row=0, column=index, sticky="w", padx=(0 if index == 0 else 12, 0))
            if kind == "teacher":
                widget = ttk.Combobox(form, textvariable=variable, values=self.teacher_choices())
            else:
                widget = ttk.Entry(form, textvariable=variable)
            widget.grid(
                row=1,
                column=index,
                sticky="ew",
                padx=(0 if index == 0 else 12, 0),
                pady=(6, 0),
            )

        actions = tk.Frame(form, bg=COLORS["card"])
        actions.grid(row=2, column=0, columnspan=6, sticky="ew", pady=(14, 0))
        ttk.Button(actions, text="Add Course", style="Accent.TButton", command=self.add_course).pack(side="left")
        ttk.Button(
            actions,
            text="Update Selected",
            style="Secondary.TButton",
            command=self.update_course,
        ).pack(side="left", padx=(10, 0))
        ttk.Button(
            actions,
            text="Delete Selected",
            style="Danger.TButton",
            command=self.delete_course,
        ).pack(side="left", padx=(10, 0))
        ttk.Button(actions, text="Clear Form", command=self.clear_course_form).pack(side="left", padx=(10, 0))
        self.course_search_var.trace_add("write", lambda *_args: self.load_courses())

        table = self.card(container)
        table.pack(fill="both", expand=True)
        tk.Label(
            table,
            text="Course Directory",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT, 14, "bold"),
        ).pack(anchor="w")
        self.course_tree = self.create_tree(table, ("Code", "Course", "Teacher", "Room", "Credits"), height=13)
        self.course_tree.column("Course", width=250)
        self.course_tree.column("Teacher", width=220)
        self.course_tree.bind("<<TreeviewSelect>>", self.select_course)
        self.load_courses()

    def add_course(self):
        code = self.course_code_var.get().strip().upper()
        title = self.course_title_var.get().strip()
        if not code or not title:
            messagebox.showerror("Error", "Course code and name are required")
            return
        try:
            credits = self.get_float(self.course_credits_var.get().strip() or "0", "Credits", 0, 10)
        except ValueError as exc:
            messagebox.showerror("Error", str(exc))
            return
        self.db.cursor.execute(
            "INSERT INTO courses(code,title,teacher,room,credits) VALUES(?,?,?,?,?)",
            (
                code,
                title,
                self.course_teacher_var.get().strip() or "Unassigned",
                self.course_room_var.get().strip(),
                credits,
            ),
        )
        self.db.conn.commit()
        self.notify("Course added", f"{code} - {title}")
        self.clear_course_form()
        self.load_courses()

    def select_course(self, _event=None):
        selected = self.course_tree.selection()
        if not selected:
            return
        self.selected_course_db_id = selected[0]
        values = self.course_tree.item(selected[0], "values")
        if not values:
            return
        self.course_code_var.set(values[0])
        self.course_title_var.set(values[1])
        self.course_teacher_var.set(values[2])
        self.course_room_var.set(values[3])
        self.course_credits_var.set(values[4])

    def update_course(self):
        if not self.selected_course_db_id:
            self.selected_course_db_id = self.selected_iid(self.course_tree, "Select a course to update")
            if not self.selected_course_db_id:
                return
        code = self.course_code_var.get().strip().upper()
        title = self.course_title_var.get().strip()
        if not code or not title:
            messagebox.showerror("Error", "Course code and name are required")
            return
        try:
            credits = self.get_float(self.course_credits_var.get().strip() or "0", "Credits", 0, 10)
        except ValueError as exc:
            messagebox.showerror("Error", str(exc))
            return
        self.db.cursor.execute(
            """
            UPDATE courses
            SET code=?, title=?, teacher=?, room=?, credits=?
            WHERE id=?
            """,
            (
                code,
                title,
                self.course_teacher_var.get().strip() or "Unassigned",
                self.course_room_var.get().strip(),
                credits,
                self.selected_course_db_id,
            ),
        )
        self.db.conn.commit()
        self.notify("Course updated", f"{code} - {title}")
        self.load_courses()

    def delete_course(self):
        iid = self.selected_iid(self.course_tree, "Select a course to delete")
        if not iid:
            return
        values = self.course_tree.item(iid, "values")
        label = f"{values[0]} - {values[1]}" if values else "selected course"
        if not messagebox.askyesno("Delete course", f"Delete {label}?"):
            return
        self.db.cursor.execute("DELETE FROM courses WHERE id=?", (iid,))
        self.db.conn.commit()
        self.notify("Course deleted", label)
        self.clear_course_form()
        self.load_courses()

    def clear_course_form(self):
        self.selected_course_db_id = None
        self.course_code_var.set("")
        self.course_title_var.set("")
        self.course_teacher_var.set("Unassigned")
        self.course_room_var.set("")
        self.course_credits_var.set("3")
        if hasattr(self, "course_tree"):
            self.course_tree.selection_remove(self.course_tree.selection())

    def load_courses(self):
        if not hasattr(self, "course_tree"):
            return
        for row_id in self.course_tree.get_children():
            self.course_tree.delete(row_id)
        search = self.course_search_var.get().strip() if hasattr(self, "course_search_var") else ""
        if search:
            like = f"%{search}%"
            self.db.cursor.execute(
                """
                SELECT id, code, title, teacher, room, credits
                FROM courses
                WHERE code LIKE ? OR title LIKE ? OR teacher LIKE ? OR room LIKE ?
                ORDER BY code, title
                """,
                (like, like, like, like),
            )
        else:
            self.db.cursor.execute(
                "SELECT id, code, title, teacher, room, credits FROM courses ORDER BY code, title"
            )
        for index, row in enumerate(self.db.cursor.fetchall()):
            tag = "even" if index % 2 == 0 else "odd"
            self.course_tree.insert(
                "",
                "end",
                iid=str(row[0]),
                values=(row[1], row[2], row[3] or "Unassigned", row[4] or "", f"{float(row[5] or 0):.1f}"),
                tags=(tag,),
            )

    # ---------------------
    # Timetable
    # ---------------------
    def timetable_page(self):
        container = self.start_page(
            "Timetable",
            "Build the weekly schedule for courses, teachers, and rooms.",
            "Timetable",
            scroll=False,
        )

        self.selected_timetable_db_id = None
        form = self.card(container)
        form.pack(fill="x", pady=(0, 16))
        for index in range(5):
            form.columnconfigure(index, weight=1)

        self.tt_day_var = StringVar(value="Monday")
        self.tt_time_var = StringVar(value="09:00")
        self.tt_course_var = StringVar()
        self.tt_teacher_var = StringVar(value="Unassigned")
        self.tt_room_var = StringVar()
        fields = (
            ("Day", self.tt_day_var, "day"),
            ("Start Time", self.tt_time_var, "entry"),
            ("Course", self.tt_course_var, "course"),
            ("Teacher", self.tt_teacher_var, "teacher"),
            ("Room", self.tt_room_var, "entry"),
        )
        for index, (label, variable, kind) in enumerate(fields):
            tk.Label(
                form,
                text=label,
                bg=COLORS["card"],
                fg=COLORS["text"],
                font=(FONT, 10, "bold"),
            ).grid(row=0, column=index, sticky="w", padx=(0 if index == 0 else 12, 0))
            if kind == "day":
                widget = ttk.Combobox(
                    form,
                    textvariable=variable,
                    values=("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"),
                    state="readonly",
                )
            elif kind == "course":
                widget = ttk.Combobox(form, textvariable=variable, values=self.course_choices())
                widget.bind("<<ComboboxSelected>>", self.populate_timetable_course_defaults)
            elif kind == "teacher":
                widget = ttk.Combobox(form, textvariable=variable, values=self.teacher_choices())
            else:
                widget = ttk.Entry(form, textvariable=variable)
            widget.grid(
                row=1,
                column=index,
                sticky="ew",
                padx=(0 if index == 0 else 12, 0),
                pady=(6, 0),
            )

        actions = tk.Frame(form, bg=COLORS["card"])
        actions.grid(row=2, column=0, columnspan=5, sticky="ew", pady=(14, 0))
        ttk.Button(actions, text="Add Slot", style="Accent.TButton", command=self.add_timetable_slot).pack(side="left")
        ttk.Button(
            actions,
            text="Update Selected",
            style="Secondary.TButton",
            command=self.update_timetable_slot,
        ).pack(side="left", padx=(10, 0))
        ttk.Button(
            actions,
            text="Delete Selected",
            style="Danger.TButton",
            command=self.delete_timetable_slot,
        ).pack(side="left", padx=(10, 0))
        ttk.Button(actions, text="Clear Form", command=self.clear_timetable_form).pack(side="left", padx=(10, 0))

        table = self.card(container)
        table.pack(fill="both", expand=True)
        tk.Label(
            table,
            text="Weekly Schedule",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT, 14, "bold"),
        ).pack(anchor="w")
        self.timetable_tree = self.create_tree(table, ("Day", "Time", "Course", "Teacher", "Room"), height=13)
        self.timetable_tree.column("Course", width=260)
        self.timetable_tree.column("Teacher", width=200)
        self.timetable_tree.bind("<<TreeviewSelect>>", self.select_timetable_slot)
        self.load_timetable()

    def populate_timetable_course_defaults(self, _event=None):
        course_code = self.tt_course_var.get().split(" - ", 1)[0].strip()
        if not course_code:
            return
        self.db.cursor.execute("SELECT teacher, room FROM courses WHERE code=?", (course_code,))
        row = self.db.cursor.fetchone()
        if row:
            self.tt_teacher_var.set(row[0] or "Unassigned")
            self.tt_room_var.set(row[1] or "")

    def add_timetable_slot(self):
        if not self.tt_course_var.get().strip():
            messagebox.showerror("Error", "Select or enter a course")
            return
        self.db.cursor.execute(
            "INSERT INTO timetable(day_name,start_time,course,teacher,room) VALUES(?,?,?,?,?)",
            (
                self.tt_day_var.get().strip(),
                self.tt_time_var.get().strip(),
                self.tt_course_var.get().strip(),
                self.tt_teacher_var.get().strip() or "Unassigned",
                self.tt_room_var.get().strip(),
            ),
        )
        self.db.conn.commit()
        self.notify("Timetable slot added", f"{self.tt_day_var.get()} {self.tt_time_var.get()}")
        self.clear_timetable_form()
        self.load_timetable()

    def select_timetable_slot(self, _event=None):
        selected = self.timetable_tree.selection()
        if not selected:
            return
        self.selected_timetable_db_id = selected[0]
        values = self.timetable_tree.item(selected[0], "values")
        if not values:
            return
        self.tt_day_var.set(values[0])
        self.tt_time_var.set(values[1])
        self.tt_course_var.set(values[2])
        self.tt_teacher_var.set(values[3])
        self.tt_room_var.set(values[4])

    def update_timetable_slot(self):
        if not self.selected_timetable_db_id:
            self.selected_timetable_db_id = self.selected_iid(self.timetable_tree, "Select a slot to update")
            if not self.selected_timetable_db_id:
                return
        self.db.cursor.execute(
            """
            UPDATE timetable
            SET day_name=?, start_time=?, course=?, teacher=?, room=?
            WHERE id=?
            """,
            (
                self.tt_day_var.get().strip(),
                self.tt_time_var.get().strip(),
                self.tt_course_var.get().strip(),
                self.tt_teacher_var.get().strip() or "Unassigned",
                self.tt_room_var.get().strip(),
                self.selected_timetable_db_id,
            ),
        )
        self.db.conn.commit()
        self.notify("Timetable slot updated", f"{self.tt_day_var.get()} {self.tt_time_var.get()}")
        self.load_timetable()

    def delete_timetable_slot(self):
        iid = self.selected_iid(self.timetable_tree, "Select a timetable slot to delete")
        if not iid:
            return
        values = self.timetable_tree.item(iid, "values")
        label = f"{values[0]} {values[1]}" if values else "selected timetable slot"
        if not messagebox.askyesno("Delete slot", f"Delete {label}?"):
            return
        self.db.cursor.execute("DELETE FROM timetable WHERE id=?", (iid,))
        self.db.conn.commit()
        self.notify("Timetable slot deleted", label)
        self.clear_timetable_form()
        self.load_timetable()

    def clear_timetable_form(self):
        self.selected_timetable_db_id = None
        self.tt_day_var.set("Monday")
        self.tt_time_var.set("09:00")
        self.tt_course_var.set("")
        self.tt_teacher_var.set("Unassigned")
        self.tt_room_var.set("")
        if hasattr(self, "timetable_tree"):
            self.timetable_tree.selection_remove(self.timetable_tree.selection())

    def load_timetable(self):
        if not hasattr(self, "timetable_tree"):
            return
        for row_id in self.timetable_tree.get_children():
            self.timetable_tree.delete(row_id)
        self.db.cursor.execute(
            """
            SELECT id, day_name, start_time, course, teacher, room
            FROM timetable
            ORDER BY
                CASE day_name
                    WHEN 'Monday' THEN 1
                    WHEN 'Tuesday' THEN 2
                    WHEN 'Wednesday' THEN 3
                    WHEN 'Thursday' THEN 4
                    WHEN 'Friday' THEN 5
                    WHEN 'Saturday' THEN 6
                    ELSE 7
                END,
                start_time,
                id
            """
        )
        for index, row in enumerate(self.db.cursor.fetchall()):
            tag = "even" if index % 2 == 0 else "odd"
            self.timetable_tree.insert(
                "",
                "end",
                iid=str(row[0]),
                values=(row[1], row[2], row[3], row[4] or "Unassigned", row[5] or ""),
                tags=(tag,),
            )

    # ---------------------
    # Attendance
    # ---------------------
    def attendance_page(self):
        container = self.start_page(
            "Attendance System",
            "Update attendance and review students needing attention.",
            "Attendance",
            scroll=False,
        )

        avg_attendance = self.scalar("SELECT COALESCE(AVG(attendance), 0) FROM students")
        total_students = self.scalar("SELECT COUNT(*) FROM students")
        low_count = self.scalar("SELECT COUNT(*) FROM students WHERE attendance < 75")

        summary = tk.Frame(container, bg=COLORS["background"])
        summary.pack(fill="x", pady=(0, 16))
        summary.columnconfigure(0, weight=1)
        summary.columnconfigure(1, weight=1)
        summary.columnconfigure(2, weight=1)
        self.metric_card(summary, "Average Attendance", f"{avg_attendance:.0f}%", "Across all students", 0)
        self.metric_card(summary, "Student Records", str(total_students), "Available for review", 1)
        self.metric_card(summary, "Below 75%", str(low_count), "Need follow-up", 2)

        form = self.card(container)
        form.pack(fill="x", pady=(0, 16))
        form.columnconfigure(0, weight=2)
        form.columnconfigure(1, weight=1)
        form.columnconfigure(2, weight=1)
        tk.Label(
            form,
            text="Student",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT, 10, "bold"),
        ).grid(row=0, column=0, sticky="w")
        tk.Label(
            form,
            text="Attendance %",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT, 10, "bold"),
        ).grid(row=0, column=1, sticky="w", padx=(12, 0))
        self.att_student_var = StringVar()
        self.att_value_var = StringVar(value="75")
        self.att_student_combo = ttk.Combobox(
            form,
            textvariable=self.att_student_var,
            values=self.student_choices(),
            state="readonly",
        )
        self.att_student_combo.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        ttk.Entry(form, textvariable=self.att_value_var).grid(
            row=1,
            column=1,
            sticky="ew",
            padx=(12, 0),
            pady=(6, 0),
        )
        ttk.Button(
            form,
            text="Update Attendance",
            style="Accent.TButton",
            command=self.update_attendance,
        ).grid(row=1, column=2, sticky="ew", padx=(12, 0), pady=(6, 0))

        table = self.card(container)
        table.pack(fill="both", expand=True)
        tk.Label(
            table,
            text="Attendance Overview",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT, 14, "bold"),
        ).pack(anchor="w")
        self.attendance_tree = self.create_tree(
            table,
            ("ID", "Student", "Course", "Attendance", "Status"),
            height=15,
        )
        self.attendance_tree.bind("<<TreeviewSelect>>", self.select_attendance_row)
        self.load_attendance_table()

    def select_attendance_row(self, _event=None):
        selected = self.attendance_tree.selection()
        if not selected:
            return
        values = self.attendance_tree.item(selected[0], "values")
        if not values:
            return
        self.att_student_var.set(f"{values[0]} - {values[1]}")
        self.att_value_var.set(values[3].replace("%", ""))

    def update_attendance(self):
        student_id, student_name = self.parse_student_choice(self.att_student_var.get())
        if not student_id:
            messagebox.showerror("Error", "Select a student")
            return
        try:
            attendance = self.get_float(self.att_value_var.get().strip(), "Attendance", 0, 100)
        except ValueError as exc:
            messagebox.showerror("Error", str(exc))
            return
        self.db.cursor.execute(
            "UPDATE students SET attendance=? WHERE student_id=?",
            (attendance, student_id),
        )
        self.db.conn.commit()
        self.notify("Attendance updated", f"{student_name}: {attendance:.0f}%")
        self.attendance_page()

    def load_attendance_table(self):
        if not hasattr(self, "attendance_tree"):
            return
        for row_id in self.attendance_tree.get_children():
            self.attendance_tree.delete(row_id)
        self.db.cursor.execute(
            "SELECT id, student_id, fullname, course, attendance FROM students ORDER BY fullname"
        )
        for index, row in enumerate(self.db.cursor.fetchall()):
            attendance = float(row[4] or 0)
            status = "Good" if attendance >= 75 else "Needs attention"
            row_tag = "even" if index % 2 == 0 else "odd"
            status_tag = "success" if attendance >= 75 else "danger"
            self.attendance_tree.insert(
                "",
                "end",
                iid=str(row[0]),
                values=(row[1], row[2], row[3], f"{attendance:.0f}%", status),
                tags=(row_tag, status_tag),
            )

    # ---------------------
    # Assignments
    # ---------------------
    def assignments_page(self):
        container = self.start_page(
            "Assignments",
            "Create, edit, and review LMS assignments.",
            "Assignments",
            scroll=False,
        )

        self.selected_assignment_db_id = None
        form = self.card(container)
        form.pack(fill="x", pady=(0, 16))
        form.columnconfigure(0, weight=1)
        form.columnconfigure(1, weight=1)

        tk.Label(form, text="Title", bg=COLORS["card"], fg=COLORS["text"], font=(FONT, 10, "bold")).grid(
            row=0,
            column=0,
            sticky="w",
        )
        tk.Label(form, text="Due Date", bg=COLORS["card"], fg=COLORS["text"], font=(FONT, 10, "bold")).grid(
            row=0,
            column=1,
            sticky="w",
            padx=(12, 0),
        )
        self.a_title = StringVar()
        self.a_due = StringVar()
        ttk.Entry(form, textvariable=self.a_title).grid(row=1, column=0, sticky="ew", pady=(6, 0))
        ttk.Entry(form, textvariable=self.a_due).grid(
            row=1,
            column=1,
            sticky="ew",
            padx=(12, 0),
            pady=(6, 0),
        )

        tk.Label(
            form,
            text="Description",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT, 10, "bold"),
        ).grid(row=2, column=0, sticky="w", pady=(14, 0), columnspan=2)
        self.a_desc = self.text_area(form, height=4)
        self.a_desc.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(6, 12))
        action_row = tk.Frame(form, bg=COLORS["card"])
        action_row.grid(row=4, column=0, columnspan=2, sticky="ew")
        ttk.Button(
            action_row,
            text="Create Assignment",
            style="Accent.TButton",
            command=self.save_assignment,
        ).pack(side="left")
        ttk.Button(
            action_row,
            text="Update Selected",
            style="Secondary.TButton",
            command=self.update_assignment,
        ).pack(side="left", padx=(10, 0))
        ttk.Button(
            action_row,
            text="Delete Selected",
            style="Danger.TButton",
            command=self.delete_assignment,
        ).pack(side="left", padx=(10, 0))
        ttk.Button(
            action_row,
            text="Clear Form",
            command=self.clear_assignment_form,
        ).pack(side="left", padx=(10, 0))

        table = self.card(container)
        table.pack(fill="both", expand=True)
        tk.Label(
            table,
            text="Assignment List",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT, 14, "bold"),
        ).pack(anchor="w")
        self.assignment_tree = self.create_tree(table, ("Title", "Due Date", "Description"), height=9)
        self.assignment_tree.column("Description", width=460)
        self.assignment_tree.bind("<<TreeviewSelect>>", self.select_assignment)
        self.load_assignments()

    def save_assignment(self):
        title = self.a_title.get().strip()
        desc = self.a_desc.get("1.0", "end").strip()
        due = self.a_due.get().strip()
        if not title:
            messagebox.showerror("Error", "Title required")
            return

        self.db.cursor.execute(
            "INSERT INTO assignments(title,description,due_date) VALUES(?,?,?)",
            (title, desc, due),
        )
        self.db.conn.commit()
        self.a_title.set("")
        self.a_desc.delete("1.0", "end")
        self.a_due.set("")
        self.notify("Assignment created", title)
        self.clear_assignment_form()
        self.load_assignments()

    def select_assignment(self, _event=None):
        selected = self.assignment_tree.selection()
        if not selected:
            return
        self.selected_assignment_db_id = selected[0]
        self.db.cursor.execute(
            "SELECT title, due_date, description FROM assignments WHERE id=?",
            (self.selected_assignment_db_id,),
        )
        row = self.db.cursor.fetchone()
        if not row:
            return
        self.a_title.set(row[0] or "")
        self.a_due.set(row[1] or "")
        self.clear_text(self.a_desc)
        self.a_desc.insert("1.0", row[2] or "")

    def update_assignment(self):
        if not self.selected_assignment_db_id:
            self.selected_assignment_db_id = self.selected_iid(
                self.assignment_tree,
                "Select an assignment to update",
            )
            if not self.selected_assignment_db_id:
                return
        title = self.a_title.get().strip()
        desc = self.a_desc.get("1.0", "end").strip()
        due = self.a_due.get().strip()
        if not title:
            messagebox.showerror("Error", "Title required")
            return
        self.db.cursor.execute(
            """
            UPDATE assignments
            SET title=?, description=?, due_date=?
            WHERE id=?
            """,
            (title, desc, due, self.selected_assignment_db_id),
        )
        self.db.conn.commit()
        self.notify("Assignment updated", title)
        self.load_assignments()

    def delete_assignment(self):
        iid = self.selected_iid(self.assignment_tree, "Select an assignment to delete")
        if not iid:
            return
        values = self.assignment_tree.item(iid, "values")
        title = values[0] if values else "selected assignment"
        if not messagebox.askyesno("Delete assignment", f"Delete {title}?"):
            return
        self.db.cursor.execute("DELETE FROM assignments WHERE id=?", (iid,))
        self.db.conn.commit()
        self.notify("Assignment deleted", title)
        self.clear_assignment_form()
        self.load_assignments()

    def clear_assignment_form(self):
        self.selected_assignment_db_id = None
        self.a_title.set("")
        self.a_due.set("")
        self.clear_text(self.a_desc)
        if hasattr(self, "assignment_tree"):
            self.assignment_tree.selection_remove(self.assignment_tree.selection())

    def load_assignments(self):
        if not hasattr(self, "assignment_tree"):
            return
        for row in self.assignment_tree.get_children():
            self.assignment_tree.delete(row)
        self.db.cursor.execute("SELECT id, title, due_date, description FROM assignments ORDER BY id DESC")
        for index, assignment in enumerate(self.db.cursor.fetchall()):
            tag = "even" if index % 2 == 0 else "odd"
            desc = assignment[3] or ""
            if len(desc) > 80:
                desc = desc[:77] + "..."
            self.assignment_tree.insert(
                "",
                "end",
                iid=str(assignment[0]),
                values=(assignment[1], assignment[2] or "Not set", desc),
                tags=(tag,),
            )

    # ---------------------
    # Library
    # ---------------------
    def library_page(self):
        container = self.start_page(
            "Library",
            "Track books, issuing, returns, and due dates.",
            "Library",
            scroll=False,
        )

        issued_books = self.scalar("SELECT COUNT(*) FROM library_books WHERE status='Issued'")
        available_books = self.scalar("SELECT COUNT(*) FROM library_books WHERE status!='Issued'")
        total_books = self.scalar("SELECT COUNT(*) FROM library_books")

        summary = tk.Frame(container, bg=COLORS["background"])
        summary.pack(fill="x", pady=(0, 16))
        for index in range(3):
            summary.columnconfigure(index, weight=1)
        self.metric_card(summary, "Total Books", str(total_books), "Catalog records", 0)
        self.metric_card(summary, "Available", str(available_books), "Ready to issue", 1)
        self.metric_card(summary, "Issued", str(issued_books), "Currently borrowed", 2)

        self.selected_book_db_id = None
        form = self.card(container)
        form.pack(fill="x", pady=(0, 16))
        for index in range(5):
            form.columnconfigure(index, weight=1)

        self.book_accession_var = StringVar()
        self.book_title_var = StringVar()
        self.book_author_var = StringVar()
        self.book_student_var = StringVar()
        self.book_due_var = StringVar(value=date.today().isoformat())
        self.book_search_var = StringVar()

        fields = (
            ("Accession No.", self.book_accession_var, "entry"),
            ("Title", self.book_title_var, "entry"),
            ("Author", self.book_author_var, "entry"),
            ("Issue To", self.book_student_var, "student"),
            ("Due Date", self.book_due_var, "entry"),
        )
        for index, (label, variable, kind) in enumerate(fields):
            tk.Label(
                form,
                text=label,
                bg=COLORS["card"],
                fg=COLORS["text"],
                font=(FONT, 10, "bold"),
            ).grid(row=0, column=index, sticky="w", padx=(0 if index == 0 else 12, 0))
            if kind == "student":
                widget = ttk.Combobox(form, textvariable=variable, values=self.student_choices(), state="readonly")
            else:
                widget = ttk.Entry(form, textvariable=variable)
            widget.grid(
                row=1,
                column=index,
                sticky="ew",
                padx=(0 if index == 0 else 12, 0),
                pady=(6, 0),
            )

        tk.Label(
            form,
            text="Search Catalog",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT, 10, "bold"),
        ).grid(row=2, column=0, sticky="w", pady=(14, 0), columnspan=5)
        ttk.Entry(form, textvariable=self.book_search_var).grid(
            row=3,
            column=0,
            columnspan=5,
            sticky="ew",
            pady=(6, 12),
        )

        actions = tk.Frame(form, bg=COLORS["card"])
        actions.grid(row=4, column=0, columnspan=5, sticky="ew")
        ttk.Button(actions, text="Add Book", style="Accent.TButton", command=self.add_book).pack(side="left")
        ttk.Button(
            actions,
            text="Update Book",
            style="Secondary.TButton",
            command=self.update_book,
        ).pack(side="left", padx=(10, 0))
        ttk.Button(actions, text="Issue Selected", command=self.issue_book).pack(side="left", padx=(10, 0))
        ttk.Button(actions, text="Return Selected", command=self.return_book).pack(side="left", padx=(10, 0))
        ttk.Button(
            actions,
            text="Delete Selected",
            style="Danger.TButton",
            command=self.delete_book,
        ).pack(side="left", padx=(10, 0))
        ttk.Button(actions, text="Clear Form", command=self.clear_book_form).pack(side="left", padx=(10, 0))
        self.book_search_var.trace_add("write", lambda *_args: self.load_books())

        table = self.card(container)
        table.pack(fill="both", expand=True)
        tk.Label(
            table,
            text="Book Catalog",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT, 14, "bold"),
        ).pack(anchor="w")
        self.book_tree = self.create_tree(
            table,
            ("Accession", "Title", "Author", "Status", "Borrower", "Due Date"),
            height=10,
        )
        self.book_tree.column("Title", width=260)
        self.book_tree.column("Borrower", width=220)
        self.book_tree.bind("<<TreeviewSelect>>", self.select_book)
        self.load_books()

    def add_book(self):
        accession = self.book_accession_var.get().strip()
        title = self.book_title_var.get().strip()
        if not accession or not title:
            messagebox.showerror("Error", "Accession number and title are required")
            return
        self.db.cursor.execute(
            """
            INSERT INTO library_books(accession_no,title,author,status,borrower_id,borrower_name,due_date)
            VALUES(?,?,?,?,?,?,?)
            """,
            (
                accession,
                title,
                self.book_author_var.get().strip(),
                "Available",
                "",
                "",
                "",
            ),
        )
        self.db.conn.commit()
        self.notify("Book added", title)
        self.clear_book_form()
        self.load_books()

    def select_book(self, _event=None):
        selected = self.book_tree.selection()
        if not selected:
            return
        self.selected_book_db_id = selected[0]
        self.db.cursor.execute(
            """
            SELECT accession_no,title,author,borrower_id,borrower_name,due_date
            FROM library_books
            WHERE id=?
            """,
            (self.selected_book_db_id,),
        )
        row = self.db.cursor.fetchone()
        if not row:
            return
        self.book_accession_var.set(row[0] or "")
        self.book_title_var.set(row[1] or "")
        self.book_author_var.set(row[2] or "")
        borrower = f"{row[3]} - {row[4]}" if row[3] and row[4] else ""
        self.book_student_var.set(borrower)
        self.book_due_var.set(row[5] or date.today().isoformat())

    def update_book(self):
        if not self.selected_book_db_id:
            self.selected_book_db_id = self.selected_iid(self.book_tree, "Select a book to update")
            if not self.selected_book_db_id:
                return
        accession = self.book_accession_var.get().strip()
        title = self.book_title_var.get().strip()
        if not accession or not title:
            messagebox.showerror("Error", "Accession number and title are required")
            return
        self.db.cursor.execute(
            """
            UPDATE library_books
            SET accession_no=?, title=?, author=?
            WHERE id=?
            """,
            (accession, title, self.book_author_var.get().strip(), self.selected_book_db_id),
        )
        self.db.conn.commit()
        self.notify("Book updated", title)
        self.load_books()

    def issue_book(self):
        iid = self.selected_iid(self.book_tree, "Select a book to issue")
        if not iid:
            return
        student_id, student_name = self.parse_student_choice(self.book_student_var.get())
        if not student_id:
            messagebox.showerror("Error", "Select the student who is borrowing this book")
            return
        self.db.cursor.execute(
            """
            UPDATE library_books
            SET status='Issued', borrower_id=?, borrower_name=?, due_date=?
            WHERE id=?
            """,
            (student_id, student_name, self.book_due_var.get().strip(), iid),
        )
        self.db.conn.commit()
        self.notify("Book issued", f"{student_name} borrowed the selected book")
        self.load_books()

    def return_book(self):
        iid = self.selected_iid(self.book_tree, "Select a book to return")
        if not iid:
            return
        self.db.cursor.execute(
            """
            UPDATE library_books
            SET status='Available', borrower_id='', borrower_name='', due_date=''
            WHERE id=?
            """,
            (iid,),
        )
        self.db.conn.commit()
        self.notify("Book returned", "Selected book is now available")
        self.clear_book_form()
        self.load_books()

    def delete_book(self):
        iid = self.selected_iid(self.book_tree, "Select a book to delete")
        if not iid:
            return
        values = self.book_tree.item(iid, "values")
        title = values[1] if values else "selected book"
        if not messagebox.askyesno("Delete book", f"Delete {title}?"):
            return
        self.db.cursor.execute("DELETE FROM library_books WHERE id=?", (iid,))
        self.db.conn.commit()
        self.notify("Book deleted", title)
        self.clear_book_form()
        self.load_books()

    def clear_book_form(self):
        self.selected_book_db_id = None
        self.book_accession_var.set("")
        self.book_title_var.set("")
        self.book_author_var.set("")
        self.book_student_var.set("")
        self.book_due_var.set(date.today().isoformat())
        if hasattr(self, "book_tree"):
            self.book_tree.selection_remove(self.book_tree.selection())

    def load_books(self):
        if not hasattr(self, "book_tree"):
            return
        for row_id in self.book_tree.get_children():
            self.book_tree.delete(row_id)
        search = self.book_search_var.get().strip() if hasattr(self, "book_search_var") else ""
        if search:
            like = f"%{search}%"
            self.db.cursor.execute(
                """
                SELECT id, accession_no, title, author, status, borrower_name, due_date
                FROM library_books
                WHERE accession_no LIKE ? OR title LIKE ? OR author LIKE ? OR borrower_name LIKE ?
                ORDER BY title
                """,
                (like, like, like, like),
            )
        else:
            self.db.cursor.execute(
                """
                SELECT id, accession_no, title, author, status, borrower_name, due_date
                FROM library_books
                ORDER BY title
                """
            )
        for index, row in enumerate(self.db.cursor.fetchall()):
            row_tag = "even" if index % 2 == 0 else "odd"
            status_tag = "warning" if row[4] == "Issued" else "success"
            self.book_tree.insert(
                "",
                "end",
                iid=str(row[0]),
                values=(row[1], row[2], row[3] or "", row[4], row[5] or "", row[6] or ""),
                tags=(row_tag, status_tag),
            )

    # ---------------------
    # Analytics
    # ---------------------
    def analytics_page(self):
        container = self.start_page(
            "Analytics",
            "Visual attendance trend and operational signals.",
            "Analytics",
        )

        stats = tk.Frame(container, bg=COLORS["background"])
        stats.pack(fill="x", pady=(0, 16))
        for index in range(4):
            stats.columnconfigure(index, weight=1)
        self.metric_card(stats, "Students", str(self.scalar("SELECT COUNT(*) FROM students")), "Active records", 0)
        self.metric_card(stats, "Teachers", str(self.scalar("SELECT COUNT(*) FROM teachers")), "Faculty records", 1)
        self.metric_card(
            stats,
            "Assignments",
            str(self.scalar("SELECT COUNT(*) FROM assignments")),
            "Created tasks",
            2,
        )
        self.metric_card(
            stats,
            "Collected Fees",
            self.money(self.scalar("SELECT COALESCE(SUM(amount), 0) FROM fee_records WHERE status='Paid'")),
            "Paid records",
            3,
        )

        chart_card = self.card(container)
        chart_card.pack(fill="both", expand=True)
        tk.Label(
            chart_card,
            text="Attendance Trend",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT, 14, "bold"),
        ).pack(anchor="w")

        if Figure is None or FigureCanvasTkAgg is None:
            self.empty_state(
                chart_card,
                "Analytics chart unavailable",
                "Install matplotlib with pip install matplotlib to enable the embedded chart.",
            )
            return

        self.db.cursor.execute(
            """
            SELECT course, AVG(attendance)
            FROM students
            GROUP BY course
            ORDER BY course
            """
        )
        attendance_rows = self.db.cursor.fetchall()
        courses = [row[0] or "Unassigned" for row in attendance_rows] or ["No data"]
        attendance = [float(row[1] or 0) for row in attendance_rows] or [0]

        self.db.cursor.execute(
            """
            SELECT status, COALESCE(SUM(amount), 0)
            FROM fee_records
            GROUP BY status
            ORDER BY status
            """
        )
        fee_rows = self.db.cursor.fetchall()
        fee_labels = [row[0] or "Pending" for row in fee_rows] or ["No data"]
        fee_values = [float(row[1] or 0) for row in fee_rows] or [0]

        fig = Figure(figsize=(8, 4.6), dpi=100, facecolor=COLORS["card"])
        attendance_ax = fig.add_subplot(121)
        fees_ax = fig.add_subplot(122)
        for ax in (attendance_ax, fees_ax):
            ax.set_facecolor(COLORS["card"])
            ax.grid(True, axis="y", color="#e2e8f0", linewidth=0.8)
            ax.spines["top"].set_visible(False)
            ax.spines["right"].set_visible(False)
            ax.spines["left"].set_color(COLORS["border"])
            ax.spines["bottom"].set_color(COLORS["border"])
            ax.tick_params(colors=COLORS["muted"], labelsize=8)

        attendance_ax.bar(courses, attendance, color=COLORS["accent"])
        attendance_ax.set_title("Attendance by Course", color=COLORS["text"], fontsize=10, fontweight="bold")
        attendance_ax.set_ylim(0, 100)
        attendance_ax.set_ylabel("Attendance %")
        attendance_ax.tick_params(axis="x", rotation=25)

        palette = [COLORS["teal"], COLORS["orange"], COLORS["purple"]]
        fee_colors = [palette[index % len(palette)] for index in range(len(fee_labels))]
        fees_ax.bar(fee_labels, fee_values, color=fee_colors)
        fees_ax.set_title("Fee Ledger", color=COLORS["text"], fontsize=10, fontweight="bold")
        fees_ax.set_ylabel("Amount")
        fig.tight_layout()

        canvas = FigureCanvasTkAgg(fig, master=chart_card)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True, pady=(12, 0))

    # ---------------------
    # GPA Calculator
    # ---------------------
    def gpa_page(self):
        container = self.start_page(
            "GPA Calculator",
            "Convert marks to a 4.0 GPA scale.",
            "GPA Calculator",
        )

        panel = self.card(container)
        panel.pack(fill="x")
        tk.Label(
            panel,
            text="Total Marks",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT, 10, "bold"),
        ).pack(anchor="w")
        self.gpa_marks = StringVar()
        ttk.Entry(panel, textvariable=self.gpa_marks, width=30).pack(anchor="w", pady=(6, 14))
        self.gpa_result_lbl = tk.Label(
            panel,
            text="GPA: 0.00 / 4.00",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT, 20, "bold"),
        )
        self.gpa_result_lbl.pack(anchor="w")
        self.gpa_progress = ttk.Progressbar(
            panel,
            orient="horizontal",
            mode="determinate",
            maximum=4,
            value=0,
        )
        self.gpa_progress.pack(fill="x", pady=(10, 14))
        ttk.Button(
            panel,
            text="Calculate GPA",
            style="Accent.TButton",
            command=self.calculate_gpa,
        ).pack(anchor="w")

    def calculate_gpa(self):
        try:
            marks = float(self.gpa_marks.get())
            if marks < 0 or marks > 100:
                raise ValueError
            gpa = round((marks / 100) * 4, 2)
            self.gpa_result_lbl.configure(text=f"GPA: {gpa:.2f} / 4.00")
            self.gpa_progress.configure(value=gpa)
            self.set_status(f"GPA calculated from {marks:.1f} marks")
        except Exception:
            messagebox.showerror("Error", "Enter valid marks from 0 to 100")

    # ---------------------
    # Events
    # ---------------------
    def events_page(self):
        container = self.start_page(
            "Event Calendar",
            "Plan campus programs and keep dates organized.",
            "Events",
            scroll=False,
        )

        self.selected_event_db_id = None
        form = self.card(container)
        form.pack(fill="x", pady=(0, 16))
        for index in range(4):
            form.columnconfigure(index, weight=1)

        self.event_title_var = StringVar()
        self.event_date_var = StringVar(value=date.today().isoformat())
        self.event_category_var = StringVar(value="Academic")
        self.event_location_var = StringVar()

        labels = ("Title", "Date", "Category", "Location")
        variables = (
            self.event_title_var,
            self.event_date_var,
            self.event_category_var,
            self.event_location_var,
        )
        for index, label in enumerate(labels):
            tk.Label(
                form,
                text=label,
                bg=COLORS["card"],
                fg=COLORS["text"],
                font=(FONT, 10, "bold"),
            ).grid(row=0, column=index, sticky="w", padx=(0 if index == 0 else 12, 0))
            ttk.Entry(form, textvariable=variables[index]).grid(
                row=1,
                column=index,
                sticky="ew",
                padx=(0 if index == 0 else 12, 0),
                pady=(6, 0),
            )

        tk.Label(
            form,
            text="Description",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT, 10, "bold"),
        ).grid(row=2, column=0, sticky="w", pady=(14, 0), columnspan=4)
        self.event_desc_box = self.text_area(form, height=3)
        self.event_desc_box.grid(row=3, column=0, columnspan=4, sticky="ew", pady=(6, 12))

        action_row = tk.Frame(form, bg=COLORS["card"])
        action_row.grid(row=4, column=0, columnspan=4, sticky="ew")
        ttk.Button(
            action_row,
            text="Add Event",
            style="Accent.TButton",
            command=self.add_event,
        ).pack(side="left")
        ttk.Button(
            action_row,
            text="Update Selected",
            style="Secondary.TButton",
            command=self.update_event,
        ).pack(side="left", padx=(10, 0))
        ttk.Button(
            action_row,
            text="Delete Selected",
            style="Danger.TButton",
            command=self.delete_event,
        ).pack(side="left", padx=(10, 0))
        ttk.Button(
            action_row,
            text="Clear Form",
            command=self.clear_event_form,
        ).pack(side="left", padx=(10, 0))

        table = self.card(container)
        table.pack(fill="both", expand=True)
        tk.Label(
            table,
            text="Upcoming Events",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT, 14, "bold"),
        ).pack(anchor="w")
        self.event_tree = self.create_tree(
            table,
            ("Date", "Title", "Category", "Location", "Description"),
            height=11,
        )
        self.event_tree.column("Title", width=220)
        self.event_tree.column("Description", width=360)
        self.event_tree.bind("<<TreeviewSelect>>", self.select_event)
        self.load_events()

    def add_event(self):
        title = self.event_title_var.get().strip()
        if not title:
            messagebox.showerror("Error", "Event title required")
            return
        self.db.cursor.execute(
            """
            INSERT INTO events(title,event_date,category,location,description)
            VALUES(?,?,?,?,?)
            """,
            (
                title,
                self.event_date_var.get().strip(),
                self.event_category_var.get().strip(),
                self.event_location_var.get().strip(),
                self.event_desc_box.get("1.0", "end").strip(),
            ),
        )
        self.db.conn.commit()
        self.notify("Event added", title)
        self.clear_event_form()
        self.load_events()

    def select_event(self, _event=None):
        selected = self.event_tree.selection()
        if not selected:
            return
        self.selected_event_db_id = selected[0]
        self.db.cursor.execute(
            "SELECT title, event_date, category, location, description FROM events WHERE id=?",
            (self.selected_event_db_id,),
        )
        row = self.db.cursor.fetchone()
        if not row:
            return
        self.event_title_var.set(row[0] or "")
        self.event_date_var.set(row[1] or "")
        self.event_category_var.set(row[2] or "")
        self.event_location_var.set(row[3] or "")
        self.clear_text(self.event_desc_box)
        self.event_desc_box.insert("1.0", row[4] or "")

    def update_event(self):
        if not self.selected_event_db_id:
            self.selected_event_db_id = self.selected_iid(self.event_tree, "Select an event to update")
            if not self.selected_event_db_id:
                return
        title = self.event_title_var.get().strip()
        if not title:
            messagebox.showerror("Error", "Event title required")
            return
        self.db.cursor.execute(
            """
            UPDATE events
            SET title=?, event_date=?, category=?, location=?, description=?
            WHERE id=?
            """,
            (
                title,
                self.event_date_var.get().strip(),
                self.event_category_var.get().strip(),
                self.event_location_var.get().strip(),
                self.event_desc_box.get("1.0", "end").strip(),
                self.selected_event_db_id,
            ),
        )
        self.db.conn.commit()
        self.notify("Event updated", title)
        self.load_events()

    def delete_event(self):
        iid = self.selected_iid(self.event_tree, "Select an event to delete")
        if not iid:
            return
        values = self.event_tree.item(iid, "values")
        title = values[1] if values else "selected event"
        if not messagebox.askyesno("Delete event", f"Delete {title}?"):
            return
        self.db.cursor.execute("DELETE FROM events WHERE id=?", (iid,))
        self.db.conn.commit()
        self.notify("Event deleted", title)
        self.clear_event_form()
        self.load_events()

    def clear_event_form(self):
        self.selected_event_db_id = None
        self.event_title_var.set("")
        self.event_date_var.set(date.today().isoformat())
        self.event_category_var.set("Academic")
        self.event_location_var.set("")
        self.clear_text(self.event_desc_box)
        if hasattr(self, "event_tree"):
            self.event_tree.selection_remove(self.event_tree.selection())

    def load_events(self):
        if not hasattr(self, "event_tree"):
            return
        for row_id in self.event_tree.get_children():
            self.event_tree.delete(row_id)
        self.db.cursor.execute(
            """
            SELECT id, event_date, title, category, location, description
            FROM events
            ORDER BY event_date, id
            """
        )
        for index, row in enumerate(self.db.cursor.fetchall()):
            tag = "even" if index % 2 == 0 else "odd"
            desc = row[5] or ""
            if len(desc) > 80:
                desc = desc[:77] + "..."
            self.event_tree.insert(
                "",
                "end",
                iid=str(row[0]),
                values=(row[1] or "Not set", row[2], row[3] or "", row[4] or "", desc),
                tags=(tag,),
            )

    # ---------------------
    # Notifications
    # ---------------------
    def notification_center(self):
        container = self.start_page(
            "Notifications",
            "Live notices from attendance, fees, events, and LMS records.",
            "Notifications",
        )
        notes = []
        low_attendance = self.scalar("SELECT COUNT(*) FROM students WHERE attendance < 75")
        pending_fees = self.scalar("SELECT COALESCE(SUM(amount), 0) FROM fee_records WHERE status!='Paid'")
        assignment_count = self.scalar("SELECT COUNT(*) FROM assignments")
        issued_books = self.scalar("SELECT COUNT(*) FROM library_books WHERE status='Issued'")
        timetable_slots = self.scalar("SELECT COUNT(*) FROM timetable")
        self.db.cursor.execute(
            "SELECT title, event_date FROM events ORDER BY event_date, id LIMIT 1"
        )
        next_event = self.db.cursor.fetchone()

        if low_attendance:
            notes.append(
                (
                    "Attendance follow-up",
                    f"{low_attendance} student records are below the 75% threshold.",
                )
            )
        if pending_fees:
            notes.append(("Fee reminder", f"{self.money(pending_fees)} is pending in the fee ledger."))
        if assignment_count:
            notes.append(("LMS activity", f"{assignment_count} assignments are available for review."))
        if issued_books:
            notes.append(("Library circulation", f"{issued_books} books are currently issued to students."))
        if timetable_slots:
            notes.append(("Timetable ready", f"{timetable_slots} weekly schedule slots are configured."))
        if next_event:
            notes.append(("Upcoming event", f"{next_event[0]} is scheduled for {next_event[1] or 'a pending date'}."))
        if not notes:
            notes.append(("All clear", "No operational alerts are waiting right now."))

        for title, body in notes:
            note = self.card(container)
            note.pack(fill="x", pady=7)
            self.pill_label(note, "Notice", "#fef3c7", COLORS["warning"]).pack(anchor="w")
            tk.Label(
                note,
                text=title,
                bg=COLORS["card"],
                fg=COLORS["text"],
                font=(FONT, 12, "bold"),
            ).pack(anchor="w", pady=(8, 0))
            tk.Label(
                note,
                text=body,
                bg=COLORS["card"],
                fg=COLORS["muted"],
                font=(FONT, 10),
            ).pack(anchor="w", pady=(4, 0))

        if notification:
            try:
                notification.notify(title="Notifications", message=notes[0][0], timeout=3)
            except Exception:
                pass

    # ---------------------
    # Chat
    # ---------------------
    def chat_page(self):
        container = self.start_page(
            "Messaging System",
            "A simple local message area.",
            "Chat",
            scroll=False,
        )
        panel = self.card(container)
        panel.pack(fill="both", expand=True)
        self.chat_box = self.text_area(panel, height=18, readonly=True)
        self.chat_box.pack(fill="both", expand=True)

        input_row = tk.Frame(panel, bg=COLORS["card"])
        input_row.pack(fill="x", pady=(12, 0))
        input_row.columnconfigure(0, weight=1)
        self.chat_input_var = StringVar()
        entry = ttk.Entry(input_row, textvariable=self.chat_input_var)
        entry.grid(row=0, column=0, sticky="ew")
        ttk.Button(input_row, text="Send", style="Accent.TButton", command=self.send_chat).grid(
            row=0,
            column=1,
            padx=(10, 0),
        )
        entry.bind("<Return>", lambda _event: self.send_chat())

    def send_chat(self):
        msg = self.chat_input_var.get().strip()
        if not msg:
            return
        self.append_text(self.chat_box, f"YOU: {msg}\n")
        self.append_text(self.chat_box, f"AI: This is a local assistant echoing '{msg}'\n\n")
        self.chat_input_var.set("")

    # ---------------------
    # Fees
    # ---------------------
    def fees_page(self):
        container = self.start_page(
            "Fee Management",
            "Create invoices and track payment status.",
            "Fees",
            scroll=False,
        )
        paid_total = self.scalar("SELECT COALESCE(SUM(amount), 0) FROM fee_records WHERE status='Paid'")
        pending_total = self.scalar("SELECT COALESCE(SUM(amount), 0) FROM fee_records WHERE status!='Paid'")
        total = self.scalar("SELECT COALESCE(SUM(amount), 0) FROM fee_records")

        summary = tk.Frame(container, bg=COLORS["background"])
        summary.pack(fill="x", pady=(0, 16))
        for index in range(3):
            summary.columnconfigure(index, weight=1)
        self.metric_card(summary, "Collected", self.money(paid_total), "Paid invoices", 0)
        self.metric_card(summary, "Pending", self.money(pending_total), "Awaiting payment", 1)
        self.metric_card(summary, "Total", self.money(total), "All fee records", 2)

        self.selected_fee_db_id = None
        form = self.card(container)
        form.pack(fill="x", pady=(0, 16))
        for index in range(4):
            form.columnconfigure(index, weight=1)

        self.fee_student_var = StringVar()
        self.fee_amount_var = StringVar()
        self.fee_due_var = StringVar(value=date.today().isoformat())
        self.fee_status_var = StringVar(value="Pending")
        self.fee_notes_var = StringVar()

        tk.Label(
            form,
            text="Student",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT, 10, "bold"),
        ).grid(row=0, column=0, sticky="w")
        tk.Label(
            form,
            text="Amount",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT, 10, "bold"),
        ).grid(row=0, column=1, sticky="w", padx=(12, 0))
        tk.Label(
            form,
            text="Due Date",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT, 10, "bold"),
        ).grid(row=0, column=2, sticky="w", padx=(12, 0))
        tk.Label(
            form,
            text="Status",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT, 10, "bold"),
        ).grid(row=0, column=3, sticky="w", padx=(12, 0))

        ttk.Combobox(
            form,
            textvariable=self.fee_student_var,
            values=self.student_choices(),
            state="readonly",
        ).grid(row=1, column=0, sticky="ew", pady=(6, 0))
        ttk.Entry(form, textvariable=self.fee_amount_var).grid(
            row=1,
            column=1,
            sticky="ew",
            padx=(12, 0),
            pady=(6, 0),
        )
        ttk.Entry(form, textvariable=self.fee_due_var).grid(
            row=1,
            column=2,
            sticky="ew",
            padx=(12, 0),
            pady=(6, 0),
        )
        ttk.Combobox(
            form,
            textvariable=self.fee_status_var,
            values=("Pending", "Paid", "Partial"),
            state="readonly",
        ).grid(row=1, column=3, sticky="ew", padx=(12, 0), pady=(6, 0))

        tk.Label(
            form,
            text="Notes",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT, 10, "bold"),
        ).grid(row=2, column=0, sticky="w", pady=(14, 0), columnspan=4)
        ttk.Entry(form, textvariable=self.fee_notes_var).grid(
            row=3,
            column=0,
            columnspan=4,
            sticky="ew",
            pady=(6, 12),
        )

        action_row = tk.Frame(form, bg=COLORS["card"])
        action_row.grid(row=4, column=0, columnspan=4, sticky="ew")
        ttk.Button(
            action_row,
            text="Add Fee Record",
            style="Accent.TButton",
            command=self.add_fee_record,
        ).pack(side="left")
        ttk.Button(
            action_row,
            text="Mark Paid",
            style="Secondary.TButton",
            command=self.mark_fee_paid,
        ).pack(side="left", padx=(10, 0))
        ttk.Button(
            action_row,
            text="Delete Selected",
            style="Danger.TButton",
            command=self.delete_fee_record,
        ).pack(side="left", padx=(10, 0))
        ttk.Button(
            action_row,
            text="Clear Form",
            command=self.clear_fee_form,
        ).pack(side="left", padx=(10, 0))

        table = self.card(container)
        table.pack(fill="both", expand=True)
        tk.Label(
            table,
            text="Fee Ledger",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT, 14, "bold"),
        ).pack(anchor="w")
        self.fee_tree = self.create_tree(
            table,
            ("Student", "Amount", "Status", "Due Date", "Paid Date", "Notes"),
            height=10,
        )
        self.fee_tree.column("Student", width=220)
        self.fee_tree.column("Notes", width=280)
        self.fee_tree.bind("<<TreeviewSelect>>", self.select_fee_record)
        self.load_fee_records()

    def add_fee_record(self):
        student_id, student_name = self.parse_student_choice(self.fee_student_var.get())
        if not student_id:
            messagebox.showerror("Error", "Select a student first")
            return
        try:
            amount = self.get_float(self.fee_amount_var.get().strip(), "Amount", 0)
        except ValueError as exc:
            messagebox.showerror("Error", str(exc))
            return
        status = self.fee_status_var.get().strip() or "Pending"
        paid_date = date.today().isoformat() if status == "Paid" else ""
        self.db.cursor.execute(
            """
            INSERT INTO fee_records(student_id,student_name,amount,status,due_date,paid_date,notes)
            VALUES(?,?,?,?,?,?,?)
            """,
            (
                student_id,
                student_name,
                amount,
                status,
                self.fee_due_var.get().strip(),
                paid_date,
                self.fee_notes_var.get().strip(),
            ),
        )
        self.db.conn.commit()
        self.notify("Fee record added", f"{student_name}: {self.money(amount)}")
        self.fees_page()

    def select_fee_record(self, _event=None):
        selected = self.fee_tree.selection()
        if not selected:
            return
        self.selected_fee_db_id = selected[0]
        self.db.cursor.execute(
            """
            SELECT student_id, student_name, amount, status, due_date, notes
            FROM fee_records
            WHERE id=?
            """,
            (self.selected_fee_db_id,),
        )
        row = self.db.cursor.fetchone()
        if not row:
            return
        self.fee_student_var.set(f"{row[0]} - {row[1]}")
        self.fee_amount_var.set(f"{float(row[2] or 0):.2f}")
        self.fee_status_var.set(row[3] or "Pending")
        self.fee_due_var.set(row[4] or "")
        self.fee_notes_var.set(row[5] or "")

    def mark_fee_paid(self):
        iid = self.selected_iid(self.fee_tree, "Select a fee record to mark paid")
        if not iid:
            return
        self.db.cursor.execute(
            "UPDATE fee_records SET status='Paid', paid_date=? WHERE id=?",
            (date.today().isoformat(), iid),
        )
        self.db.conn.commit()
        self.notify("Fee updated", "Marked selected record as paid")
        self.fees_page()

    def delete_fee_record(self):
        iid = self.selected_iid(self.fee_tree, "Select a fee record to delete")
        if not iid:
            return
        values = self.fee_tree.item(iid, "values")
        label = values[0] if values else "selected fee record"
        if not messagebox.askyesno("Delete fee record", f"Delete fee record for {label}?"):
            return
        self.db.cursor.execute("DELETE FROM fee_records WHERE id=?", (iid,))
        self.db.conn.commit()
        self.notify("Fee record deleted", label)
        self.fees_page()

    def clear_fee_form(self):
        self.selected_fee_db_id = None
        self.fee_student_var.set("")
        self.fee_amount_var.set("")
        self.fee_due_var.set(date.today().isoformat())
        self.fee_status_var.set("Pending")
        self.fee_notes_var.set("")
        if hasattr(self, "fee_tree"):
            self.fee_tree.selection_remove(self.fee_tree.selection())

    def load_fee_records(self):
        if not hasattr(self, "fee_tree"):
            return
        for row_id in self.fee_tree.get_children():
            self.fee_tree.delete(row_id)
        self.db.cursor.execute(
            """
            SELECT id, student_name, amount, status, due_date, paid_date, notes
            FROM fee_records
            ORDER BY id DESC
            """
        )
        for index, row in enumerate(self.db.cursor.fetchall()):
            row_tag = "even" if index % 2 == 0 else "odd"
            status_tag = "success" if row[3] == "Paid" else "warning"
            self.fee_tree.insert(
                "",
                "end",
                iid=str(row[0]),
                values=(
                    row[1],
                    self.money(row[2]),
                    row[3] or "Pending",
                    row[4] or "",
                    row[5] or "",
                    row[6] or "",
                ),
                tags=(row_tag, status_tag),
            )

    # ---------------------
    # Export PDF
    # ---------------------
    def export_pdf(self):
        if SimpleDocTemplate is None:
            messagebox.showwarning(
                "Missing",
                "reportlab not installed. Install: pip install reportlab\n"
                "A plain text report will be written instead.",
            )
            self._export_text_report()
            return

        doc = SimpleDocTemplate("school_report.pdf")
        styles = getSampleStyleSheet()
        students = self.scalar("SELECT COUNT(*) FROM students")
        teachers = self.scalar("SELECT COUNT(*) FROM teachers")
        courses = self.scalar("SELECT COUNT(*) FROM courses")
        assignments = self.scalar("SELECT COUNT(*) FROM assignments")
        timetable_slots = self.scalar("SELECT COUNT(*) FROM timetable")
        issued_books = self.scalar("SELECT COUNT(*) FROM library_books WHERE status='Issued'")
        paid_total = self.scalar("SELECT COALESCE(SUM(amount), 0) FROM fee_records WHERE status='Paid'")
        pending_total = self.scalar("SELECT COALESCE(SUM(amount), 0) FROM fee_records WHERE status!='Paid'")
        elements = [
            Paragraph("Enterprise School ERP Report", styles["Title"]),
            Paragraph(f"Generated: {datetime.now().isoformat()}", styles["Normal"]),
            Paragraph(f"Students: {students}", styles["BodyText"]),
            Paragraph(f"Teachers: {teachers}", styles["BodyText"]),
            Paragraph(f"Courses: {courses}", styles["BodyText"]),
            Paragraph(f"Assignments: {assignments}", styles["BodyText"]),
            Paragraph(f"Timetable Slots: {timetable_slots}", styles["BodyText"]),
            Paragraph(f"Books Issued: {issued_books}", styles["BodyText"]),
            Paragraph(f"Collected Fees: {self.money(paid_total)}", styles["BodyText"]),
            Paragraph(f"Pending Fees: {self.money(pending_total)}", styles["BodyText"]),
        ]
        doc.build(elements)
        self.notify("Exported", "school_report.pdf created")
        messagebox.showinfo("Exported", "school_report.pdf created")

    def _export_text_report(self):
        students = self.scalar("SELECT COUNT(*) FROM students")
        teachers = self.scalar("SELECT COUNT(*) FROM teachers")
        courses = self.scalar("SELECT COUNT(*) FROM courses")
        assignments = self.scalar("SELECT COUNT(*) FROM assignments")
        timetable_slots = self.scalar("SELECT COUNT(*) FROM timetable")
        issued_books = self.scalar("SELECT COUNT(*) FROM library_books WHERE status='Issued'")
        paid_total = self.scalar("SELECT COALESCE(SUM(amount), 0) FROM fee_records WHERE status='Paid'")
        pending_total = self.scalar("SELECT COALESCE(SUM(amount), 0) FROM fee_records WHERE status!='Paid'")
        with open("school_report.txt", "w", encoding="utf-8") as report:
            report.write("Enterprise School ERP Report\n")
            report.write(f"Generated: {datetime.now().isoformat()}\n\n")
            report.write(f"Students: {students}\n")
            report.write(f"Teachers: {teachers}\n")
            report.write(f"Courses: {courses}\n")
            report.write(f"Assignments: {assignments}\n")
            report.write(f"Timetable Slots: {timetable_slots}\n")
            report.write(f"Books Issued: {issued_books}\n")
            report.write(f"Collected Fees: {self.money(paid_total)}\n")
            report.write(f"Pending Fees: {self.money(pending_total)}\n")
        self.notify("Exported", "school_report.txt created")
        messagebox.showinfo("Exported", "school_report.txt created")

    # ---------------------
    # AI Assistant
    # ---------------------
    def ai_assistant_page(self):
        container = self.start_page(
            "AI Assistant",
            "Demo helper for quick school queries.",
            "AI Assistant",
            scroll=False,
        )
        panel = self.card(container)
        panel.pack(fill="both", expand=True)
        self.ai_box = self.text_area(panel, height=18, readonly=True)
        self.ai_box.pack(fill="both", expand=True)

        input_row = tk.Frame(panel, bg=COLORS["card"])
        input_row.pack(fill="x", pady=(12, 0))
        input_row.columnconfigure(0, weight=1)
        self.ai_entry_var = StringVar()
        entry = ttk.Entry(input_row, textvariable=self.ai_entry_var)
        entry.grid(row=0, column=0, sticky="ew")
        ttk.Button(input_row, text="Send", style="Accent.TButton", command=self.send_ai).grid(
            row=0,
            column=1,
            padx=(10, 0),
        )
        entry.bind("<Return>", lambda _event: self.send_ai())

    def send_ai(self):
        q = self.ai_entry_var.get().strip()
        if not q:
            return

        lowered = q.lower()
        if "gpa" in lowered:
            answer = "Your GPA is currently 3.8 in this demo."
        elif "attendance" in lowered:
            avg = self.scalar("SELECT COALESCE(AVG(attendance), 0) FROM students")
            answer = f"Average attendance is currently {avg:.0f}%."
        elif "course" in lowered:
            answer = f"There are {self.scalar('SELECT COUNT(*) FROM courses')} courses in the catalog."
        elif "timetable" in lowered or "schedule" in lowered:
            answer = f"The timetable has {self.scalar('SELECT COUNT(*) FROM timetable')} weekly slots configured."
        elif "library" in lowered or "book" in lowered:
            issued = self.scalar("SELECT COUNT(*) FROM library_books WHERE status='Issued'")
            total = self.scalar("SELECT COUNT(*) FROM library_books")
            answer = f"The library has {total} books, with {issued} currently issued."
        elif "fee" in lowered or "payment" in lowered:
            pending = self.scalar("SELECT COALESCE(SUM(amount), 0) FROM fee_records WHERE status!='Paid'")
            answer = f"Pending fee balance is {self.money(pending)}."
        elif "assignment" in lowered:
            answer = "Open Assignments to create and review LMS tasks."
        else:
            answer = "I can help with students, teachers, courses, timetable, library, fees, assignments, GPA, and attendance."

        self.append_text(self.ai_box, f"YOU: {q}\nAI: {answer}\n\n")
        self.ai_entry_var.set("")


def main():
    root = Tk()
    SchoolERP(root)
    root.mainloop()


if __name__ == "__main__":
    main()
