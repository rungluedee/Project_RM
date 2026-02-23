import tkinter as tk
from tkinter import ttk, scrolledtext

# --- ค่านิยมพื้นฐาน (Modern Dark Theme - Dracula Inspired) ---
COLORS = {
    "bg_dark": "#1e1e2e",      # พื้นหลังหลัก
    "bg_secondary": "#282a36", # พื้นหลังช่องเนื้อหา
    "fg_main": "#f8f8f2",      # ตัวอักษรหลัก
    "fg_muted": "#94a3b8",     # ตัวอักษรสีรอง
    "accent_primary": "#f00000",# สีแดง (THREAT)
    "accent_success": "#15f74e",# สีเขียว (SAFE)
    "accent_info": "#8be9fd",   # สีฟ้า (ANALYZING)
    "accent_warn": "#fb8a00",   # สีส้ม (SUSPICIOUS)
    "text_dark": "#282a36"      # สีตัวอักษรสำหรับพื้นหลังสว่าง
}

FONTS = {
    "header": ("Inter", 28, "bold"),
    "sub_header": ("Inter", 10),
    "button": ("Inter", 11, "bold"),
    "status": ("Inter", 9, "bold"),
    "code": ("Consolas", 10),
    "popup_title": ("Inter", 16, "bold"),
    "popup_body": ("Inter", 10)
}

def apply_styles():
    """ตั้งค่าสไตล์เบื้องต้นให้กับระบบ GUI"""
    style = ttk.Style()
    style.theme_use('clam')
    style.configure("Modern.Horizontal.TProgressbar", 
                    troughcolor=COLORS["bg_secondary"], 
                    background=COLORS["accent_success"], 
                    thickness=10)
    return style

def show_result_popup(parent, title, message, color):
    """ฟังก์ชันสร้างหน้าต่างรายงานการวิเคราะห์แบบ Dashboard"""
    dialog = tk.Toplevel(parent)
    dialog.title(f"SCAN REPORT: {title}")
    dialog.geometry("550x650")  # ปรับให้สูงขึ้นเพื่อรองรับข้อมูลที่ครบถ้วน
    dialog.configure(bg=COLORS["bg_dark"])
    dialog.transient(parent) 
    dialog.grab_set()

    # --- Header: แถบสถานะด้านบน ---
    header = tk.Frame(dialog, bg=color, height=70)
    header.pack(fill="x")
    header.pack_propagate(False)
    
    # ปรับสีฟอนต์ตามพื้นหลัง
    text_color = "#ffffff" if color == COLORS["accent_primary"] else COLORS["text_dark"]
    
    status_icon = "🛡️" if title == "SAFE" else "🚨"
    tk.Label(header, text=f"{status_icon} {title}", font=FONTS["popup_title"], 
             bg=color, fg=text_color).pack(expand=True)

    # --- Body: ส่วนเนื้อหาการวิเคราะห์ ---
    content_frame = tk.Frame(dialog, bg=COLORS["bg_dark"], padx=20, pady=15)
    content_frame.pack(fill="both", expand=True)

    # ใช้ ScrolledText เพื่อความสวยงามและรองรับข้อมูลเยอะโดยไม่ค้าง
    report_area = scrolledtext.ScrolledText(
        content_frame, 
        font=FONTS["code"], 
        bg=COLORS["bg_secondary"], 
        fg=COLORS["fg_main"],
        relief="flat", 
        padx=15, 
        pady=15,
        borderwidth=0
    )
    report_area.pack(fill="both", expand=True)
    
    # แทรกข้อความ Report
    report_area.insert(tk.INSERT, message)
    report_area.configure(state='disabled') # อ่านอย่างเดียว ห้ามแก้ไข

    # --- Footer: ปุ่มปิดด้านล่าง ---
    footer = tk.Frame(dialog, bg=COLORS["bg_dark"], pady=15)
    footer.pack(fill="x")

    btn = tk.Button(
        footer, 
        text="DISMISS REPORT", 
        command=dialog.destroy, 
        font=FONTS["button"], 
        bg="#44475a", 
        fg="white", 
        relief="flat", 
        padx=40, 
        pady=10, 
        cursor="hand2",
        activebackground="#6272a4",
        activeforeground="white"
    )
    btn.pack()