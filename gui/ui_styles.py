import tkinter as tk
from tkinter import ttk

# --- ค่านิยมพื้นฐาน (Modern Dark Theme) ---
COLORS = {
    "bg_dark": "#1e1e2e",      # พื้นหลังหลัก
    "bg_secondary": "#282a36", # พื้นหลังช่อง Input
    "fg_main": "#ffffff",      # ตัวอักษรหลัก
    "fg_muted": "#94a3b8",     # ตัวอักษรสีรอง
    "accent_primary": "#ff5555",# สีแดง (THREAT)
    "accent_success": "#50fa7b",# สีเขียว (SAFE)
    "accent_info": "#8be9fd",   # สีฟ้า (ANALYZING)
    "accent_warn": "#f1fa8c",   # สีเหลือง (SUSPICIOUS)
    "text_dark": "#11111b"      # สีตัวอักษรสำหรับพื้นหลังสว่าง
}

FONTS = {
    "header": ("Inter", 28, "bold"),
    "sub_header": ("Inter", 10),
    "button": ("Inter", 12, "bold"),
    "status": ("Inter", 9, "bold"),
    "code": ("Consolas", 11),
    "popup_title": ("Inter", 14, "bold"),
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
    """ฟังก์ชันสร้างหน้าต่างแจ้งเตือนแยกตามสีความเสี่ยง"""
    dialog = tk.Toplevel(parent)
    dialog.title(title)
    dialog.geometry("500x320")
    dialog.configure(bg=COLORS["bg_dark"])
    dialog.resizable(False, False)
    dialog.transient(parent) 
    dialog.grab_set()

    # แถบหัวเรื่องเปลี่ยนสีตามความเสี่ยง
    header = tk.Frame(dialog, bg=color, height=60)
    header.pack(fill="x")
    
    # ปรับสีฟอนต์ตามพื้นหลัง (สีแดงใช้ฟอนต์ขาว สีอื่นใช้ฟอนต์เข้ม)
    text_color = "white" if color == COLORS["accent_primary"] else COLORS["text_dark"]
    tk.Label(header, text=title, font=FONTS["popup_title"], bg=color, fg=text_color).pack(pady=15)

    # รายละเอียดการวิเคราะห์
    body = tk.Frame(dialog, bg=COLORS["bg_dark"])
    body.pack(expand=True, fill="both", padx=25, pady=20)
    tk.Label(body, text=message, font=FONTS["popup_body"], bg=COLORS["bg_dark"], 
             fg=COLORS["fg_main"], justify="left", wraplength=440).pack()

    # ปุ่มปิด
    btn = tk.Button(dialog, text="CLOSE", command=dialog.destroy, font=FONTS["button"], 
                    bg=color, fg=text_color, relief="flat", padx=30, pady=7, cursor="hand2")
    btn.pack(pady=20)