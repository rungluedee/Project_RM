import os
import sys
import tkinter as tk
from tkinter import filedialog, ttk, simpledialog, messagebox
import threading

# --- จัดการ Path เพื่อให้หาโฟลเดอร์ core เจอ ---
# หาตำแหน่งของโฟลเดอร์ D:/project
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)

if project_root not in sys.path:
    sys.path.append(project_root)

# นำเข้าการตกแต่งและการแจ้งเตือน (เรียกจากโฟลเดอร์เดียวกัน)
try:
    from ui_styles import COLORS, FONTS, apply_styles, show_result_popup
except ImportError:
    from gui.ui_styles import COLORS, FONTS, apply_styles, show_result_popup

# นำเข้าโมดูลจาก core
from core.input_files_path import InputHandler
from core.feature_extractor import get_feature_vector, get_pe_metadata
from core.ensemble_classifier import EnsembleClassifier
from core.malware_cleaner import run_deep_cleanup, scan_hidden_persistence

# --- การกำหนดค่า Path ของโมเดล AI (ใช้ Path แบบ Absolute เพื่อความชัวร์) ---
MODELS_CONFIG = {
    'lgbm': "D:/project/ember2018/ember_model_2018.txt",
    'rf': "D:/project/models/random_forest.pkl",
    'et': "D:/project/models/extra_trees.pkl"
}

class MalwareScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SHIELD AI | NEXT-GEN DETECTION")
        self.root.geometry("700x520")
        self.root.configure(bg=COLORS["bg_dark"])
        
        # ส่งค่า temp_dir ให้ชัดเจนเพื่อป้องกันการสับสนของ Path
        self.handler = InputHandler(temp_dir=os.path.join(project_root, "temp_extraction"))
        self.style = apply_styles()
        self._build_ui()
        
        # โหลดโมเดลเบื้องหลัง
        threading.Thread(target=self._warmup_engines, daemon=True).start()

    def _warmup_engines(self):
        """โหลดโมเดล AI"""
        try:
            self.classifier = EnsembleClassifier(MODELS_CONFIG)
            self.root.after(0, lambda: self.status.config(text="SYSTEM READY", fg=COLORS["accent_success"]))
        except Exception as e:
            self.root.after(0, lambda: self.status.config(text=f"ERROR: Model Not Found", fg=COLORS["accent_primary"]))

    def _build_ui(self):
        """สร้าง UI"""
        header = tk.Frame(self.root, bg=COLORS["bg_dark"])
        header.pack(pady=30)
        tk.Label(header, text="🛡️ SHIELD AI", font=FONTS["header"], bg=COLORS["bg_dark"], fg=COLORS["fg_main"]).pack()
        tk.Label(header, text="Ensemble Malware Detection System", font=FONTS["sub_header"], bg=COLORS["bg_dark"], fg=COLORS["fg_muted"]).pack()

        input_f = tk.Frame(self.root, bg=COLORS["bg_dark"])
        input_f.pack(pady=20, padx=50, fill="x")
        self.path_var = tk.StringVar()
        self.entry = tk.Entry(input_f, textvariable=self.path_var, font=FONTS["code"], bg=COLORS["bg_secondary"], fg=COLORS["fg_main"], relief="flat", borderwidth=10)
        self.entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        tk.Button(input_f, text="BROWSE", command=self._browse, font=("Inter", 9, "bold"), bg="#44475a", fg="white", relief="flat", padx=15, cursor="hand2").pack(side="right")

        self.scan_btn = tk.Button(self.root, text="START DEEP SCAN", font=FONTS["button"], bg=COLORS["accent_primary"], fg="white", relief="flat", width=30, height=2, command=self._start_thread, cursor="hand2")
        self.scan_btn.pack(pady=30)

        self.progress = ttk.Progressbar(self.root, style="Modern.Horizontal.TProgressbar", length=500, mode="determinate")
        self.progress.pack(pady=(10, 5))
        self.status = tk.Label(self.root, text="INITIALIZING...", bg=COLORS["bg_dark"], fg=COLORS["accent_warn"], font=FONTS["status"])
        self.status.pack()

    def _browse(self):
        path = filedialog.askopenfilename(filetypes=[("Executable/Archive", "*.exe *.zip")])
        if path: self.path_var.set(path)

    def _ask_password_popup(self):
        """แสดงหน้าต่างถามรหัสแบบเน้นความเสถียร (Thread-Safe)"""
        # สร้างตัวแปรรับค่าที่ Main Thread
        password_val = tk.StringVar()
        
        def on_submit(event=None):
            password_val.set(entry.get())
            dialog.destroy()

        # สร้างหน้าต่าง Dialog แบบ Custom
        dialog = tk.Toplevel(self.root)
        dialog.title("🔐 ZIP Password Required")
        dialog.geometry("350x180")
        dialog.configure(bg="#282a36")
        dialog.resizable(False, False)
        dialog.transient(self.root) # ให้อยู่เหนือหน้าต่างหลัก
        dialog.grab_set() # ล็อคหน้าจอหลักไว้จนกว่าจะกรอกเสร็จ

        tk.Label(dialog, text="ไฟล์ ZIP นี้ถูกเข้ารหัสไว้", font=("Inter", 10, "bold"), bg="#282a36", fg="#ff79c6").pack(pady=(15, 5))
        tk.Label(dialog, text="กรุณากรอกรหัสผ่านเพื่อสแกน:", bg="#282a36", fg="white").pack()
        
        entry = tk.Entry(dialog, show="*", font=("Consolas", 12), bg="#44475a", fg="white", insertbackground="white", relief="flat")
        entry.pack(pady=10, padx=30, fill="x")
        entry.bind("<Return>", on_submit) # กด Enter เพื่อยืนยันได้
        entry.focus_set()

        btn = tk.Button(dialog, text="UNLOCK & SCAN", command=on_submit, bg="#50fa7b", fg="#282a36", font=("Inter", 9, "bold"), relief="flat", padx=20)
        btn.pack(pady=10)

        # รอจนกว่าหน้าต่างนี้จะปิดลง
        self.root.wait_window(dialog)
        
        return password_val.get() if password_val.get() else None

    def _start_thread(self):
        if not hasattr(self, 'classifier'): 
            messagebox.showwarning("Warning", "ระบบ AI ยังโหลดไม่เสร็จ กรุณารอสักครู่")
            return
        path = self.path_var.get().strip().replace('"', '')
        if not path or not os.path.exists(path):
            messagebox.showerror("Error", "ไม่พบไฟล์ที่ระบุ")
            return
        
        threading.Thread(target=self._run_logic, args=(path,), daemon=True).start()

    def _run_logic(self, path):
        """ประมวลผลการวิเคราะห์ไฟล์เบื้องหลังแบบเน้นความเสถียร"""
        import time # นำเข้าชั่วคราวเพื่อใช้หน่วงเวลาเล็กน้อย
        
        self.root.after(0, lambda: self.scan_btn.config(state="disabled", bg="#6272a4"))
        self.root.after(0, lambda: self.status.config(text="PREPARING FILES...", fg="#8be9fd"))
        
        try:
            # 1. จัดการไฟล์ (แตกไฟล์)
            result = self.handler.process(path, password_func=self._ask_password_popup)
            
            if result["status"] == "success":
                files = result["files"]
                for file in files:
                    fname = os.path.basename(file)
                    # อัปเดตสถานะหน้าจอ
                    self.root.after(0, lambda f=fname: self.status.config(text=f"🔬 ANALYZING: {f}"))
                    
                    # ป้องกัน Path ยาวเกินไปบน Windows
                    safe_path = "\\\\?\\" + os.path.abspath(file)
                    
                    try:
                        # 2. ดึงข้อมูล Metadata (จุดที่มักจะใช้เวลานาน)
                        get_pe_metadata(safe_path)
                        
                        # 3. สกัด Features (จุดที่มักจะค้างหากไฟล์มีขนาดใหญ่)
                        vector = get_feature_vector(safe_path)
                        
                        if vector is not None:
                            # 4. ทำนายผลด้วย AI
                            analysis = self.classifier.predict_risk(vector)
                            
                            # แสดง Popup ผลลัพธ์
                            self.root.after(100, lambda f=file, r=analysis["final_score"]*100, a=analysis: 
                                           self._handle_result(f, r, path, a["details"]))
                        else:
                            print(f"[ERROR] Could not extract features from {fname}")
                            
                    except Exception as inner_e:
                        print(f"[CRITICAL ERROR] during scanning {fname}: {inner_e}")
                        continue # ข้ามไฟล์ที่พังไปทำไฟล์ถัดไป
                    
                    # หน่วงเวลาเล็กน้อยเพื่อให้ UI ระบบอัปเดตทัน (ป้องกันอาการ Not Responding)
                    time.sleep(0.5) 
                    self.root.after(0, lambda: self.progress.step(100/len(files)))
            else:
                self.root.after(0, lambda m=result["message"]: messagebox.showerror("Scan Error", m))
                
        except Exception as e:
            self.root.after(0, lambda msg=str(e): messagebox.showerror("System Error", f"เกิดข้อผิดพลาดร้ายแรง: {msg}"))
        
        finally:
            # ไม่ว่าจะสำเร็จหรือพัง ต้องคืนสถานะปุ่มกดเสมอ
            self.root.after(500, self._reset_ui)

    def _reset_ui(self):
        self.status.config(text="SYSTEM READY", fg=COLORS["accent_success"])
        self.scan_btn.config(state="normal", bg=COLORS["accent_primary"])
        self.progress["value"] = 0

    def _handle_result(self, file_path, risk, original_path, details=None):
        fname = os.path.basename(file_path)
        ai_details_msg = (f"\n--------------------------------------------\n"
                          f"📊 AI DETAILS:\n"
                          f"• LightGBM: {details['lgbm']*100:.2f}%\n"
                          f"• Random Forest: {details['rf']*100:.2f}%\n"
                          f"• Extra Trees: {details['et']*100:.2f}%")
        
        if risk > 70:
            malware_type = "Potential Ransomware / Trojan" if risk > 90 else "Malicious Executable"
            msg = (f"🚨 THREAT DETECTED: {malware_type}\nFILE: {fname}\nAI CONFIDENCE: {risk:.2f}%" + ai_details_msg)
            show_result_popup(self.root, "🚨 ALERT!", msg, COLORS["accent_primary"])
            
            # รันกระบวนการลบไฟล์
            run_deep_cleanup([file_path], original_input=original_path)
            scan_hidden_persistence()
        elif risk >= 20:
            msg = (f"STATUS: Suspicious Activity\nFILE: {fname}\nRISK: {risk:.2f}%" + ai_details_msg)
            show_result_popup(self.root, "⚠️ WARNING", msg, COLORS["accent_warn"])
        else:
            msg = (f"STATUS: Clean / Safe\nFILE: {fname}\nRISK: {risk:.2f}%\nไฟล์นี้ปลอดภัย" + ai_details_msg)
            show_result_popup(self.root, "✅ SAFE", msg, COLORS["accent_success"])

if __name__ == "__main__":
    root = tk.Tk()
    app = MalwareScannerGUI(root)
    root.mainloop()