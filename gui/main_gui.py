import os
import sys
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import threading
import time

# --- จัดการ Path เพื่อให้หาโฟลเดอร์ core เจอ ---
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)

if project_root not in sys.path:
    sys.path.append(project_root)

# นำเข้าการตกแต่งและการแจ้งเตือน
try:
    from ui_styles import COLORS, FONTS, apply_styles, show_result_popup
except ImportError:
    from gui.ui_styles import COLORS, FONTS, apply_styles, show_result_popup

# นำเข้าโมดูลจาก core
from core.input_files_path import InputHandler
from core.feature_extractor import get_feature_vector, get_pe_metadata
from core.ensemble_classifier import EnsembleClassifier
from core.malware_cleaner import run_deep_cleanup, scan_hidden_persistence

# --- การกำหนดค่า Path ของโมเดล AI ---
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
        header = tk.Frame(self.root, bg=COLORS["bg_dark"])
        header.pack(pady=30)
        tk.Label(header, text="🛡️Al Malware Scanner", font=FONTS["header"], bg=COLORS["bg_dark"], fg=COLORS["fg_main"]).pack()
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
        password_val = tk.StringVar()
        def on_submit(event=None):
            password_val.set(entry.get())
            dialog.destroy()

        dialog = tk.Toplevel(self.root)
        dialog.title("🔐 ZIP Password Required")
        dialog.geometry("350x180")
        dialog.configure(bg="#282a36")
        dialog.transient(self.root)
        dialog.grab_set()

        tk.Label(dialog, text="ไฟล์ ZIP นี้ถูกเข้ารหัสไว้", font=("Inter", 10, "bold"), bg="#282a36", fg="#ff79c6").pack(pady=(15, 5))
        entry = tk.Entry(dialog, show="*", font=("Consolas", 12), bg="#44475a", fg="white", relief="flat")
        entry.pack(pady=10, padx=30, fill="x")
        entry.bind("<Return>", on_submit)
        entry.focus_set()

        tk.Button(dialog, text="UNLOCK & SCAN", command=on_submit, bg="#50fa7b", fg="#282a36", font=("Inter", 9, "bold"), relief="flat").pack(pady=10)
        self.root.wait_window(dialog)
        return password_val.get() if password_val.get() else None

    def _start_thread(self):
        if not hasattr(self, 'classifier'): 
            messagebox.showwarning("Warning", "ระบบ AI ยังโหลดไม่เสร็จ")
            return
        path = self.path_var.get().strip().replace('"', '')
        if not path or not os.path.exists(path):
            messagebox.showerror("Error", "ไม่พบไฟล์ที่ระบุ")
            return
        threading.Thread(target=self._run_logic, args=(path,), daemon=True).start()

    def _run_logic(self, path):
        """ประมวลผลหลัก: จัดการไฟล์ -> ดึงข้อมูล -> ทำนาย -> โชว์ผล"""
        self.root.after(0, lambda: self.scan_btn.config(state="disabled", bg="#6272a4"))
        self.root.after(0, lambda: self.status.config(text="📦 PREPARING FILES...", fg="#f1fa8c"))
        
        try:
            # 1. จัดการแตกไฟล์
            result = self.handler.process(path, password_func=self._ask_password_popup)
            
            if result["status"] == "success":
                files = result["files"]
                total = len(files)
                
                for i, file in enumerate(files):
                    fname = os.path.basename(file)
                    self.root.after_idle(lambda f=fname: self.status.config(text=f"🔬 ANALYZING: {f}"))
                    
                    # 2. ดึง Metadata (ต้องปรับฟังก์ชันใน feature_extractor.py ให้ return dict)
                    meta_data = get_pe_metadata(file) 
                    
                    # 3. สกัด Feature Vector
                    safe_path = "\\\\?\\" + os.path.abspath(file)
                    vector = get_feature_vector(safe_path)
                    
                    if vector is not None:
                        # 4. AI Prediction
                        analysis = self.classifier.predict_risk(vector)
                        
                        # ส่งข้อมูลทั้งหมดไปแสดงผล
                        self.root.after(200, lambda f=file, r=analysis["final_score"]*100, a=analysis, m=meta_data: 
                                        self._handle_result_v2(f, r, path, a["details"], m))
                    
                    # คืนลมหายใจให้ GUI (กันค้าง)
                    time.sleep(0.1)
                    self.root.after(0, lambda v=(i+1)*100/total: self.progress.configure(value=v))
            else:
                self.root.after(0, lambda m=result["message"]: messagebox.showerror("Scan Error", m))
                
        except Exception as e:
            self.root.after(0, lambda msg=str(e): messagebox.showerror("System Error", f"Error: {msg}"))
        finally:
            self.root.after(500, self._reset_ui)

    def _reset_ui(self):
        self.status.config(text="SYSTEM READY", fg=COLORS["accent_success"])
        self.scan_btn.config(state="normal", bg=COLORS["accent_primary"])
        self.progress["value"] = 0

    def _handle_result_v2(self, file_path, risk, original_path, details, meta):
        fname = os.path.basename(file_path)
        ext = os.path.splitext(fname)[1].upper() or "Unknown"
        
        # กำหนด Verdict และคำแนะนำตามระดับความเสี่ยง
        if risk > 70:
            verdict = "❌ MALICIOUS (อันตรายมาก)"
            status_desc = "พบพฤติกรรมหรือโครงสร้างที่ตรงกับมัลแวร์"
            advice = "⚠️ ระบบได้ดำเนินการกำจัดไฟล์นี้เพื่อความปลอดภัยของคุณแล้ว"
        elif risk >= 20:
            verdict = "⚠️ SUSPICIOUS (น่าสงสัย)"
            status_desc = "ไฟล์มีคุณลักษณะบางอย่างที่ผิดปกติ"
            advice = "💡 โปรดระมัดระวังในการใช้งาน หรือตรวจสอบแหล่งที่มาอีกครั้ง"
        else:
            verdict = "✅ SAFE (ปลอดภัย)"
            status_desc = "ไม่พบพฤติกรรมที่เป็นอันตรายในฐานข้อมูล AI"
            advice = "✔️ คุณสามารถใช้งานไฟล์นี้ได้ตามปกติ"

        # จัดรูปแบบข้อความใหม่ให้ดูเหมือน Dashboard
        report = []
        report.append(f"🛡️ SHIELD AI VERDICT: {verdict}")
        report.append(f"สถานะ: {status_desc}")
        report.append(f"ประเภทไฟล์: {ext}")
        report.append(f"คำแนะนำ: {advice}")
        report.append("="*45)

        report.append(f"🔎 ANALYSIS SUMMARY")
        report.append(f"Target: {fname}")
        report.append(f"Size  : {meta.get('file_size', 0):,} bytes")
        report.append(f"Date  : {meta.get('date_created', 'Unknown')}")
        report.append("-" * 45)

        # AI Scoring Section
        report.append(f"🤖 AI ENSEMBLE ENGINE SCORES")
        report.append(f"Overall Risk Score: {risk:.2f}%")
        report.append(f" • LightGBM Model   : {details['lgbm']*100:.2f}%")
        report.append(f" • Random Forest     : {details['rf']*100:.2f}%")
        report.append(f" • Extra Trees       : {details['et']*100:.2f}%")
        report.append("-" * 45)

        # Technical Sections (Sections & Entropy)
        if meta.get('sections'):
            report.append(f"📦 PE SECTIONS (ENTROPY)")
            for sec in meta['sections']:
                name = (sec['name'] + " " * 8)[:8]
                indicator = "🚩" if sec['entropy'] > 7.2 else "✅"
                report.append(f" {indicator} {name} : {sec['entropy']:.2f}")
            report.append("-" * 45)

        # API/DLL Section
        if meta.get('imports'):
            report.append(f"🧪 IMPORTED LIBRARIES (DLLs)")
            for imp in meta['imports'][:5]: # แสดงสูงสุด 5 ตัวแรก
                report.append(f" • {imp['dll']}")
                if imp.get('functions'):
                    report.append(f"   └─ {', '.join(imp['functions'][:3])}...")
            report.append("=" * 45)

        full_msg = "\n".join(report)

        # เรียกใช้ Popup ตามสีความเสี่ยง
        if risk > 70:
            show_result_popup(self.root, "MALICIOUS", full_msg, COLORS["accent_primary"])
            run_deep_cleanup([file_path], original_input=original_path)
            scan_hidden_persistence()
        elif risk >= 20:
            show_result_popup(self.root, "SUSPICIOUS", full_msg, COLORS["accent_warn"])
        else:
            show_result_popup(self.root, "SAFE", full_msg, COLORS["accent_success"])

if __name__ == "__main__":
    root = tk.Tk()
    app = MalwareScannerGUI(root)
    root.mainloop()