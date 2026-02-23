import os
import shutil
import pyzipper
import hashlib

class InputHandler:
    def __init__(self, temp_dir="D:/project/temp_extraction"):
        self.temp_dir = os.path.abspath(temp_dir)
        os.makedirs(self.temp_dir, exist_ok=True)

    # ---------------- SHA256 ----------------
    def sha256(self, path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    # ---------------- SAFE CLEAN ----------------
    def clean_temp(self):
        for name in os.listdir(self.temp_dir):
            path = os.path.abspath(os.path.join(self.temp_dir, name))
            if not path.startswith(self.temp_dir):
                continue
            try:
                if os.path.isfile(path) or os.path.islink(path):
                    os.unlink(path)
                else:
                    shutil.rmtree(path)
            except Exception as e:
                print("[WARN] Cleanup error:", e)

    # ---------------- ZIP SLIP SAFE ----------------
    def safe_extract(self, zip_ref):
        for member in zip_ref.namelist():
            dest = os.path.abspath(os.path.join(self.temp_dir, member))
            if not dest.startswith(self.temp_dir):
                raise Exception("ZIP SLIP ATTACK DETECTED")
        zip_ref.extractall(self.temp_dir)

    # ---------------- MAIN PROCESS ----------------
  # ---------------- MAIN PROCESS (ส่วนที่ต้องเติม) ----------------
    def process(self, file_path, password_func=None):
        if not os.path.exists(file_path):
            return {"status": "error", "message": "File not found"}

        self.clean_temp()
        result = {"encrypted": False, "files": [], "hash": self.sha256(file_path)}

        if file_path.lower().endswith(".zip"):
            try:
                with pyzipper.AESZipFile(file_path) as z:
                    # --- ขั้นตอนที่ 1: เช็คก่อนว่ามีการเข้ารหัสจริงไหม ---
                    is_encrypted = any(item.flag_bits & 0x1 for item in z.infolist())
                    result["encrypted"] = is_encrypted

                    if is_encrypted:
                        # ถ้ามีรหัส ให้เรียกถามผ่าน GUI
                        if password_func:
                            pwd = password_func()
                            if not pwd: return {"status": "error", "message": "ต้องระบุรหัสผ่าน"}
                            z.pwd = pwd.encode()
                        else:
                            return {"status": "error", "message": "ไฟล์นี้มีการป้องกันด้วยรหัสผ่าน"}

                    # --- ขั้นตอนที่ 2: ทดสอบรหัสผ่านก่อนแตกไฟล์จริง ---
                    try:
                        z.testzip() # จะ Error ทันทีถ้ารหัสผิด
                    except RuntimeError:
                        return {"status": "error", "message": "รหัสผ่านไม่ถูกต้อง"}

                    self.safe_extract(z)

                # ค้นหาไฟล์ .exe หลังแตกเสร็จ
                exes = [os.path.join(r, f) for r, _, fs in os.walk(self.temp_dir) for f in fs if f.lower().endswith(".exe")]
                if not exes: return {"status": "error", "message": "ไม่พบไฟล์ .exe ใน ZIP"}
                
                return {"status": "success", "files": exes, "hash": result["hash"]}

            except Exception as e:
                return {"status": "error", "message": f"ZIP Error: {str(e)}"}
        
        elif file_path.lower().endswith(".exe"):
            return {"status": "success", "files": [file_path], "hash": result["hash"]}

        return {"status": "error", "message": "ไม่รองรับไฟล์ประเภทนี้"}