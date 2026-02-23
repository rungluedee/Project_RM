import os
import psutil
import time
import shutil

class AdaptiveMonitor:
    def __init__(self, target_pid, extracted_file_path, original_source_path=None):
        self.pid = target_pid
        self.file_path = extracted_file_path  # ไฟล์ใน temp_extraction
        self.source_path = original_source_path  # ไฟล์ต้นฉบับใน Downloads
        self.is_active = True
        self.trap_path = "D:/project/canary_trap"
        self.canary_file = os.path.join(self.trap_path, "important_data.txt")
        self._setup_canary()

    def _setup_canary(self):
        """สร้างไฟล์ล่อ (Canary Trap) เพื่อดักจับพฤติกรรมการเขียนไฟล์"""
        if not os.path.exists(self.trap_path):
            os.makedirs(self.trap_path)
        with open(self.canary_file, "w") as f:
            f.write("SYSTEM_PROTECTED_DATA")
        self.initial_mtime = os.path.getmtime(self.canary_file)

    def start_monitoring(self):
        print(f"🕵️ เริ่มต้นเฝ้าระวัง PID: {self.pid}")
        try:
            process = psutil.Process(self.pid)
            while self.is_active and process.is_running():
                # ตรวจจับถ้าไฟล์ล่อถูกแก้ไข
                if os.path.getmtime(self.canary_file) != self.initial_mtime:
                    print("🚨 ALERT: Canary Trap Triggered! มัลแวร์พยายามแก้ไขข้อมูล")
                    self.execute_response(process)
                    break
                time.sleep(1)
        except psutil.NoSuchProcess:
            print("🏁 Process จบการทำงาน (หรือมัลแวร์พยายามซ่อนตัว)")

    def execute_response(self, process):
        """กลไกการกวาดล้างแบบถอนรากถอนโคน (Perfect Response)"""
        try:
            print(f"🚫 ตรวจพบพฤติกรรมอันตราย! กำลังตัดวงจรการทำงาน...")

            # 1. เปลี่ยนชื่อไฟล์ต้นตอทันที (Quarantine) - มัลแวร์จะ Re-spawn ไม่ได้เพราะหาไฟล์ไม่เจอ
            targets = [self.file_path]
            if self.source_path:
                targets.append(self.source_path)
            
            renamed_targets = []
            for path in targets:
                if os.path.exists(path):
                    try:
                        new_path = path + f".{int(time.time())}.locked"
                        os.rename(path, new_path)
                        renamed_targets.append(new_path)
                    except OSError:
                        renamed_targets.append(path)

            # 2. บังคับปิดกระบวนการ (Force Kill) ทุกตัวที่มีชื่อเดียวกัน
            filename = os.path.basename(self.file_path)
            os.system(f"taskkill /F /IM {filename} /T >nul 2>&1")
            os.system(f"taskkill /F /PID {self.pid} /T >nul 2>&1")

            # 3. วนลูปลบไฟล์ที่ถูกล็อก (Retry Loop)
            for i in range(15):
                remaining = []
                time.sleep(1.5)
                for path in renamed_targets:
                    if os.path.exists(path):
                        try:
                            os.chmod(path, 0o777) # ปลดล็อกสิทธิ์ไฟล์
                            os.remove(path)
                            print(f"🗑️ กำจัดสำเร็จ: {os.path.basename(path)}")
                        except OSError:
                            remaining.append(path)
                
                renamed_targets = remaining
                if not renamed_targets:
                    print(f"✅ [SUCCESS] กวาดล้างภัยคุกคามและหยุดการ Re-spawn สำเร็จ!")
                    break
                print(f"🔄 รอบที่ {i+1}: รอระบบคลายล็อกไฟล์...")

        except Exception as e:
            print(f"❌ การตอบสนองล้มเหลว: {e}")