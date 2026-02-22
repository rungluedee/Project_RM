import os
import shutil
import pyzipper  # ต้องติดตั้งเพิ่มด้วยคำสั่ง: pip install pyzipper

class InputHandler:
    def __init__(self, temp_dir="D:/project/temp_extraction"):
        """
        กำหนดโฟลเดอร์สำหรับแตกไฟล์ชั่วคราว (Input Layer)
        """
        self.temp_dir = temp_dir
        if not os.path.exists(self.temp_dir):
            os.makedirs(self.temp_dir)

    def clean_temp(self):
        """
        ล้างไฟล์เก่าทิ้งเพื่อป้องกันการปนเปื้อนของข้อมูล (Data Integrity)
        """
        for filename in os.listdir(self.temp_dir):
            file_path = os.path.join(self.temp_dir, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                print(f'❌ ไม่สามารถล้างไฟล์เก่าได้: {e}')

    def process(self, file_path):
        if not os.path.exists(file_path):
            return {"status": "error", "message": "ไม่พบ Path ที่ระบุ"}

        self.clean_temp()
        
        if file_path.lower().endswith('.zip'):
            print(f"📦 ตรวจพบไฟล์ ZIP: {os.path.basename(file_path)}")
            try:
                # ใช้ AESZipFile เพื่อรองรับการบีบอัดและรหัสผ่านทุกรูปแบบ
                with pyzipper.AESZipFile(file_path, 'r') as zip_ref:
                    try:
                        # พยายามแตกไฟล์โดยตรงก่อน (กรณีไม่มีรหัสผ่าน)
                        zip_ref.extractall(self.temp_dir)
                    except Exception:
                        # หากติดรหัสผ่าน ระบบจะเข้าสู่ส่วนนี้
                        print("🔑 ไฟล์นี้ถูกเข้ารหัสหรือต้องใช้รหัสผ่าน")
                        password = input("กรุณาใส่รหัสผ่าน (เช่น infected): ")
                        # กำหนดรหัสผ่านให้กับ zip_ref โดยตรงในรูปแบบ bytes
                        zip_ref.pwd = bytes(password, 'utf-8')
                        zip_ref.extractall(self.temp_dir)
                
                # ค้นหาไฟล์ .exe หลังแตกไฟล์สำเร็จ
                extracted_exes = []
                for root, dirs, files in os.walk(self.temp_dir):
                    for f in files:
                        if f.lower().endswith('.exe'):
                            extracted_exes.append(os.path.join(root, f))
                
                if not extracted_exes:
                    return {"status": "error", "message": "ไม่พบไฟล์ .exe ใน ZIP"}
                return {"status": "success", "type": "zip", "files": extracted_exes}
                
            except Exception as e:
                return {"status": "error", "message": f"การแตกไฟล์ล้มเหลว: {e}"}
# ส่วนการทดสอบการทำงานเบื้องต้น
if __name__ == "__main__":
    handler = InputHandler()
    print("\n" + "="*60)
    print("🛡️ ระบบตรวจจับมัลแวร์: ส่วนจัดการไฟล์นำเข้า (Full Support)")
    print("="*60)
    user_input = input("กรุณาใส่ Path ของไฟล์ที่ต้องการตรวจสอบ: ").strip('"')
    
    result = handler.process(user_input)
    
    if result["status"] == "success":
        print(f"\n✅ ประมวลผลสำเร็จ ({result['type']})")
        print(f"เตรียมส่งไฟล์เข้าสู่กระบวนการ Static Analysis Engine...")
        for f in result["files"]:
            print(f" ➡️ {f}")
    else:
        print(f"\n❌ เกิดข้อผิดพลาด: {result['message']}")