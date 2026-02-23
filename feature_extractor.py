import pefile
import os
import datetime
import ember
import string

def is_printable(s):
    """ตรวจสอบว่าข้อความประกอบด้วยตัวอักษรที่อ่านออกได้เท่านั้น"""
    printable = set(string.printable)
    return all(c in printable for c in s)

def get_pe_metadata(file_path):
    try:
        pe = pefile.PE(file_path)
        file_size = os.path.getsize(file_path)
        
        # จัดการเรื่องเวลา (Header TimeDateStamp)
        timedatestamp = pe.FILE_HEADER.TimeDateStamp
        try:
            date_created = datetime.datetime.fromtimestamp(timedatestamp)
        except:
            date_created = "Invalid Date (Potential Timestomping Detected)"

        print(f"📊 --- ข้อมูลพื้นฐาน: {os.path.basename(file_path)} ---")
        print(f"ขนาดไฟล์: {file_size} bytes")
        print(f"วันที่สร้าง (Header): {date_created}")

        # วิเคราะห์แต่ละ Section (เน้นค่า Entropy เพื่อตรวจจับการเข้ารหัสไฟล์)
        print(f"\n📦 จำนวน Sections: {len(pe.sections)}")
        for section in pe.sections:
            try:
                # ล้างชื่อ Section จากอักขระขยะ (Null bytes)
                raw_name = section.Name.decode(errors='ignore').strip('\x00')
                name = raw_name if is_printable(raw_name) else "Unknown"
                
                entropy = section.get_entropy()
                print(f" - Section: {name:8} | Entropy: {entropy:.2f}")
            except:
                continue

        # วิเคราะห์การนำเข้า DLL (Imports) อย่างปลอดภัย
        print("\n🔍 รายชื่อ DLL และ APIs (ตรวจสอบเบื้องต้น):")
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT[:5]: # ตรวจสอบ 5 DLL แรก
                try:
                    dll_name = entry.dll.decode(errors='ignore')
                    if is_printable(dll_name):
                        print(f" - DLL: {dll_name}")
                        for imp in entry.imports[:3]: # ตรวจสอบ 3 Function แรก
                            if imp.name:
                                func_name = imp.name.decode(errors='ignore')
                                if is_printable(func_name):
                                    print(f"   -> Function: {func_name}")
                except:
                    continue

        # จัดการส่วน Export (เพื่อป้องกันการแสดงอักขระขยะจากเทคนิค Obfuscation)
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            print("\n📋 รายชื่อ Exports:")
            try:
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols[:3]:
                    if exp.name:
                        exp_name = exp.name.decode(errors='ignore')
                        if is_printable(exp_name):
                            print(f"   -> Export: {exp_name}")
            except:
                print("   ⚠️ ไม่สามารถอ่าน Export Name ได้ (Potential Obfuscation)")

        pe.close()
    except Exception as e:
        print(f"❌ เกิดข้อผิดพลาดในการอ่าน PE Header: {e}")

def get_feature_vector(file_path):
    """สกัด Feature Vector ขนาด 2,381 มิติ เพื่อส่งให้โมเดล AI"""
    try:
        extractor = ember.PEFeatureExtractor(feature_version=2)
        with open(file_path, "rb") as f:
            file_data = f.read()
            return extractor.feature_vector(file_data)
    except Exception as e:
        print(f"❌ ไม่สามารถสร้าง Vector ได้: {e}")
        return None