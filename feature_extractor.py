import pefile
import os
import datetime
import ember

# ส่วนที่ 1: ดึงข้อมูลโครงสร้าง (ตามที่คุณเขียน)
def get_pe_metadata(file_path):
    try:
        pe = pefile.PE(file_path)
        file_size = os.path.getsize(file_path)
        timedatestamp = pe.FILE_HEADER.TimeDateStamp
        date_created = datetime.datetime.fromtimestamp(timedatestamp)
        
        print(f"📊 --- ข้อมูลพื้นฐาน: {os.path.basename(file_path)} ---")
        print(f"ขนาดไฟล์: {file_size} bytes")
        print(f"วันที่สร้าง (Header): {date_created}")

        print(f"\n📦 จำนวน Sections: {len(pe.sections)}")
        for section in pe.sections:
            name = section.Name.decode().strip('\x00')
            entropy = section.get_entropy()
            print(f" - Section: {name} | Entropy: {entropy:.2f}")

        print("\n🔍 รายชื่อ DLL และ APIs (บางส่วน):")
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT[:3]:
                print(f" - DLL: {entry.dll.decode()}")
                for imp in entry.imports[:2]:
                    print(f"   -> Function: {imp.name.decode() if imp.name else 'Ordinal'}")
        pe.close()
    except Exception as e:
        print(f"❌ เกิดข้อผิดพลาดในการอ่าน PE Header: {e}")

# ส่วนที่ 2: สร้าง Feature Vector เพื่อส่งให้โมเดล
def get_feature_vector(file_path):
    try:
        extractor = ember.PEFeatureExtractor(feature_version=2)
        with open(file_path, "rb") as f:
            file_data = f.read()
            return extractor.feature_vector(file_data)
    except Exception as e:
        print(f"❌ ไม่สามารถสร้าง Vector ได้: {e}")
        return None