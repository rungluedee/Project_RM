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
    """สกัดข้อมูล PE Header และส่งกลับเป็น Dictionary เพื่อแสดงใน GUI"""
    # เตรียมโครงสร้างข้อมูลเริ่มต้น
    metadata = {
        "file_name": os.path.basename(file_path),
        "file_size": os.path.getsize(file_path),
        "date_created": "Unknown",
        "sections": [],
        "imports": [],
        "exports": [],
        "error": None
    }
    
    try:
        # ใช้ fast_load=True เพื่อความรวดเร็ว
        pe = pefile.PE(file_path, fast_load=True)
        
        # 1. จัดการเรื่องเวลา (Header TimeDateStamp)
        timedatestamp = pe.FILE_HEADER.TimeDateStamp
        try:
            dt = datetime.datetime.fromtimestamp(timedatestamp)
            metadata["date_created"] = dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            metadata["date_created"] = "Invalid Date (Potential Timestomping)"

        # 2. วิเคราะห์ Sections
        for section in pe.sections:
            try:
                raw_name = section.Name.decode(errors='ignore').strip('\x00')
                name = raw_name if is_printable(raw_name) else "Unknown"
                entropy = section.get_entropy()
                metadata["sections"].append({"name": name, "entropy": entropy})
            except:
                continue

        # 3. วิเคราะห์ DLL และ APIs (Imports)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT[:5]: # ตรวจสอบ 5 DLL แรก
                try:
                    dll_name = entry.dll.decode(errors='ignore')
                    if is_printable(dll_name):
                        funcs = []
                        for imp in entry.imports[:3]: # ตรวจสอบ 3 Function แรก
                            if imp.name:
                                f_name = imp.name.decode(errors='ignore')
                                if is_printable(f_name):
                                    funcs.append(f_name)
                        metadata["imports"].append({"dll": dll_name, "functions": funcs})
                except:
                    continue

        # 4. วิเคราะห์ Exports
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            try:
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols[:3]:
                    if exp.name:
                        exp_name = exp.name.decode(errors='ignore')
                        if is_printable(exp_name):
                            metadata["exports"].append(exp_name)
            except:
                pass

        pe.close()
        
    except Exception as e:
        metadata["error"] = str(e)
        print(f"❌ เกิดข้อผิดพลาดในการอ่าน PE Header: {e}")

    # --- ส่วนสำคัญ: ต้องส่งข้อมูลกลับไปให้ main_gui.py ---
    return metadata

def get_feature_vector(file_path):
    """สกัด Feature Vector ขนาด 2,381 มิติ เพื่อส่งให้โมเดล AI"""
    try:
        # กำหนดเวอร์ชันให้ตรงกับที่ใช้เทรน (Ember 2018 ใช้ version 2)
        extractor = ember.PEFeatureExtractor(feature_version=2)
        with open(file_path, "rb") as f:
            file_data = f.read()
            return extractor.feature_vector(file_data)
    except Exception as e:
        print(f"❌ ไม่สามารถสร้าง Vector ได้: {e}")
        return None