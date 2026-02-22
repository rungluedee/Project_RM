import os
import numpy as np
from input_files_path import InputHandler
from feature_extractor import get_pe_metadata, get_feature_vector
from ensemble_classifier import EnsembleClassifier # นำเข้า Classifier ที่แยกออกมา

def secure_delete(file_list, original_zip=None):
    """ฟังก์ชันลบไฟล์มัลแวร์ในทุกจุดที่เกี่ยวข้องตามขั้นตอน Output & Response"""
    # 1. ลบไฟล์ EXE ทั้งหมดที่แตกออกมาในโฟลเดอร์ชั่วคราว
    for file_path in file_list:
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"🗑️ ลบไฟล์มัลแวร์สำเร็จ: {os.path.basename(file_path)}")
        except Exception as e:
            print(f"❌ ไม่สามารถลบไฟล์ EXE ได้: {e}")

    # 2. ลบไฟล์ ZIP ต้นฉบับ (ลบออกทุก Path ตามนโยบายความปลอดภัย)
    if original_zip and os.path.exists(original_zip):
        try:
            os.remove(original_zip)
            print(f"💣 ลบไฟล์ ZIP ต้นฉบับสำเร็จ: {os.path.basename(original_zip)}")
        except Exception as e:
            print(f"❌ ไม่สามารถลบไฟล์ต้นฉบับได้: {e}")

# --- ส่วนหลักของระบบ ---

# 1. กำหนด Path สำหรับโมเดลทั้ง 3 ตัว (Ensemble Voting)
MODELS_CONFIG = {
    'lgbm': "D:/project/ember2018/ember_model_2018.txt", # ตัวแทน XGBoost
    'rf': "D:/project/models/random_forest.pkl",        # Random Forest
    'et': "D:/project/models/extra_trees.pkl"           # Extra-Trees
}

print("🚀 กำลังเตรียมระบบตรวจจับมัลแวร์ (Ensemble Voting System)...")
classifier = EnsembleClassifier(MODELS_CONFIG) # โหลดโมเดลย่อยทั้ง 3
handler = InputHandler()

path_input = input("\nกรุณาใส่ Path ของไฟล์ที่ต้องการตรวจสอบ: ").strip('"')
result = handler.process(path_input) # ขั้นตอน Input Layer

if result["status"] == "success":
    is_malicious = False
    
    for file in result["files"]:
        print(f"\n" + "="*60)
        # ขั้นตอน Static Analysis Engine
        get_pe_metadata(file) 
        
        # สกัด Feature Vector 2,381 มิติ
        vector = get_feature_vector(file)
        
        if vector is not None:
            # เข้าสู่กระบวนการ Decision Gate (Soft Voting)
            analysis = classifier.predict_risk(vector)
            risk_score = analysis["final_score"]
            
            print(f"\n🎯 Final Confidence Score (Average): {risk_score:.4f}")
            print(f"📊 รายละเอียดการโหวต: LGBM={analysis['details']['lgbm']:.2f}, "
                  f"RF={analysis['details']['rf']:.2f}, ET={analysis['details']['et']:.2f}")
            
            # การตัดสินใจตามเกณฑ์ Thresholds
            if risk_score > 0.8:
                print("❌ สถานะ: อันตราย (Malicious) [Danger Zone]")
                is_malicious = True
            elif 0.2 <= risk_score <= 0.8:
                print("⚠️ สถานะ: เฝ้าระวัง (Gray Zone) [Adaptive Monitoring]")
            else:
                print("✅ สถานะ: ปลอดภัย (Safe Zone)")
        print("="*60)

    # หากตรวจพบไฟล์อันตราย ให้ทำการบล็อกและลบทิ้งทันทีทุก Path
    if is_malicious:
        original_source = path_input if path_input.lower().endswith('.zip') else None
        secure_delete(result["files"], original_zip=original_source)

else:
    print(f"\n❌ เกิดข้อผิดพลาด: {result['message']}")