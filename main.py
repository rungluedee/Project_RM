import os
import time
import subprocess
from input_files_path import InputHandler
from feature_extractor import get_pe_metadata, get_feature_vector
from ensemble_classifier import EnsembleClassifier
from adaptive_monitor import AdaptiveMonitor
from malware_cleaner import run_deep_cleanup # นำเข้าโมดูลทำความสะอาด

# --- เริ่มการทำงานของระบบ ---
MODELS_CONFIG = {
    'lgbm': "D:/project/ember2018/ember_model_2018.txt",
    'rf': "D:/project/models/random_forest.pkl",
    'et': "D:/project/models/extra_trees.pkl"
}

print("🚀 ระบบตรวจจับและกวาดล้างมัลแวร์สมบูรณ์แบบ (Ensemble System) พร้อมทำงาน...")
classifier = EnsembleClassifier(MODELS_CONFIG)
handler = InputHandler()

path_input = input("\nกรุณาใส่ Path ไฟล์ที่ต้องการตรวจสอบ: ").strip('"')
result = handler.process(path_input)

if result["status"] == "success":
    is_malicious = False
    
    for file in result["files"]:
        print(f"\n" + "="*60)
        get_pe_metadata(file) # Phase 2
        vector = get_feature_vector(file)
        
        if vector is not None:
            # Phase 3: Classification
            analysis = classifier.predict_risk(vector)
            risk_percent = analysis["final_score"] * 100
            print(f"\n🎯 ค่าความเชื่อมั่นรวม (AI Confidence): {risk_percent:.2f}%")
            
            # --- DECISION GATE ---
            if risk_percent > 80:
                print("❌ สถานะ: [Danger Zone] อันตราย -> สั่งกวาดล้างทันที")
                is_malicious = True
            
            elif 20 <= risk_percent <= 80:
                print(f"⚠️ สถานะ: [Grey Zone] กลุ่มเสี่ยง ({risk_percent:.2f}%)")
                try:
                    # ส่วนที่ 1: เปิดใช้งานและติดตามพฤติกรรม
                    print(f"กำลังเปิดใช้งานไฟล์เพื่อติดตาม PID และพฤติกรรม...")
                    proc = subprocess.Popen([file]) 
                    
                    # ส่วนที่ 2: เฝ้าระวัง Canary Trap
                    print(f"🕵️ ติดตาม PID: {proc.pid} ... หากมีการบุกรุกระบบจะกวาดล้างทันที!")
                    monitor = AdaptiveMonitor(proc.pid, file, original_source_path=path_input)
                    should_delete = monitor.start_monitoring() 
                    
                    if should_delete:
                        print(f"🚫 [TRIGGER] ตรวจพบพฤติกรรมอันตราย! สั่งกวาดล้างระบบ...")
                    
                    # บังคับกวาดล้างใน Gray Zone เพื่อไม่ให้เหลือร่องรอยการติดตั้ง
                    is_malicious = True 
                        
                except Exception as e:
                    print(f"❌ ระบบถูกบล็อกการรัน (Access Denied): {e} -> สั่งลบทิ้งทันที")
                    is_malicious = True 
            else:
                print("✅ สถานะ: [Safe Zone] ปกติ")

    # ขั้นตอนสุดท้าย: กวาดล้างมัลแวร์และร่องรอยการติดตั้ง
    if is_malicious:
        run_deep_cleanup(result["files"], original_input=path_input)

else:
    print(f"\n❌ ข้อผิดพลาด: {result['message']}")