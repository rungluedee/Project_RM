import os
import subprocess
from core.input_files_path import InputHandler
from core.feature_extractor import get_pe_metadata, get_feature_vector
from core.ensemble_classifier import EnsembleClassifier
from core.adaptive_monitor import AdaptiveMonitor
from core.malware_cleaner import run_deep_cleanup

# การตั้งค่า Path ของโมเดล
MODELS_CONFIG = {
    'lgbm': "D:/project/ember2018/ember_model_2018.txt",
    'rf': "D:/project/models/random_forest.pkl",
    'et': "D:/project/models/extra_trees.pkl"
}

def main():
    print("🚀 ระบบตรวจจับและกวาดล้างมัลแวร์สมบูรณ์แบบ (Ensemble System) พร้อมทำงาน...")
    classifier = EnsembleClassifier(MODELS_CONFIG)
    handler = InputHandler()

    path_input = input("\nกรุณาใส่ Path ไฟล์ที่ต้องการตรวจสอบ: ").strip('"')
    result = handler.process(path_input)

    if result["status"] == "success":
        is_malicious = False
        malware_type = "None"
        
        for file in result["files"]:
            print(f"\n" + "="*60)
            get_pe_metadata(file) # Phase 2: Metadata Extraction
            vector = get_feature_vector(file) # Phase 2: Vectorization
            
            if vector is not None:
                # Phase 3: Classification
                analysis = classifier.predict_risk(vector)
                risk_percent = analysis["final_score"] * 100
                
                # แสดงคะแนนแยกแต่ละโมเดลตามความต้องการ
                print(f"\n📊 รายละเอียดคะแนนจาก AI Models:")
                print(f"   - LightGBM: {analysis['details']['lgbm']*100:.2f}%")
                print(f"   - Random Forest: {analysis['details']['rf']*100:.2f}%")
                print(f"   - Extra Trees: {analysis['details']['et']*100:.2f}%")
                print(f"🎯 ค่าความเชื่อมั่นรวม (AI Confidence): {risk_percent:.2f}%")
                
                # --- DECISION GATE ---
                if risk_percent > 70:
                    print("❌ สถานะ: [Danger Zone] อันตราย -> สั่งกวาดล้างทันที")
                    is_malicious = True
                    malware_type = "High-Risk Executable"
                
                elif 20 <= risk_percent <= 70:
                    print(f"⚠️ สถานะ: [Grey Zone] กลุ่มเสี่ยง ({risk_percent:.2f}%)")
                    try:
                        print(f"กำลังเปิดใช้งานไฟล์เพื่อติดตาม PID และพฤติกรรม...")
                        proc = subprocess.Popen([file]) 
                        
                        # Phase 4: Adaptive Monitoring
                        monitor = AdaptiveMonitor(proc.pid, file, original_source_path=path_input)
                        should_delete = monitor.start_monitoring() 
                        
                        if should_delete:
                            # ระบุประเภทมัลแวร์จากพฤติกรรม
                            malware_type = monitor.classify_behavior(proc)
                            print(f"🚫 [TRIGGER] ตรวจพบพฤติกรรมอันตราย: {malware_type}")
                            is_malicious = True 
                    except Exception as e:
                        print(f"❌ ระบบถูกบล็อกการรัน: {e}")
                        is_malicious = True 
                else:
                    print("✅ สถานะ: [Safe Zone] ปกติ")

        # ขั้นตอนสุดท้าย: การกวาดล้างลึก
        if is_malicious:
            run_deep_cleanup(result["files"], original_input=path_input)
            print(f"\n🏁 สรุปผล: กำจัดมัลแวร์ประเภท [{malware_type}] และร่องรอยเรียบร้อยแล้ว")

if __name__ == "__main__":
    main()