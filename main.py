import os
import subprocess
from core.input_files_path import InputHandler
from core.feature_extractor import get_pe_metadata, get_feature_vector
from core.ensemble_classifier import EnsembleClassifier
from core.adaptive_monitor import AdaptiveMonitor
from core.malware_cleaner import run_deep_cleanup

MODELS_CONFIG = {
    'lgbm': "D:/project/ember2018/ember_model_2018.txt",
    'rf': "D:/project/models/random_forest.pkl",
    'et': "D:/project/models/extra_trees.pkl"
}

def ask_password_cli():
    """ฟังก์ชันถามรหัสผ่านผ่าน Terminal"""
    print("\n🔐 [PROTECTED] ไฟล์ ZIP นี้มีการป้องกันด้วยรหัสผ่าน")
    pwd = input("🔑 กรุณาใส่รหัสผ่านเพื่อแตกไฟล์ (หรือกด Enter เพื่อข้าม): ").strip()
    return pwd if pwd else None

def main():
    print("\n🚀 SHIELD AI | ระบบตรวจจับและกวาดล้างมัลแวร์ (CLI VERSION)")
    print("="*60)
    
    try:
        classifier = EnsembleClassifier(MODELS_CONFIG)
        handler = InputHandler()
    except Exception as e:
        print(f"❌ โหลดโมเดลล้มเหลว: {e}")
        return

    path_input = input("\nกรุณาใส่ Path ไฟล์ที่ต้องการตรวจสอบ: ").strip().replace('"', '')
    
    if not path_input: return

    # --- จุดที่แก้ไข: เพิ่ม password_func เข้าไป ---
    print(f"📁 กำลังเตรียมจัดการไฟล์: {os.path.basename(path_input)}...")
    result = handler.process(path_input, password_func=ask_password_cli)

    if result.get("status") == "success":
        is_malicious = False
        malware_type = "None"
        
        for file in result["files"]:
            print(f"\n" + "="*60)
            print(f"🔬 กำลังวิเคราะห์: {os.path.basename(file)}")
            
            get_pe_metadata(file)
            vector = get_feature_vector(file)
            
            if vector is not None:
                analysis = classifier.predict_risk(vector)
                risk_percent = analysis["final_score"] * 100
                
                print(f"\n📊 คะแนน AI Confidence: {risk_percent:.2f}%")
                
                if risk_percent > 80:
                    print("❌ สถานะ: [Danger Zone] อันตราย")
                    is_malicious = True
                    malware_type = "High-Risk Executable"
                
                elif 20 <= risk_percent <= 80:
                    print(f"⚠️ สถานะ: [Grey Zone] กลุ่มเสี่ยง")
                    try:
                        proc = subprocess.Popen([file])
                        monitor = AdaptiveMonitor(proc.pid, file, original_source_path=path_input)
                        if monitor.start_monitoring():
                            malware_type = monitor.classify_behavior(proc)
                            is_malicious = True 
                    except Exception as e:
                        print(f"❌ บล็อกการรัน: {e}")
                        is_malicious = True 
                else:
                    print("✅ สถานะ: [Safe Zone] ปกติ")

        if is_malicious:
            print("\n🧹 เริ่มขั้นตอนการกวาดล้าง...")
            run_deep_cleanup(result["files"], original_input=path_input)
            print(f"🏁 สรุปผล: กำจัด [{malware_type}] เรียบร้อยแล้ว")
            
    else:
        print(f"❌ การเตรียมไฟล์ล้มเหลว: {result.get('message')}")

if __name__ == "__main__":
    main()
    input("\nกด Enter เพื่อปิดหน้าต่าง...")