import lightgbm as lgb
import joblib
import numpy as np

# เพิ่ม 3 บรรทัดนี้เพื่อแก้ปัญหาในไฟล์ .exe
try:
    import sklearn.ensemble._forest
    import sklearn.ensemble._etree
    import sklearn.tree._tree
except ImportError:
    pass

class EnsembleClassifier:
    def __init__(self, model_paths):
        """โหลดโมเดล LGBM, RF, และ ET เข้าสู่ระบบ"""
        print("🤖 กำลังโหลด Ensemble Models...")
        self.lgbm_model = lgb.Booster(model_file=model_paths['lgbm'])
        self.rf_model = joblib.load(model_paths['rf'])
        self.et_model = joblib.load(model_paths['et'])

    def predict_risk(self, vector):
        """คำนวณ Final Confidence Score"""
        features = np.array([vector], dtype=np.float32)

        # ทำนายผลจากทั้ง 3 โมเดล
        prob_lgbm = self.lgbm_model.predict(features)[0]
        prob_rf = self.rf_model.predict_proba(features)[0][1]
        prob_et = self.et_model.predict_proba(features)[0][1]

        # หาค่าเฉลี่ย (Soft Voting)
        final_score = (prob_lgbm + prob_rf + prob_et) / 3
        
        return {
            "final_score": final_score,
            "details": {"lgbm": prob_lgbm, "rf": prob_rf, "et": prob_et}
        }
    