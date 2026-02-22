import os
import ember
import multiprocessing
import numpy as np
import joblib
import lightgbm as lgb
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
# หมายเหตุ: หากต้องการใช้ SMOTE-Tomek ต้องติดตั้ง: pip install imbalanced-learn
from imblearn.combine import SMOTETomek 

if __name__ == '__main__':
    multiprocessing.freeze_support()
    
    data_dir = "D:/project/ember2018"
    model_dir = "D:/project/models"
    if not os.path.exists(model_dir):
        os.makedirs(model_dir)

    # --- Step 1: Feature Vectorization ---
    print("🚀 1/3 กำลังเริ่มกระบวนการ Vectorization...")
    ember.create_vectorized_features(data_dir, feature_version=2)
    ember.create_metadata(data_dir)

    # --- Step 2: Model Training (Ensemble Learning Phase) ---
    print("🧠 2/3 เริ่มกระบวนการเรียนรู้โมเดล (Training Phase)...")
    X_train, y_train, X_test, y_test = ember.read_vectorized_features(data_dir, feature_version=2)
    
    # กรองข้อมูลที่ไม่ต้องการ (Unlabeled) ออกก่อนเทรน
    train_rows = (y_train != -1)
    X_train, y_train = X_train[train_rows], y_train[train_rows]

    # ทำ Data Balancing ด้วย SMOTE-Tomek ตามแผนภาพ
    print("⚖️ กำลังปรับสมดุลข้อมูลด้วย SMOTE-Tomek...")
    smt = SMOTETomek(random_state=42)
    X_resampled, y_resampled = smt.fit_resample(X_train, y_train)

    # --- ฝึกฝน 3 โมเดลย่อยสำหรับ Ensemble Voting ---
    
    # 1. เทรน Random Forest (วิเคราะห์จากเสียงส่วนใหญ่)
    print("🌲 เทรน Random Forest...")
    rf = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
    rf.fit(X_resampled, y_resampled)
    joblib.dump(rf, os.path.join(model_dir, "random_forest.pkl"))

    # 2. เทรน Extra-Trees (ลดความผิดพลาดจากการสุ่มคุณลักษณะ)
    print("🌳 เทรน Extra-Trees...")
    et = ExtraTreesClassifier(n_estimators=100, n_jobs=-1, random_state=42)
    et.fit(X_resampled, y_resampled)
    joblib.dump(et, os.path.join(model_dir, "extra_trees.pkl"))

    # 3. เทรน LightGBM (วิเคราะห์จุดอ่อนและแก้ไขข้อผิดพลาด)
    print("💡 เทรน LightGBM...")
    lgbm_params = {"objective": "binary", "metric": "auc", "verbosity": -1}
    dtrain = lgb.Dataset(X_resampled, label=y_resampled)
    lgbm_model = lgb.train(lgbm_params, dtrain, num_boost_round=100)
    lgbm_model.save_model(os.path.join(model_dir, "lgbm_model.txt"))

    print(f"✅ เสร็จสมบูรณ์! โมเดลทั้งหมดถูกเก็บไว้ที่: {model_dir}")