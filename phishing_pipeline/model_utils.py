import joblib
from .config import *
import sys, asyncio
if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
 

def load_models_and_preproc():
    model_label = joblib.load(MODEL_LABEL_PATH)
    model_source = joblib.load(MODEL_SOURCE_PATH)
    le_label = joblib.load(ENCODER_LABEL_PATH)
    source_classes = joblib.load(SOURCE_CLASSES_PATH)
    feature_columns = joblib.load(FEATURE_COLUMNS_PATH)
    scaler = joblib.load(SCALER_PATH)
    imputer = joblib.load(IMPUTER_PATH)
    return model_label, model_source, le_label, source_classes, feature_columns, scaler, imputer
