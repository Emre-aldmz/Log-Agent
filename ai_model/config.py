"""
AI Model Configuration
Log Gözcüsü - Saldırı Tespit Modeli
"""

# Model Ayarları
MODEL_NAME = "distilbert-base-uncased"
MAX_SEQ_LENGTH = 256
DROPOUT_RATE = 0.3

# Sınıf Etiketleri (8 sınıf)
LABEL_MAP = {
    0: "benign",
    1: "sqli",
    2: "xss",
    3: "path_traversal",
    4: "command_injection",
    5: "bruteforce",
    6: "honeypot_trap",
    7: "other_attack"
}

# Ters mapping
LABEL_TO_ID = {v: k for k, v in LABEL_MAP.items()}

NUM_CLASSES = len(LABEL_MAP)

# Eğitim Ayarları (Colab için)
TRAIN_CONFIG = {
    "batch_size": 32,
    "learning_rate": 2e-5,
    "epochs": 10,
    "warmup_steps": 500,
    "weight_decay": 0.01,
}

# Model dosya yolları
MODEL_WEIGHTS_PATH = "log_classifier.pth"
TOKENIZER_PATH = "tokenizer/"
