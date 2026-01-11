"""
Inference Module
Yerel model ile log analizi
"""

from pathlib import Path
from typing import Dict, Any, Optional
import torch

from .config import LABEL_MAP, MAX_SEQ_LENGTH, MODEL_WEIGHTS_PATH
from .model import LogClassifier, load_model, get_tokenizer, TRANSFORMERS_AVAILABLE


class LogAnalyzer:
    """
    Log satırlarını analiz eden sınıf.
    API yerine yerel model kullanır.
    """
    
    def __init__(self, model_path: Optional[str] = None, device: str = "cpu"):
        """
        Args:
            model_path: Eğitilmiş model dosyası (.pth)
            device: "cpu" veya "cuda"
        """
        self.device = device
        self.model = None
        self.tokenizer = None
        self.is_ready = False
        
        # Model yolunu belirle
        if model_path is None:
            base_dir = Path(__file__).parent
            model_path = base_dir / MODEL_WEIGHTS_PATH
        else:
            model_path = Path(model_path)
        
        self._load(model_path)
    
    def _load(self, model_path: Path):
        """Model ve tokenizer'ı yükle"""
        if not TRANSFORMERS_AVAILABLE:
            print("[HATA] transformers kütüphanesi bulunamadı!")
            print("[HATA] Kurulum: pip install torch transformers")
            return
        
        try:
            self.tokenizer = get_tokenizer()
            self.model = load_model(str(model_path), self.device)
            self.is_ready = True
            print(f"[LogAnalyzer] Model hazır. Device: {self.device}")
        except Exception as e:
            print(f"[HATA] Model yüklenemedi: {e}")
            self.is_ready = False
    
    def analyze(self, log_line: str) -> Dict[str, Any]:
        """
        Tek bir log satırını analiz et.
        
        Args:
            log_line: Ham log satırı
            
        Returns:
            {
                "label": "attack" | "benign",
                "probable_category": "sqli" | "xss" | ...,
                "confidence": 0.0-1.0,
                "reason": "Açıklama",
                "all_probs": {...}
            }
        """
        if not self.is_ready:
            return {
                "label": "unknown",
                "probable_category": "Unknown",
                "confidence": 0.0,
                "reason": "Model yüklenmedi. Eğitim gerekli.",
                "source": "local-model-error"
            }
        
        # Tokenize
        encoding = self.tokenizer(
            log_line,
            truncation=True,
            max_length=MAX_SEQ_LENGTH,
            padding="max_length",
            return_tensors="pt"
        )
        
        input_ids = encoding["input_ids"].to(self.device)
        attention_mask = encoding["attention_mask"].to(self.device)
        
        # Predict
        pred_class, confidence, all_probs = self.model.predict(input_ids, attention_mask)
        
        # Sonuçları formatla
        category = LABEL_MAP.get(pred_class, "other_attack")
        is_attack = category != "benign"
        
        # Olasılık dağılımını dict'e çevir
        prob_dict = {LABEL_MAP[i]: round(p, 4) for i, p in enumerate(all_probs)}
        
        return {
            "label": "attack" if is_attack else "benign",
            "probable_category": category.upper().replace("_", " "),
            "confidence": round(confidence, 4),
            "reason": f"Local AI: {category} (%{confidence*100:.1f} güven)",
            "source": "local-model",
            "all_probs": prob_dict
        }
    
    def analyze_batch(self, log_lines: list) -> list:
        """Birden fazla log satırını analiz et"""
        return [self.analyze(line) for line in log_lines]


# Global instance (lazy loading)
_analyzer_instance = None


def get_analyzer(model_path: Optional[str] = None) -> LogAnalyzer:
    """
    Singleton pattern ile LogAnalyzer instance'ı döndür.
    İlk çağrıda yüklenir, sonraki çağrılarda aynı instance döner.
    """
    global _analyzer_instance
    
    if _analyzer_instance is None:
        _analyzer_instance = LogAnalyzer(model_path)
    
    return _analyzer_instance


def analyze_with_local_model(log_line: str) -> Dict[str, Any]:
    """
    Ajan.py entegrasyonu için wrapper fonksiyon.
    Eski analyze_with_ai() fonksiyonunun yerine geçer.
    """
    analyzer = get_analyzer()
    return analyzer.analyze(log_line)
