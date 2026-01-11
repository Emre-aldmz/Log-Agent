"""
Log Classifier Model
DistilBERT tabanlı metin sınıflandırma modeli
"""

import torch
import torch.nn as nn
from pathlib import Path

try:
    from transformers import DistilBertModel, DistilBertTokenizer
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    print("[UYARI] transformers kütüphanesi bulunamadı. Model yüklenemez.")

from .config import MODEL_NAME, MAX_SEQ_LENGTH, DROPOUT_RATE, NUM_CLASSES


class LogClassifier(nn.Module):
    """
    DistilBERT tabanlı log sınıflandırma modeli.
    
    8 sınıf çıktısı:
    - benign, sqli, xss, path_traversal, command_injection, 
    - bruteforce, honeypot_trap, other_attack
    """
    
    def __init__(self, num_classes: int = NUM_CLASSES, dropout: float = DROPOUT_RATE):
        super().__init__()
        
        if not TRANSFORMERS_AVAILABLE:
            raise ImportError("transformers kütüphanesi gerekli: pip install transformers")
        
        # DistilBERT backbone
        self.bert = DistilBertModel.from_pretrained(MODEL_NAME)
        
        # Classifier head
        self.dropout = nn.Dropout(dropout)
        self.classifier = nn.Linear(768, num_classes)  # DistilBERT hidden size = 768
        
    def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        """
        Forward pass
        
        Args:
            input_ids: Token IDs [batch_size, seq_len]
            attention_mask: Attention mask [batch_size, seq_len]
            
        Returns:
            logits: Sınıf skorları [batch_size, num_classes]
        """
        # BERT encoding
        outputs = self.bert(input_ids=input_ids, attention_mask=attention_mask)
        
        # [CLS] token embedding'ini al (ilk token)
        pooled_output = outputs.last_hidden_state[:, 0, :]
        
        # Dropout + Classification
        pooled_output = self.dropout(pooled_output)
        logits = self.classifier(pooled_output)
        
        return logits
    
    def predict(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> tuple:
        """
        Tahmin yap ve olasılıkları döndür
        
        Returns:
            (predicted_class, confidence, all_probs)
        """
        self.eval()
        with torch.no_grad():
            logits = self.forward(input_ids, attention_mask)
            probs = torch.softmax(logits, dim=1)
            predicted_class = torch.argmax(probs, dim=1)
            confidence = probs.gather(1, predicted_class.unsqueeze(1)).squeeze()
            
        return predicted_class.item(), confidence.item(), probs.squeeze().tolist()


def load_model(weights_path: str, device: str = "cpu") -> LogClassifier:
    """
    Eğitilmiş modeli yükle
    
    Args:
        weights_path: .pth dosya yolu
        device: "cpu" veya "cuda"
        
    Returns:
        Yüklenmiş model
    """
    model = LogClassifier()
    
    if Path(weights_path).exists():
        state_dict = torch.load(weights_path, map_location=device)
        model.load_state_dict(state_dict)
        print(f"[INFO] Model yüklendi: {weights_path}")
    else:
        print(f"[UYARI] Model dosyası bulunamadı: {weights_path}")
        print("[UYARI] Model eğitilmemiş ağırlıklarla başlatıldı.")
    
    model.to(device)
    model.eval()
    return model


def get_tokenizer():
    """DistilBERT tokenizer'ı döndür"""
    if not TRANSFORMERS_AVAILABLE:
        raise ImportError("transformers kütüphanesi gerekli")
    return DistilBertTokenizer.from_pretrained(MODEL_NAME)
