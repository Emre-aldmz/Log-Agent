"""
Dataset Classes for Log Classification
PyTorch Dataset implementation
"""

import json
from pathlib import Path
from typing import List, Dict, Optional
import torch
from torch.utils.data import Dataset

try:
    from transformers import DistilBertTokenizer
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False

from .config import MODEL_NAME, MAX_SEQ_LENGTH, LABEL_TO_ID


class LogDataset(Dataset):
    """
    Log satırları için PyTorch Dataset
    
    JSONL formatı beklenir:
    {"log": "192.168.1.1 - - [10/Jan/2026:12:00:00] \"GET /login?id=1' OR 1=1-- HTTP/1.1\" 200 1234", "label": "sqli"}
    """
    
    def __init__(
        self, 
        data_path: str,
        tokenizer: Optional[any] = None,
        max_length: int = MAX_SEQ_LENGTH
    ):
        self.data_path = Path(data_path)
        self.max_length = max_length
        
        # Tokenizer
        if tokenizer is None:
            if not TRANSFORMERS_AVAILABLE:
                raise ImportError("transformers kütüphanesi gerekli")
            self.tokenizer = DistilBertTokenizer.from_pretrained(MODEL_NAME)
        else:
            self.tokenizer = tokenizer
        
        # Veriyi yükle
        self.samples = self._load_data()
        
    def _load_data(self) -> List[Dict]:
        """JSONL dosyasını oku"""
        samples = []
        
        if not self.data_path.exists():
            print(f"[UYARI] Veri dosyası bulunamadı: {self.data_path}")
            return samples
        
        with open(self.data_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    sample = json.loads(line)
                    if "log" in sample and "label" in sample:
                        samples.append(sample)
                except json.JSONDecodeError:
                    continue
        
        print(f"[INFO] {len(samples)} örnek yüklendi: {self.data_path}")
        return samples
    
    def __len__(self) -> int:
        return len(self.samples)
    
    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        sample = self.samples[idx]
        log_text = sample["log"]
        label_str = sample["label"].lower()
        
        # Label ID
        label_id = LABEL_TO_ID.get(label_str, LABEL_TO_ID.get("other_attack", 7))
        
        # Tokenize
        encoding = self.tokenizer(
            log_text,
            truncation=True,
            max_length=self.max_length,
            padding="max_length",
            return_tensors="pt"
        )
        
        return {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
            "label": torch.tensor(label_id, dtype=torch.long)
        }


def create_sample_data(output_path: str, num_samples: int = 10):
    """
    Test için örnek veri oluştur
    """
    samples = [
        # Benign
        {"log": '192.168.1.1 - - [10/Jan/2026:12:00:00] "GET /index.html HTTP/1.1" 200 5678 "-" "Mozilla/5.0"', "label": "benign"},
        {"log": '10.0.0.5 - - [10/Jan/2026:12:01:00] "GET /api/users HTTP/1.1" 200 1234 "-" "curl/7.68.0"', "label": "benign"},
        {"log": '172.16.0.1 - - [10/Jan/2026:12:02:00] "POST /login HTTP/1.1" 302 0 "-" "Mozilla/5.0"', "label": "benign"},
        
        # SQLi
        {"log": '192.168.1.100 - - [10/Jan/2026:12:03:00] "GET /login?user=admin\' OR \'1\'=\'1 HTTP/1.1" 200 1234', "label": "sqli"},
        {"log": '10.0.0.50 - - [10/Jan/2026:12:04:00] "GET /product?id=1 UNION SELECT * FROM users HTTP/1.1" 200 3000', "label": "sqli"},
        
        # XSS
        {"log": '192.168.1.200 - - [10/Jan/2026:12:05:00] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 500', "label": "xss"},
        
        # Path Traversal
        {"log": '10.0.0.100 - - [10/Jan/2026:12:06:00] "GET /download?file=../../etc/passwd HTTP/1.1" 200 1500', "label": "path_traversal"},
        
        # Command Injection
        {"log": '172.16.0.50 - - [10/Jan/2026:12:07:00] "GET /ping?ip=127.0.0.1;cat /etc/shadow HTTP/1.1" 200 2000', "label": "command_injection"},
        
        # Bruteforce
        {"log": '192.168.1.150 - - [10/Jan/2026:12:08:00] "POST /login HTTP/1.1" 401 100 "-" "hydra/9.0"', "label": "bruteforce"},
        
        # Other
        {"log": '10.0.0.200 - - [10/Jan/2026:12:09:00] "GET /.env HTTP/1.1" 200 500 "-" "Mozilla/5.0"', "label": "honeypot_trap"},
    ]
    
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, "w", encoding="utf-8") as f:
        for sample in samples[:num_samples]:
            f.write(json.dumps(sample, ensure_ascii=False) + "\n")
    
    print(f"[INFO] Örnek veri oluşturuldu: {output_path}")
