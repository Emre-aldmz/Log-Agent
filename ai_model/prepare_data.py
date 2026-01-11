"""
Veri Birleştirme ve Dönüştürme Scripti
Log Gözcüsü - AI Model Eğitimi

Bu script farklı formatlardaki datasetleri birleştirir ve
tek bir JSONL dosyasına dönüştürür.
"""

import csv
import json
from pathlib import Path
from collections import Counter


# Çıktı etiketleri (8 sınıf)
LABEL_MAP = {
    "benign": "benign",
    "norm": "benign",
    "normal": "benign",
    "0": "benign",
    
    "sqli": "sqli",
    "sql": "sqli",
    "sql_injection": "sqli",
    "sql injection": "sqli",
    
    "xss": "xss",
    "cross-site scripting": "xss",
    
    "path-traversal": "path_traversal",
    "path_traversal": "path_traversal",
    "traversal": "path_traversal",
    
    "cmdi": "command_injection",
    "command_injection": "command_injection",
    "command injection": "command_injection",
    "rce": "command_injection",
    
    "bruteforce": "bruteforce",
    "brute_force": "bruteforce",
    
    "honeypot": "honeypot_trap",
    "honeypot_trap": "honeypot_trap",
    
    "anomalous": "other_attack",
    "anom": "other_attack",
    "other": "other_attack",
    "1": "other_attack",  # Binary label: 1 = attack
}


def normalize_label(raw_label: str) -> str:
    """Etiketi standart formata dönüştür"""
    if raw_label is None:
        return "benign"
    
    raw = str(raw_label).lower().strip()
    
    # Direkt eşleşme
    if raw in LABEL_MAP:
        return LABEL_MAP[raw]
    
    # Kısmi eşleşme
    for key, value in LABEL_MAP.items():
        if key in raw:
            return value
    
    # Varsayılan
    return "other_attack"


def process_csic_database(filepath: Path) -> list:
    """
    CSIC 2010 dataset'ini işle
    İlk sütun ('') = classification (Normal/Anomalous)
    Son sütun (URL) = HTTP request URL
    """
    samples = []
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        
        for row in reader:
            # Classification ilk (boş isimli) sütunda
            classification = row.get('', 'Normal')
            
            # URL son sütunda
            url = row.get('URL', '')
            
            # Content de olabilir (POST istekleri için)
            content = row.get('content', '')
            
            # Log olarak URL + content birleştir
            log_text = url
            if content and len(content) > 3:
                log_text = f"{url} {content}"
            
            # Etiket belirle
            if classification.lower().strip() == 'normal':
                label = 'benign'
            else:
                label = 'other_attack'  # Anomalous = saldırı
            
            if log_text and len(log_text) > 10:
                samples.append({
                    "log": log_text[:500],  # Max 500 karakter
                    "label": label
                })
    
    return samples


def process_payload_csv(filepath: Path) -> list:
    """
    HttpParamsDataset (payload_full.csv) işle
    Sütunlar: payload, length, attack_type, label
    """
    samples = []
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        
        for row in reader:
            payload = row.get('payload', '')
            attack_type = row.get('attack_type', 'norm')
            
            label = normalize_label(attack_type)
            
            if payload and len(payload) > 3:
                samples.append({
                    "log": payload[:500],
                    "label": label
                })
    
    return samples


def process_sqli_csv(filepath: Path) -> list:
    """
    SQLiV3.csv işle
    Sütunlar: Sentence, Label (0=benign, 1=sqli)
    """
    samples = []
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        
        for row in reader:
            sentence = row.get('Sentence', '')
            label_raw = row.get('Label', '0')
            
            # Binary: 0=benign, 1=sqli
            try:
                label = 'sqli' if int(float(label_raw)) == 1 else 'benign'
            except:
                label = 'sqli' if label_raw.strip() == '1' else 'benign'
            
            if sentence and len(sentence) > 3:
                samples.append({
                    "log": sentence[:500],
                    "label": label
                })
    
    return samples


def process_xss_csv(filepath: Path) -> list:
    """
    XSS_dataset.csv işle
    Sütunlar: Sentence, Label (0=benign, 1=xss)
    """
    samples = []
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        
        for row in reader:
            sentence = row.get('Sentence', '')
            label_raw = row.get('Label', '0')
            
            # Binary: 0=benign, 1=xss
            try:
                label = 'xss' if int(float(label_raw)) == 1 else 'benign'
            except:
                label = 'xss' if label_raw.strip() == '1' else 'benign'
            
            if sentence and len(sentence) > 3:
                samples.append({
                    "log": sentence[:500],
                    "label": label
                })
    
    return samples


def save_jsonl(samples: list, output_path: Path):
    """JSONL formatında kaydet"""
    with open(output_path, 'w', encoding='utf-8') as f:
        for sample in samples:
            f.write(json.dumps(sample, ensure_ascii=False) + '\n')


def main():
    data_dir = Path(__file__).parent / "data"
    
    all_samples = []
    
    # 1. CSIC Database
    csic_path = data_dir / "csic_database.csv"
    if csic_path.exists():
        print(f"İşleniyor: {csic_path.name}...")
        samples = process_csic_database(csic_path)
        print(f"  → {len(samples)} örnek eklendi")
        all_samples.extend(samples)
    
    # 2. Payload Full (HttpParamsDataset)
    payload_path = data_dir / "payload_full.csv"
    if payload_path.exists():
        print(f"İşleniyor: {payload_path.name}...")
        samples = process_payload_csv(payload_path)
        print(f"  → {len(samples)} örnek eklendi")
        all_samples.extend(samples)
    
    # 3. SQLi Dataset
    sqli_path = data_dir / "SQLiV3.csv"
    if sqli_path.exists():
        print(f"İşleniyor: {sqli_path.name}...")
        samples = process_sqli_csv(sqli_path)
        print(f"  → {len(samples)} örnek eklendi")
        all_samples.extend(samples)
    
    # 4. XSS Dataset
    xss_path = data_dir / "XSS_dataset.csv"
    if xss_path.exists():
        print(f"İşleniyor: {xss_path.name}...")
        samples = process_xss_csv(xss_path)
        print(f"  → {len(samples)} örnek eklendi")
        all_samples.extend(samples)
    
    # İstatistikler
    print(f"\n{'='*50}")
    print(f"TOPLAM: {len(all_samples)} örnek")
    
    label_counts = Counter(s['label'] for s in all_samples)
    print("\nEtiket dağılımı:")
    for label, count in sorted(label_counts.items(), key=lambda x: -x[1]):
        pct = count / len(all_samples) * 100
        print(f"  {label:20s}: {count:6d} ({pct:5.1f}%)")
    
    # Train/Val/Test split (80/10/10)
    import random
    random.seed(42)
    random.shuffle(all_samples)
    
    n = len(all_samples)
    train_end = int(n * 0.8)
    val_end = int(n * 0.9)
    
    train_samples = all_samples[:train_end]
    val_samples = all_samples[train_end:val_end]
    test_samples = all_samples[val_end:]
    
    # Kaydet
    save_jsonl(train_samples, data_dir / "train.jsonl")
    save_jsonl(val_samples, data_dir / "val.jsonl")
    save_jsonl(test_samples, data_dir / "test.jsonl")
    save_jsonl(all_samples, data_dir / "all_data.jsonl")
    
    print(f"\n{'='*50}")
    print(f"✅ Dosyalar oluşturuldu:")
    print(f"  train.jsonl : {len(train_samples)} örnek")
    print(f"  val.jsonl   : {len(val_samples)} örnek")
    print(f"  test.jsonl  : {len(test_samples)} örnek")
    print(f"  all_data.jsonl : {len(all_samples)} örnek (tümü)")


if __name__ == "__main__":
    main()
