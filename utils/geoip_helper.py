import requests
import json
import os
from typing import Optional, Tuple, Dict

# Basit bir in-memory cache
# Gerçek hayatta bu diske kaydedilebilir veya Redis kullanılabilir.
_GEO_CACHE: Dict[str, Tuple[float, float, str]] = {}

def get_location_from_ip(ip: str) -> Optional[Tuple[float, float, str]]:
    """
    Verilen IP adresi için (lat, lon, country_code) bilgisini döner.
    ip-api.com ücretsiz API'sini kullanır.
    """
    # 1. Cache kontrolü
    if ip in _GEO_CACHE:
        return _GEO_CACHE[ip]

    # 2. Localhost Network (Sadece kendisi)
    if ip in ["127.0.0.1", "::1", "localhost"]:
        return (39.9334, 32.8597, "TR") # Ankara (Merkez)

    # 3. API İsteği
    # ip-api.com limiti: 45 istek / dakika. 
    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                lat = data.get("lat")
                lon = data.get("lon")
                country = data.get("countryCode", "UNK")
                
                result = (lat, lon, country)
                _GEO_CACHE[ip] = result
                return result
    except Exception as e:
        print(f"[GeoIP] Hata: {e}")
    
    return None
