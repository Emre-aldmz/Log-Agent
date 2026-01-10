from ajan import AnomalyDetector
import time

def test_anomaly_detector():
    print("Testing AnomalyDetector...")
    # Initialize with default window=60s, checking every 60s
    # To test quickly, we might need to mock time or modify the class to accept time overrides.
    # However, for this simple test, we will trust the logic if we can simulate the request history.
    
    detector = AnomalyDetector(window_seconds=60, threshold_multiplier=2.0)
    
    # 1. Learning Phase
    print("Phase 1: Learning (feeding 30 requests)")
    for _ in range(30):
        detector.record_request()
    
    detector.check_anomaly()
    print(f"Baseline after learning: {detector.baseline_req_per_min} (Expected >= 30)")
    
    # Force exit learning mode for testing
    detector.learning_mode = False
    
    # 2. Normal Traffic
    print("Phase 2: Normal traffic (feeding 20 requests)")
    detector.history = [] # Reset history for clarity
    for _ in range(20):
        detector.record_request()
        
    # Mocking last_check to ensure it runs
    detector.last_check = time.time() - 61 
    
    result = detector.check_anomaly()
    if result is None:
        print("SUCCESS: Normal traffic detected as normal.")
    else:
        print(f"FAILURE: Normal traffic detected as anomaly: {result}")

    # 3. Spike Traffic
    print("Phase 3: Spike traffic (feeding 100 requests)")
    detector.history = []
    for _ in range(100):
        detector.record_request()
        
    detector.last_check = time.time() - 61
    result = detector.check_anomaly()
    
    if result:
        print(f"SUCCESS: Spike detected! Details: {result}")
    else:
        print("FAILURE: Spike NOT detected.")

if __name__ == "__main__":
    test_anomaly_detector()
