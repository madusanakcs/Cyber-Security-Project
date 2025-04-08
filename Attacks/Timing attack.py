import time
import requests

def measure_time(password):
    start = time.time()
    requests.post(
        "http://98.70.102.40:8080/api/auth/secure-login",
        json={"username": "test", "password": password}
    )
    return time.time() - start

correct_time = measure_time("test123")
incorrect_time = measure_time("wrong")
print(f"Correct: {correct_time:.4f}s | Incorrect: {incorrect_time:.4f}s")