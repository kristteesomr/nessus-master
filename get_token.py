import requests
import urllib3

#Purpose: Log in by username and password -> Receive token of session -> Use that token to get keys
proxies = {
    "http" : "http://192.168.56.1:8080",
    "https": "http://192.168.56.1:8080"
}

def disable_ssl_warnings():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def authenticate_session():
    url = "https://172.24.120.204:11127/session"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.216 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
    }
    payload = {"password": "1234567890", "username": "admin"}
    response = requests.post(url, headers=headers, json=payload, verify=False, proxies= proxies)
    return response.json().get('token')

def get_access_keys(token):
    url2 = "https://172.24.120.204:11127/session/keys"
    headers2 = {"X-Cookie": f"token={token}"}
    response = requests.put(url=url2, headers=headers2, verify=False, proxies=proxies)
    return response.json().get('accessKey'), response.json().get('secretKey')

if __name__ == "__main__":
    disable_ssl_warnings()
    token = authenticate_session()
    access_key, secret_key = get_access_keys(token)
    print(access_key + "\n" + secret_key)

