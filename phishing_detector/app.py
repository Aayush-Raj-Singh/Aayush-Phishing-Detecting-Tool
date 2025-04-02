from flask import Flask, render_template, request
import requests

app = Flask(__name__)

# Google Safe Browsing API Key
API_KEY = "*******************************"
SAFE_BROWSING_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

# Store search history
search_history = []

def get_openphish_urls():
    url = "https://openphish.com/feed.txt"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.text.split("\n")
        else:
            return []
    except Exception:
        return []

def check_url_with_openphish(url):
    phishing_urls = get_openphish_urls()
    return url in phishing_urls

def check_google_safe_browsing(url):
    payload = {
        "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    response = requests.post(SAFE_BROWSING_URL, json=payload)
    return "matches" in response.json()

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        url = request.form["url"]
        is_phishing_openphish = check_url_with_openphish(url)
        is_phishing_google = check_google_safe_browsing(url)

        if is_phishing_openphish or is_phishing_google:
            result = f"⚠️ Warning! The URL '{url}' is flagged as phishing."
        else:
            result = f"✅ Safe! The URL '{url}' is not found in phishing databases."

        # Add to search history
        search_history.insert(0, {"url": url, "result": result})

    return render_template("index.html", result=result, search_history=search_history[:5])  # Show last 5 searches

if __name__ == "__main__":
    app.run(debug=True)
