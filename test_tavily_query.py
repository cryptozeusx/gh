import os
from curl_cffi import requests

token = os.environ.get("GITHUB_TOKEN")
headers = {
    "Authorization": f"token {token}",
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "CMU-Security-Research"
}

queries = [
    'TAVILY_API_KEY filename:.env',
    'TAVILY_API_KEY extension:example',
    'TAVILY_API_KEY extension:local',
    'TAVILY_API_KEY extension:development',
    'tvly filename:.env',
    'tvly extension:example',
    'tvly extension:local',
    'tvly extension:development',
]

for q in queries:
    r = requests.get("https://api.github.com/search/code", headers=headers, params={"q": q})
    print(f"{q:<40} -> {r.json().get('total_count')} results")
