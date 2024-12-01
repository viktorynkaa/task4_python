from fastapi import FastAPI
from datetime import datetime, timedelta
import json
from fastapi.middleware.cors import CORSMiddleware

def load_json(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

file_path = "known_exploited_vulnerabilities.json"
objects = load_json(file_path)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/info")
def app_info():
    return {
        "application": "Application for CVE",
        "author": "Victoria Yakym",
        "description": "This application is created for getting information about CVE"
    }

@app.get("/get/all")
def cve_five_days():
    try:
        last_twenty_days = datetime.now() - timedelta(days=20)
        export_cve = []

        for i in objects.get("vulnerabilities", []): 
            date_from = datetime.fromisoformat(i.get("dateAdded", ""))
            if date_from >= last_twenty_days:
                export_cve.append(i)
            if len(export_cve) == 40:
                break
    except Exception as e:
        print(e)
    return export_cve

@app.get("/get/new")
def new_cve():
    return objects.get("vulnerabilities", [])[:10]

@app.get("/get/known")
def get_known_cve():
    try:
        ten_cve = []

        for i in objects.get("vulnerabilities", []):
            if "Known" == i.get("knownRansomwareCampaignUse", ""):
                ten_cve.append(i)
            if len(ten_cve) == 10:
                break
    except Exception as e:
        print(e)
    return ten_cve

@app.get("/get")
def key_cve(query):
    try:
        keyw_cve = []

        for i in objects.get("vulnerabilities", []):
            if query.lower() in i.get("shortDescription", "").lower():
                keyw_cve.append(i)
    except Exception as e:
        print(e)
    return keyw_cve

