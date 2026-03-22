"""Check current PIM state and find admjlo user."""
import os
import sys
from pathlib import Path
from dotenv import load_dotenv
import httpx

load_dotenv(Path(__file__).parent.parent / ".env")

tenant = os.getenv("AZURE_TENANT_ID")
client = os.getenv("AZURE_CLIENT_ID")
secret = os.getenv("AZURE_CLIENT_SECRET")

r = httpx.post(
    f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
    data={"client_id": client, "client_secret": secret,
          "scope": "https://graph.microsoft.com/.default",
          "grant_type": "client_credentials"},
)
token = r.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}

GA_ID = "62e90394-69f5-4237-9190-012177145e10"
PRA_ID = "e8611ab8-c189-46e8-94e1-60213ab1f814"
PAA_ID = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"

def get(url):
    return httpx.get(url, headers=headers, timeout=30)

def get_user(pid):
    r = get(f"https://graph.microsoft.com/v1.0/users/{pid}?$select=id,displayName,userPrincipalName,onPremisesImmutableId")
    if r.status_code == 200:
        return r.json()
    return {"displayName": f"[unresolved:{pid}]", "userPrincipalName": "?"}

# 1. Find admjlo
print("=== Finding admjlo ===")
r = get("https://graph.microsoft.com/v1.0/users?$filter=startsWith(userPrincipalName,'admjlo')&$select=id,displayName,userPrincipalName,onPremisesImmutableId")
if r.status_code == 200:
    for u in r.json().get("value", []):
        print(f"  {u['displayName']} | {u['userPrincipalName']} | id={u['id']} | immutableId={u.get('onPremisesImmutableId')}")
else:
    print(f"  Search failed: {r.status_code} {r.text[:200]}")

# 2. Current GA permanent assignments
print("\n=== Current GA Permanent Assignments ===")
r = get(f"https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$filter=roleDefinitionId eq '{GA_ID}'")
if r.status_code == 200:
    for a in r.json().get("value", []):
        u = get_user(a["principalId"])
        print(f"  {u['displayName']} ({u['userPrincipalName']}) — permanent")
else:
    print(f"  Failed: {r.status_code}")

# 3. Current PIM eligibility for GA
print("\n=== Current GA PIM Eligible ===")
r = get(f"https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$filter=roleDefinitionId eq '{GA_ID}'")
if r.status_code == 200:
    items = r.json().get("value", [])
    if items:
        for e in items:
            u = get_user(e["principalId"])
            print(f"  {u['displayName']} ({u['userPrincipalName']}) — eligible until {e.get('endDateTime', 'permanent')}")
    else:
        print("  None")
else:
    print(f"  Failed: {r.status_code} — {r.text[:200]}")

# 4. Test write capability
print("\n=== Write Permission Check ===")
r = get("https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleRequests?$top=1")
print(f"  roleEligibilityScheduleRequests (read): {r.status_code}")

# 5. All privileged role assignments
print("\n=== All Privileged Role Assignments ===")
PRIV = {GA_ID: "Global Admin", PRA_ID: "Priv Role Admin", PAA_ID: "Priv Auth Admin",
         "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Admin",
         "29232cdf-9323-42fd-abe3-a380a76c3b73": "Exchange Admin",
         "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Admin",
         "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Admin"}
r = get("https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments")
if r.status_code == 200:
    for a in r.json().get("value", []):
        rid = a["roleDefinitionId"]
        if rid in PRIV:
            u = get_user(a["principalId"])
            print(f"  {PRIV[rid]}: {u['displayName']} ({u['userPrincipalName']})")
