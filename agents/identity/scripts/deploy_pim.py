"""Deploy PIM best practices to the tenant.

1. Create break-glass account with permanent GA (so admjlo isn't the last GA)
2. Make admjlo PIM-eligible for Global Admin
3. Remove admjlo's permanent GA assignment
4. Set activation policies: 4h duration, MFA, justification
"""
import os
import sys
import json
import secrets
import string
from datetime import datetime, timedelta, timezone
from pathlib import Path
from dotenv import load_dotenv
import httpx

load_dotenv(Path(__file__).parent.parent / ".env")

tenant = os.getenv("AZURE_TENANT_ID")
client_id = os.getenv("AZURE_CLIENT_ID")
client_secret = os.getenv("AZURE_CLIENT_SECRET")

GRAPH = "https://graph.microsoft.com/v1.0"
GA_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"
ADMJLO_ID = "9759b5af-faa0-45d1-980e-beb61185a0ef"
ADMJLO_UPN = "admjlo@tbhns.onmicrosoft.com"
DOMAIN = "tbhns.onmicrosoft.com"


def get_token():
    r = httpx.post(
        f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        data={"client_id": client_id, "client_secret": client_secret,
              "scope": "https://graph.microsoft.com/.default",
              "grant_type": "client_credentials"},
    )
    r.raise_for_status()
    return r.json()["access_token"]


def api(method, url, token, body=None):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    full_url = url if url.startswith("http") else f"{GRAPH}{url}"
    r = httpx.request(method, full_url, headers=headers, json=body, timeout=30)
    return r


def generate_password(length=32):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        pw = "".join(secrets.choice(chars) for _ in range(length))
        if (any(c.isupper() for c in pw) and any(c.islower() for c in pw)
                and any(c.isdigit() for c in pw) and any(c in "!@#$%^&*" for c in pw)):
            return pw


def main():
    token = get_token()
    print(f"Authenticated to tenant {tenant}\n")

    # ── Step 0: Create break-glass account if needed ───────────────
    print("=== Step 0: Ensure break-glass account exists ===")
    bg_upn = f"BreakGlass1@{DOMAIN}"

    r = api("GET", f"/users?$filter=userPrincipalName eq '{bg_upn}'&$select=id,displayName,userPrincipalName", token)
    bg_id = None
    if r.status_code == 200 and r.json().get("value"):
        bg_id = r.json()["value"][0]["id"]
        print(f"  Break-glass account exists: {bg_upn} (id={bg_id})")
    else:
        print(f"  Creating break-glass account: {bg_upn}")
        bg_password = generate_password()
        body = {
            "accountEnabled": True,
            "displayName": "Break Glass 1",
            "mailNickname": "BreakGlass1",
            "userPrincipalName": bg_upn,
            "jobTitle": "Emergency Access Account - DO NOT DELETE",
            "passwordProfile": {
                "forceChangePasswordNextSignIn": False,
                "password": bg_password,
            },
        }
        r = api("POST", "/users", token, body)
        if r.status_code in (200, 201):
            bg_id = r.json()["id"]
            print(f"  Created: {bg_upn} (id={bg_id})")
            print(f"  PASSWORD: {bg_password}")
            print(f"  >>> SAVE THIS PASSWORD SECURELY — it will not be shown again <<<")
        else:
            print(f"  Failed to create: {r.status_code} — {r.text[:300]}")
            print("  Cannot proceed without a second GA. Exiting.")
            return

    # Assign permanent GA to break-glass
    print(f"\n  Assigning permanent GA to break-glass account...")
    r = api("GET", f"/roleManagement/directory/roleAssignments?$filter=roleDefinitionId eq '{GA_ROLE_ID}' and principalId eq '{bg_id}'", token)
    if r.status_code == 200 and r.json().get("value"):
        print(f"  Break-glass already has GA — skipping")
    else:
        body = {
            "action": "adminAssign",
            "justification": "Break-glass emergency access account — permanent GA per PIM best practice",
            "roleDefinitionId": GA_ROLE_ID,
            "directoryScopeId": "/",
            "principalId": bg_id,
            "scheduleInfo": {
                "startDateTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "expiration": {"type": "noExpiration"},
            },
        }
        r = api("POST", "/roleManagement/directory/roleAssignmentScheduleRequests", token, body)
        if r.status_code in (200, 201):
            print(f"  Assigned permanent GA to {bg_upn}")
        else:
            print(f"  Failed: {r.status_code} — {r.text[:300]}")
            print("  Cannot proceed without a second GA. Exiting.")
            return

    # ── Step 1: Create PIM eligibility for admjlo ──────────────────
    print("\n=== Step 1: Make admjlo PIM-eligible for Global Admin ===")

    r = api("GET", f"/roleManagement/directory/roleEligibilityScheduleInstances?$filter=roleDefinitionId eq '{GA_ROLE_ID}' and principalId eq '{ADMJLO_ID}'", token)
    if r.status_code == 200 and r.json().get("value"):
        print(f"  Already eligible — skipping")
    else:
        end_date = (datetime.now(timezone.utc) + timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
        body = {
            "action": "adminAssign",
            "justification": "PIM best practice — eligible GA assignment",
            "roleDefinitionId": GA_ROLE_ID,
            "directoryScopeId": "/",
            "principalId": ADMJLO_ID,
            "scheduleInfo": {
                "startDateTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "expiration": {"type": "afterDateTime", "endDateTime": end_date},
            },
        }
        r = api("POST", "/roleManagement/directory/roleEligibilityScheduleRequests", token, body)
        if r.status_code in (200, 201):
            print(f"  Created PIM eligibility for {ADMJLO_UPN} (expires {end_date[:10]})")
        else:
            print(f"  Failed: {r.status_code} — {r.text[:300]}")

    # ── Step 2: Remove permanent GA from admjlo ────────────────────
    print("\n=== Step 2: Remove permanent GA from admjlo ===")
    body = {
        "action": "adminRemove",
        "justification": "PIM-001: converting permanent to eligible",
        "roleDefinitionId": GA_ROLE_ID,
        "directoryScopeId": "/",
        "principalId": ADMJLO_ID,
    }
    r = api("POST", "/roleManagement/directory/roleAssignmentScheduleRequests", token, body)
    if r.status_code in (200, 201):
        print(f"  Removed permanent GA from {ADMJLO_UPN}")
    else:
        print(f"  Failed: {r.status_code} — {r.text[:300]}")

    # ── Step 3: Configure GA activation policy ─────────────────────
    print("\n=== Step 3: Configure GA activation policy (4h, MFA, justification) ===")

    # List all role management policies and find the GA one
    r = api("GET", "/policies/roleManagementPolicies", token)
    ga_policy_id = None
    if r.status_code == 200:
        for policy in r.json().get("value", []):
            scope_id = policy.get("scopeId", "")
            if scope_id == GA_ROLE_ID:
                ga_policy_id = policy.get("id")
                break

    if not ga_policy_id:
        # Try via the rules endpoint directly
        r = api("GET", f"https://graph.microsoft.com/beta/policies/roleManagementPolicies?$filter=scopeId eq '{GA_ROLE_ID}' and scopeType eq 'DirectoryRole'", token)
        if r.status_code == 200 and r.json().get("value"):
            ga_policy_id = r.json()["value"][0]["id"]

    if ga_policy_id:
        print(f"  Found GA policy: {ga_policy_id}")

        # 4h max activation duration
        exp_rule = {
            "@odata.type": "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule",
            "id": "Expiration_EndUser_Assignment",
            "isExpirationRequired": True,
            "maximumDuration": "PT4H",
            "target": {"caller": "EndUser", "operations": ["All"], "level": "Assignment"},
        }
        r = api("PATCH", f"/policies/roleManagementPolicies/{ga_policy_id}/rules/Expiration_EndUser_Assignment", token, exp_rule)
        print(f"  Expiration (4h): {r.status_code}" + (f" — {r.text[:150]}" if r.status_code >= 400 else " OK"))

        # MFA + justification on activation
        enable_rule = {
            "@odata.type": "#microsoft.graph.unifiedRoleManagementPolicyEnablementRule",
            "id": "Enablement_EndUser_Assignment",
            "enabledRules": ["MultiFactorAuthentication", "Justification"],
            "target": {"caller": "EndUser", "operations": ["All"], "level": "Assignment"},
        }
        r = api("PATCH", f"/policies/roleManagementPolicies/{ga_policy_id}/rules/Enablement_EndUser_Assignment", token, enable_rule)
        print(f"  MFA+Justification: {r.status_code}" + (f" — {r.text[:150]}" if r.status_code >= 400 else " OK"))
    else:
        print("  Could not find GA role management policy")
        print("  Set manually: Entra > PIM > Entra ID roles > Global Admin > Settings")

    # ── Step 4: Verify ─────────────────────────────────────────────
    print("\n=== Verification ===")

    r = api("GET", f"/roleManagement/directory/roleEligibilityScheduleInstances?$filter=roleDefinitionId eq '{GA_ROLE_ID}'", token)
    if r.status_code == 200:
        for e in r.json().get("value", []):
            pid = e["principalId"]
            ur = api("GET", f"/users/{pid}?$select=displayName,userPrincipalName", token)
            name = ur.json().get("displayName", pid) if ur.status_code == 200 else pid
            upn = ur.json().get("userPrincipalName", "?") if ur.status_code == 200 else "?"
            print(f"  ELIGIBLE: {name} ({upn}) — until {e.get('endDateTime', 'N/A')[:10]}")

    r = api("GET", f"/roleManagement/directory/roleAssignments?$filter=roleDefinitionId eq '{GA_ROLE_ID}'", token)
    if r.status_code == 200:
        for a in r.json().get("value", []):
            pid = a["principalId"]
            ur = api("GET", f"/users/{pid}?$select=displayName,userPrincipalName", token)
            name = ur.json().get("displayName", pid) if ur.status_code == 200 else pid
            upn = ur.json().get("userPrincipalName", "?") if ur.status_code == 200 else "?"
            print(f"  PERMANENT: {name} ({upn})")

    print("\nDone.")


if __name__ == "__main__":
    main()
