# Brute-Force Detection Lab: Threat Hunt on Internet-Facing Windows VM

## :bookmark_tabs: Overview
This lab simulates a real-world threat hunt to investigate brute-force login attempts on an internet-facing Windows VM. Using KQL queries, Azure Defender telemetry, and MITRE ATT&CK alignment, we determined exposure status, login activity, and potential compromise.

---

## :world_map: Incident Summary
The VM `windows-target-1`, part of the shared services cluster, was unintentionally left exposed to the public internet. A threat hunt was initiated to:
- Identify brute-force login attempts
- Detect any unauthorized access
- Map activities to known TTPs

---

## :mag_right: Investigation Timeline & KQL Queries

### 1. Check Internet-Facing Status
```kql
DeviceInfo
| where DeviceName == "windows-target-1"
| where IsInternetFacing == true
| order by Timestamp desc
```
### **IsInternetFacing = true result**

<img width="650" alt="Screen Shot 2025-04-12 at 11 17 56 PM" src="https://github.com/user-attachments/assets/318e937e-7707-48bb-a145-1580ad036835" />

### 2. Failed Logon Attempts
```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts desc
```
### **Failed login attempts list**

<img width="650" alt="Screen Shot 2025-04-12 at 11 21 22 PM" src="https://github.com/user-attachments/assets/01cea89d-b217-495f-aa71-e030eb25a560" />

### 3. Check Success from Suspicious IPs
```kql
let RemoteIPsInQuestion = dynamic(["92.255.85.172","147.45.112.27", "196.251.84.131", "185.42.12.59", "147.45.112.29", "91.238.181.40", "88.214.25.73"]);
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```
### **Query returning 0 results**

<img width="650" alt="Screen Shot 2025-04-12 at 11 25 39 PM" src="https://github.com/user-attachments/assets/09d60008-56b5-4a5e-8d38-7e221c3dec03" />

### 4. Legitimate Logins from `labuser`
```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| summarize count()
```
### **8 successful logins for labuser**

<img width="650" alt="Screen Shot 2025-04-12 at 11 31 57 PM" src="https://github.com/user-attachments/assets/272c1414-1884-4c80-ac8d-71594530ebd5" />

### 5. Failed Logins for `labuser`
```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where AccountName == "labuser"
| summarize count()
```
### **0 failed attempts for labuser**

<img width="737" alt="Screen Shot 2025-04-12 at 11 33 33 PM" src="https://github.com/user-attachments/assets/de47d2e8-3c61-4d7d-9f9b-663ca501c365" />

### 6. Logins by Remote IP for `labuser`
```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| summarize Logincount = count() by DeviceName, ActionType, AccountName, RemoteIP
```

### **Clean login IP breakdown**

<img width="740" alt="Screen Shot 2025-04-13 at 12 07 40 AM" src="https://github.com/user-attachments/assets/ef676f87-8572-4484-8717-171b57b26542" />

---

## :shield: Conclusion
Although the VM was exposed and brute-force attempts were made, no suspicious or unauthorized logins were found. All legitimate logins came from expected IPs.

---

## :bulb: Recommendations
- Geo-block top brute-force IPs
- Enforce MFA and account lockout
- Implement Just-in-Time access for RDP
- Monitor for lateral movement using Defender for Endpoint

---

## :memo: MITRE ATT&CK Mapping
| Tactic | Technique | Description |
|--------|-----------|-------------|
| Initial Access | T1133 | External Remote Services (RDP exposed) |
| Credential Access | T1110 | Brute Force against login services |
| Defense Evasion | N/A | No successful evasion detected |

---

## :toolbox: Lab Process Summary
### 1. **Preparation**
- Defined hypothesis: "Are brute-force logins possible on exposed VMs?"

### 2. **Data Collection**
- Pulled logs from `DeviceInfo` and `DeviceLogonEvents`

### 3. **Analysis**
- Reviewed failed vs. successful login trends and IP origins

### 4. **Investigation**
- Mapped IPs and users, verified legitimacy, and matched to MITRE TTPs

### 5. **Response**
- No compromise, but recommended layered protections

### 6. **Documentation**
- Full report created with KQL, visuals, and findings

### 7. **Improvement**
- Implement lockout policies, alerting, NSG restrictions
---

> **Created with Microsoft Defender and Sentinel with KQL analysis on Microsoft Azure**  
> **Project by James Moore | [GitHub](https://github.com/techgneek) | [YouTube](https://youtube.com/@techgneek) | [LinkedIn](https://linkedin.com/in/jamesmoore1983)**

