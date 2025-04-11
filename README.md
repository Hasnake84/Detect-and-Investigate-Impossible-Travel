# Alert Investigation: Impossible Travel Detection in Microsoft Sentinel
## Objective:
To detect and investigate impossible travel scenarios—where a user logs in from geographically distant locations within a time window too short for feasible physical travel. These behaviors could indicate account compromise, VPN misuse, or policy violations.

Corporations have policies against working outside of designated geographic regions, account sharing, or use of non-corporate VPNs. The following scenario will be used to detect unusual logon behavior by creating an incident if a user's login patterns are from multiple geographic regions within a given time period.
## Investigation #1: Suspicious Logins from Multiple Unique Locations
### KQL Query:
```KQL Query
   SigninLogs
   | where TimeGenerated > ago(7day)
   | where ResultType == 0  // Successful logins only
   | project TimeGenerated, UserPrincipalName, Location = tostring(LocationDetails.city), IPAddress
   | summarize UniqueLocations = dcount(Location), Logins = count(), StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) 
     by UserPrincipalName
   | where UniqueLocations >= 3
   | order by EndTime desc
```
A total of 137 successful login events from **four UniqueLocations** were recorded for the user identified by UPN ba027c6850fda28969165cd4f42376694e570ca5bbf3d70f6c434c4861cebd12@#########.com, from **four UniqueIps.**

![Screenshot 2025-04-10 210410](https://github.com/user-attachments/assets/c57f712b-6b7f-4746-91e4-bc01d2cf3927)

To narrow the investigation scope, we modified the KQL query to filter by the specific **UPN**, enabling us to examine detailed location and IP address activity for this user.

![image](https://github.com/user-attachments/assets/b4c35f9c-92b7-4b6b-8406-7a97b187c77f)

## IP and Location Analysis: 
All IP addresses were found to be legitimate and traced back to the United Kingdom, specifically within the London metropolitan area, including cities such as Barnet, Barking and Dagenham, and Southwark.
No known threats or anomalies were observed in OSINT databases.

## Action Taken:
- Marked incident as Informational due to legitimate geolocation overlap.
- Created Sentinel Scheduled Query Rule to monitor for 3+ unique location logins in a rolling window.

## Investigation #2: VPN-Linked Access Patterns from DataCamp IP Ranges
## Summary: 
Another user was flagged with 35 successful login events from three distinct locations and three different IP addresses within a short span.

![Screenshot 2025-04-10 222137](https://github.com/user-attachments/assets/bf745337-e902-405f-abea-b63af11463fc)

## Analysis: 
The IP addresses for this user resolved to DataCamp Limited (AS60068) — a known VPN hosting provider. While legitimate, the use of VPNs can mask real user location and introduce false positives for impossible travel alerts.

## Action Taken:
- Flagged the user for additional behavioral review.
- Notified IT compliance team about possible VPN usage.
- Added DataCamp IPs to a contextual allowlist to reduce future alert noise.

## Detection Logic
We used a scheduled query rule in Microsoft Sentinel to surface accounts logging in from three or more unique cities in the past 7 days.
```KQL query
   SigninLogs
   | where TimeGenerated > ago(7d)
   | where ResultType == 0  // Successful logins only
   | project TimeGenerated, UserPrincipalName, Location = tostring(LocationDetails.city), IPAddress
   | summarize UniqueLocations = dcount(Location), Logins = count(), StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) 
    by UserPrincipalName
   | where UniqueLocations >= 3
   | order by EndTime desc
```
## Analytics Rule Settings
- Name: Potential Impossible Travel Alert
- Description: Detects logins from multiple geographic regions
- Rule Enabled
- Runs Every: 4 Hours
- Query Lookup Period: 24 Hours
- Does not re-run after alert is generated

## Entity Mappings
- Account ID: AadUserId → UserId
- Display Name: UserPrincipalName → Value

## Containment, Eradication, and Recovery
- The alerts were determined to be True Benign:
- Legitimate behavior (e.g., nearby locations, trusted ISPs)
- No evidence of account compromise or lateral movement

## Action taken:
- No suspicious behavior detected from **AzureActivity Logs**
```kql
   AzureActivity
| where tostring(parse_json(Claims)["http://schemas.microsoft.com/identity/claims/objectidentifier"]) == "AzureADObjectID"
```
- Added VPN ranges (DataCamp) to an internal context list
- Alert logic retained but moved to Medium severity

## Post-Incident Activities
- Considered enforcing Geo-fencing for high-sensitivity roles

## Documentation:
- All observations and resolutions recorded in internal ticketing system

## Closure
- Incident reviewed and documented
- Case marked as Benign Positive
- Report submitted, rule continues to monitor for future anomalies

## Lessons Learned
- VPN usage can create noise in impossible travel detections — contextual intelligence is key
- Geographic proximity matters — not every alert is a threat
- Scheduled detections with entity mapping streamline triage workflows








