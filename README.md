# Detect-and-Investigate-Impossible-Travel
Impossible travel is when a user logs in from two geographically distant locations within a short period — something physically impossible without teleportation 
# Objectives:
Use Azure Sentinel and Log Analytics to detect and investigate impossible travel scenarios i.e, when a user logs in from two geographic locations that are impossible to travel between within the time observed and create a *Sentinel Scheduled Query Rule* within Log Analytics that will discover when a user logs in from more than a certain number of locations within a given time period.  
Corporations have policies against working outside of designated geographic regions, account sharing, or use of non-corporate VPNs. The following scenario will be used to detect unusual logon behavior by creating an incident if a user's login patterns are from multiple geographic regions within a given time period.
# 
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
A total of 138 successful login events from four UniqueLocations were recorded for the user identified by UPN ba027c6850fda28969165cd4f42376694e570ca5bbf3d70f6c434c4861cebd12@#########.com.

![Screenshot 2025-04-10 210410](https://github.com/user-attachments/assets/c57f712b-6b7f-4746-91e4-bc01d2cf3927)

To investigate further, we refined our query to focus exclusively on this user’s activity by filtering sign-in logs based on their unique User Principal Name (UPN)."


Microsoft Sentinel → Analytics

Create → Scheduled query rule

Paste the KQL query above

Set schedule (every 30 minutes)

Set alert logic ( > 0)

Save
