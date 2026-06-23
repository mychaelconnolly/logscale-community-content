---
title: "Password Age and Reused Local Passwords"
date: 2021-05-14
author: "Andrew-CS"
source_url: "https://www.reddit.com/r/crowdstrike/comments/ncb5z7/20210514_cool_query_friday_password_age_and/"
mitre: []
series: Cool Query Friday
---

# Password Age and Reused Local Passwords

> Source: [https://www.reddit.com/r/crowdstrike/comments/ncb5z7/20210514_cool_query_friday_password_age_and/](https://www.reddit.com/r/crowdstrike/comments/ncb5z7/20210514_cool_query_friday_password_age_and/) — by Andrew-CS (CrowdStrike) — 2021-05-14

Welcome to our eleventh installment of [Cool Query Friday](https://www.reddit.com/r/crowdstrike/collection/8016c539-c284-442c-9726-6bc05053d7a9/). The format will be: (1) description of what we're doing (2) walk though of each step (3) application in the wild.

## Query 1
```cql
| fields, aid, event_platform, ComputerName, LocalAddressIP4, LogonDomain, LogonServer, LogonTime_decimal, LogonType_decimal, PasswordLastSet_decimal, ProductType, UserIsAdmin_decimal, UserName, UserSid_readable
```

## Query 2
```cql
| where isnotnull(PasswordLastSet_decimal)
| eval LogonType=case(LogonType_decimal="2", "Interactive", LogonType_decimal="3", "Network", LogonType_decimal="4", "Batch", LogonType_decimal="5", "Service", LogonType_decimal="6", "Proxy", LogonType_decimal="7", "Unlock", LogonType_decimal="8", "Network Cleartext", LogonType_decimal="9", "New Credentials", LogonType_decimal="10", "RDP", LogonType_decimal="11", "Cached Credentials", LogonType_decimal="12", "Auditing", LogonType_decimal="13", "Unlock Workstation")
| eval Product=case(ProductType = "1","Workstation", ProductType = "2","Domain Controller", ProductType = "3","Server") 
| eval UserIsAdmin=case(UserIsAdmin_decimal = "1","Admin", UserIsAdmin_decimal = "0","Standard")
```

## Query 3
```cql
| eval passwordAge=now()-PasswordLastSet_decimal
```

## Query 4
```cql
| eval passwordAge=round(passwordAge/60/60/24,0)
```

## Query 5
```cql
| stats values(event_platform) as Platform latest(passwordAge) as passwordAge values(UserIsAdmin) as adminStatus by UserName, UserSid_readable
| sort - passwordAge
```

## Query 6
```cql
| where passwordAge > 179
```

## Query 7
```cql
event_simpleName=UserLogon
| where isnotnull(PasswordLastSet_decimal)
| fields, aid, event_platform, ComputerName, LocalAddressIP4, LogonDomain, LogonServer, LogonTime_decimal, LogonType_decimal, PasswordLastSet_decimal, ProductType, UserIsAdmin_decimal, UserName, UserSid_readable
| eval LogonType=case(LogonType_decimal="2", "Interactive", LogonType_decimal="3", "Network", LogonType_decimal="4", "Batch", LogonType_decimal="5", "Service", LogonType_decimal="6", "Proxy", LogonType_decimal="7", "Unlock", LogonType_decimal="8", "Network Cleartext", LogonType_decimal="9", "New Credentials", LogonType_decimal="10", "RDP", LogonType_decimal="11", "Cached Credentials", LogonType_decimal="12", "Auditing", LogonType_decimal="13", "Unlock Workstation")
| eval Product=case(ProductType = "1","Workstation", ProductType = "2","Domain Controller", ProductType = "3","Server") 
| eval UserIsAdmin=case(UserIsAdmin_decimal = "1","Admin", UserIsAdmin_decimal = "0","Standard")
| eval passwordAge=now()-PasswordLastSet_decimal
| eval passwordAge=round(passwordAge/60/60/24,0)
| stats values(event_platform) as Platform latest(passwordAge) as passwordAge values(UserIsAdmin) as adminStatus by UserName, UserSid_readable
| sort - passwordAge
| where passwordAge > 179
```

## Query 8
```cql
event_simpleName=UserLogon
| where isnotnull(PasswordLastSet_decimal)
| where LogonDomain=ComputerName
| stats dc(UserSid_readable) as distinctSID values(UserSid_readable) as userSIDs dc(UserName) as distinctUserNames values(UserName) as userNames count(aid) as totalLogins dc(aid) as distinctEndpoints by PasswordLastSet_decimal, event_platform
| sort - distinctEndpoints
| convert ctime(PasswordLastSet_decimal) 
| where distinctEndpoints > 1
```
