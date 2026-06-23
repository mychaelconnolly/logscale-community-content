---
title: "New Feature in Raptor: Falcon Helper"
date: 2023-12-22
author: "Andrew-CS"
source_url: "https://www.reddit.com/r/crowdstrike/comments/18off35/20231222_cool_query_friday_new_feature_in_raptor/"
mitre: []
series: Cool Query Friday
---

# New Feature in Raptor: Falcon Helper

> Source: [https://www.reddit.com/r/crowdstrike/comments/18off35/20231222_cool_query_friday_new_feature_in_raptor/](https://www.reddit.com/r/crowdstrike/comments/18off35/20231222_cool_query_friday_new_feature_in_raptor/) — by Andrew-CS (CrowdStrike) — 2023-12-22

Welcome to our seventy-first installment of Cool Query Friday. The format will be: (1) description of what we're doing (2) walk through of each step (3) application in the wild.

## Query 1
```cql
#event_simpleName=UserLogon
| case {
        LogonType = "2"  | LogonType := "Interactive" ;
        LogonType = "3"  | LogonType := "Network" ;
        LogonType = "4"  | LogonType := "Batch" ;
        LogonType = "5"  | LogonType := "Service" ;
        LogonType = "6"  | LogonType := "Proxy" ;
        LogonType = "7"  | LogonType := "Unlock" ;
        LogonType = "8"  | LogonType := "Network Cleartext" ;
        LogonType = "9"  | LogonType := "New Credential" ;
        LogonType = "10" | LogonType := "Remote Interactive" ;
        LogonType = "11" | LogonType := "Cached Interactive" ;
        LogonType = "12" | LogonType := "Cached Remote Interactive" ;
        LogonType = "13" | LogonType := "Cached Unlock" ; 
        * }
| table([@timestamp, aid, ComputerName, UserName, LogonType])
```

## Query 2
```cql
#event_simpleName=UserLogon
| $falcon/helper:enrich(field=LogonType)
| table([@timestamp, aid, ComputerName, UserName, LogonType])
```

## Query 3
```cql
| $falcon/helper:enrich(field=FIELD)
```

## Query 4
```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| select([@timestamp, aid, ComputerName, FileName, UserName, UserSid, TokenType, IntegrityLevel, ImageSubsystem])
```

## Query 5
```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| select([@timestamp, aid, ComputerName, FileName, UserName, UserSid, TokenType, IntegrityLevel, ImageSubsystem])
| $falcon/helper:enrich(field=IntegrityLevel)
| $falcon/helper:enrich(field=TokenType)
| $falcon/helper:enrich(field=ImageSubsystem)
```
