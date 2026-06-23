---
title: "Mining Windows CommandHistory for Artifacts"
date: 2021-10-15
author: "Andrew-CS"
source_url: "https://www.reddit.com/r/crowdstrike/comments/q8qzmp/20211015_cool_query_friday_mining_windows/"
mitre: []
series: Cool Query Friday
---

# Mining Windows CommandHistory for Artifacts

> Source: [https://www.reddit.com/r/crowdstrike/comments/q8qzmp/20211015_cool_query_friday_mining_windows/](https://www.reddit.com/r/crowdstrike/comments/q8qzmp/20211015_cool_query_friday_mining_windows/) — by Andrew-CS (CrowdStrike) — 2021-10-15

Welcome to our twenty-seventh installment of [Cool Query Friday](https://www.reddit.com/r/crowdstrike/collection/8016c539-c284-442c-9726-6bc05053d7a9/). The format will be: (1) description of what we're doing (2) walk though of each step (3) application in the wild.

## Query 1
```cql
index=main sourcetype=CommandHistory* event_platform=win event_simpleName=CommandHistory
| rex field=CommandHistory ".*(?<passedURL>http(|s)\:\/\/.*\.(net|com|org|io)).*"
```

## Query 2
```cql
http(s):\\<anything>.com|.net|.org|.io
```

## Query 3
```cql
index=main sourcetype=CommandHistory* event_platform=win event_simpleName=CommandHistory
| rex field=CommandHistory ".*(?<passedURL>http(|s)\:\/\/.*\.(net|com|org|io)).*"
| where isnotnull(passedURL)
```

## Query 4
```cql
[...]
| fillnull ApplicationName value="powershell.exe"
| eval timestamp=timestamp/1000
| table timestamp ComputerName ApplicationName TargetProcessId_decimal passedURL CommandHistory 
| convert ctime(timestamp)
| rename timestamp as Time, ComputerName as Endpoint, ApplicationName as "Responsible Application", TargetProcessId_decimal as "Falcon PID", passedURL as "URL Fragment", CommandHistory as "Complete Command Context"
```

## Query 5
```cql
[...]
| table timestamp ComputerName ApplicationName TargetProcessId_decimal passedURL CommandHistory 
| search ComputerName!=DESKTOP-ICAKMS8 AND passedURL!="*.crowdstrike.*" AND passedURL!="*.microsoft.*"
| convert ctime(timestamp)
[...]
```

## Query 6
```cql
index=main sourcetype=CommandHistory* event_platform=win event_simpleName=CommandHistory
| rex field=CommandHistory ".*(?<passedURL>http(|s)\:\/\/.*\.(net|com|org|io)).*"
| where isnotnull(passedURL)
| fillnull ApplicationName value="powershell.exe"
| eval timestamp=timestamp/1000
| table timestamp ComputerName ApplicationName TargetProcessId_decimal passedURL CommandHistory 
| search ComputerName!=DESKTOP-ICAKMS8 AND passedURL!="*.crowdstrike.*" AND passedURL!="*.microsoft.*"
| convert ctime(timestamp)
| rename timestamp as Time, ComputerName as Endpoint, ApplicationName as "Responsible Application", TargetProcessId_decimal as "Falcon PID", passedURL as "URL Fragment", CommandHistory as "Complete Command Context"
```
