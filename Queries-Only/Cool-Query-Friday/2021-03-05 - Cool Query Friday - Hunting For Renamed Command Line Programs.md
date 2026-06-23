---
title: "Hunting For Renamed Command Line Programs"
date: 2021-03-05
author: "Andrew-CS"
source_url: "https://www.reddit.com/r/crowdstrike/comments/lyhga8/20210305_cool_query_friday_hunting_for_renamed/"
mitre: []
series: Cool Query Friday
---

# Hunting For Renamed Command Line Programs

> Source: [https://www.reddit.com/r/crowdstrike/comments/lyhga8/20210305_cool_query_friday_hunting_for_renamed/](https://www.reddit.com/r/crowdstrike/comments/lyhga8/20210305_cool_query_friday_hunting_for_renamed/) — by Andrew-CS (CrowdStrike) — 2021-03-05

Okay, we're going to try something here. Welcome to the first "Cool Query Friday." We're going to (try!) to publish a new, cool threat hunting query every Friday to the community. The format will be: (1) description of what we're doing (2) walk though of each step (3) application in the wild.

## Query 1
```cql
| inputlookup appinfo.csv
```

## Query 2
```cql
event_platform=win event_simpleName=ProcessRollup2 ImageSubsystem_decimal=3 
| rename FileName as runningExe
```

## Query 3
```cql
event_platform=win event_simpleName=ProcessRollup2 ImageSubsystem_decimal=3 
| rename FileName as runningExe
| lookup local=true appinfo.csv SHA256HashData OUTPUT FileName FileDescription
| eval runningExe=lower(runningExe)
| eval FileName=lower(FileName)
```

## Query 4
```cql
event_platform=win event_simpleName=ProcessRollup2 ImageSubsystem_decimal=3 
| rename FileName as runningExe
| lookup local=true appinfo.csv SHA256HashData OUTPUT FileName FileDescription
| eval runningExe=lower(runningExe)
| eval FileName=lower(FileName)
| where runningExe!=FileName
```

## Query 5
```cql
event_platform=win event_simpleName=ProcessRollup2 ImageSubsystem_decimal=3 
| rename FileName as runningExe
| lookup local=true appinfo.csv SHA256HashData OUTPUT FileName FileDescription
| eval runningExe=lower(runningExe)
| eval FileName=lower(FileName)
| where runningExe!=FileName
| stats dc(aid) as "System Count" count(aid) as "Execution Count" values(runningExe) as "File On Disk" values(FileName) as "Cloud File Name" values(FileDescription) as "File Description" by SHA256HashData
```

## Query 6
```cql
event_platform=win event_simpleName=ProcessRollup2 ImageSubsystem_decimal=3 
| rename FileName as runningExe
| lookup local=true appinfo.csv SHA256HashData OUTPUT FileName FileDescription
| eval runningExe=lower(runningExe)
| eval FileName=lower(FileName)
| where runningExe!=FileName
| search FileName=cmd.exe
| stats dc(aid) as "System Count" count(aid) as "Execution Count" values(runningExe) as "File On Disk" values(FileName) as "Cloud File Name" values(FileDescription) as "File Description" by SHA256HashData
```
