---
title: "Hunting Cluster Events by Process Lineage"
date: 2022-08-15
author: "Andrew-CS"
source_url: "https://www.reddit.com/r/crowdstrike/comments/woz73a/20220815_cool_query_friday_hunting_cluster_events/"
mitre: []
series: Cool Query Friday
---

# Hunting Cluster Events by Process Lineage

> Source: [https://www.reddit.com/r/crowdstrike/comments/woz73a/20220815_cool_query_friday_hunting_cluster_events/](https://www.reddit.com/r/crowdstrike/comments/woz73a/20220815_cool_query_friday_hunting_cluster_events/) — by Andrew-CS (CrowdStrike) — 2022-08-15

Welcome to our forty-sixth installment of[ Cool Query Friday](https://www.reddit.com/r/crowdstrike/collection/8016c539-c284-442c-9726-6bc05053d7a9/). The format will be: (1) description of what we're doing (2) walk through of each step (3) application in the wild.

## Query 1
```cql
[...]
| stats dc(FileName) as fnameCount, earliest(ProcessStartTime_decimal) as firstRun, latest(ProcessStartTime_decimal) as lastRun, values(FileName) as filesRun, values(CommandLine) as cmdsRun by cid, aid, ComputerName, ParentBaseFileName, ParentProcessId_decimal
```

## Query 2
```cql
[...]
| where fnameCount > 3
```

## Query 3
```cql
[...]
| where fnameCount>=9
```

## Query 4
```cql
event_platform=win event_simpleName=ProcessRollup2 FileName IN (whoami.exe, arp.exe, cmd.exe, net.exe, net1.exe, ipconfig.exe, route.exe, netstat.exe, nslookup.exe)
| stats dc(FileName) as fnameCount, earliest(ProcessStartTime_decimal) as firstRun, latest(ProcessStartTime_decimal) as lastRun, values(FileName) as filesRun, values(CommandLine) as cmdsRun by cid, aid, ComputerName, ParentBaseFileName, ParentProcessId_decimal
| where fnameCount > 3
```

## Query 5
```cql
[...]
| eval timeDelta=lastRun-firstRun
| where timeDelta < 600
```

## Query 6
```cql
event_platform=win event_simpleName=ProcessRollup2 FileName IN (whoami.exe, arp.exe, cmd.exe, net.exe, net1.exe, ipconfig.exe, route.exe, netstat.exe, nslookup.exe)
| stats dc(FileName) as fnameCount, earliest(ProcessStartTime_decimal) as firstRun, latest(ProcessStartTime_decimal) as lastRun, values(FileName) as filesRun, values(CommandLine) as cmdsRun by cid, aid, ComputerName, ParentBaseFileName, ParentProcessId_decimal
| where fnameCount > 3
| eval timeDelta=lastRun-firstRun
| where timeDelta < 600
```

## Query 7
```cql
[...]
| eval graphExplorer=case(ParentProcessId_decimal!="","https://falcon.crowdstrike.com/graphs/process-explorer/tree?id=pid:".aid.":".ParentProcessId_decimal)
| table cid, aid, ComputerName, ParentBaseFileName, filesRun, cmdsRun, timeDelta, graphExplorer
```

## Query 8
```cql
event_platform=win event_simpleName=ProcessRollup2 FileName IN (whoami.exe, arp.exe, cmd.exe, net.exe, net1.exe, ipconfig.exe, route.exe, netstat.exe, nslookup.exe)
| stats dc(FileName) as fnameCount, earliest(ProcessStartTime_decimal) as firstRun, latest(ProcessStartTime_decimal) as lastRun, values(FileName) as filesRun, values(CommandLine) as cmdsRun by cid, aid, ComputerName, ParentBaseFileName, ParentProcessId_decimal
| where fnameCount > 3
| eval timeDelta=lastRun-firstRun
| where timeDelta < 600
| eval graphExplorer=case(ParentProcessId_decimal!="","https://falcon.crowdstrike.com/graphs/process-explorer/tree?id=pid:".aid.":".ParentProcessId_decimal)
| table cid, aid, ComputerName, ParentBaseFileName, filesRun, cmdsRun, timeDelta, graphExplorer
```
