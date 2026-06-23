---
title: "Adding Process Explorer and RTR Links to Scheduled Queries"
date: 2022-01-07
author: "Andrew-CS"
source_url: "https://www.reddit.com/r/crowdstrike/comments/ry6ma0/20220107_cool_query_friday_adding_process/"
mitre: []
series: Cool Query Friday
---

# Adding Process Explorer and RTR Links to Scheduled Queries

> Source: [https://www.reddit.com/r/crowdstrike/comments/ry6ma0/20220107_cool_query_friday_adding_process/](https://www.reddit.com/r/crowdstrike/comments/ry6ma0/20220107_cool_query_friday_adding_process/) — by Andrew-CS (CrowdStrike) — 2022-01-07

Welcome to our thirty-fourth installment of [Cool Query Friday](https://www.reddit.com/r/crowdstrike/collection/8016c539-c284-442c-9726-6bc05053d7a9/). The format will be: (1) description of what we're doing (2) walk though of each step (3) application in the wild.

## Query 1
```cql
[...]
| eval CommandLine=lower(CommandLine)
| regex CommandLine=".*group\s+.*admin.*"
```

## Query 2
```cql
[...]
| stats count(aid) as executionCount, latest(TargetProcessId_decimal) as latestFalconPID by aid, ComputerName, UserName, UserSid_readable, FileName, CommandLine
```

## Query 3
```cql
index=main sourcetype=ProcessRollup* event_platform=win event_simpleName=ProcessRollup2 FileName IN (net.exe, net1.exe)
| eval CommandLine=lower(CommandLine)
| regex CommandLine=".*group\s+.*admin.*"
| stats count(aid) as executionCount, latest(TargetProcessId_decimal) as latestFalconPID by aid, ComputerName, UserName, UserSid_readable, FileName, CommandLine
| sort + executionCount
```

## Query 4
```cql
[...]
| eval processExplorer="https://falcon.crowdstrike.com/investigate/process-explorer/" .aid. "/" . latestFalconPID
```

## Query 5
```cql
[...]
| eval startRTR="https://falcon.crowdstrike.com/activity/real-time-response/console/?start=hosts&aid=".aid
```

## Query 6
```cql
index=main sourcetype=ProcessRollup* event_platform=win event_simpleName=ProcessRollup2 FileName IN (net.exe, net1.exe)
| fields aid, TargetProcessId_decimal, ComputerName, UserName, UserSid_readable, FileName, CommandLine
| eval CommandLine=lower(CommandLine)
| regex CommandLine=".*group\s+.*admin.*"
| stats count(aid) as executionCount, latest(TargetProcessId_decimal) as latestFalconPID by aid, ComputerName, UserName, UserSid_readable, FileName, CommandLine
| sort + executionCount
| eval processExplorer="https://falcon.crowdstrike.com/investigate/process-explorer/" .aid. "/" . latestFalconPID
| eval startRTR="https://falcon.crowdstrike.com/activity/real-time-response/console/?start=hosts&aid=".aid
```
