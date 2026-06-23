---
title: "Microsoft Teams Credentials in the Clear"
date: 2022-09-16
author: "Andrew-CS"
source_url: "https://www.reddit.com/r/crowdstrike/comments/xfqtyb/20220916_cool_query_friday_microsoft_teams/"
mitre: [T1552.001]
series: Cool Query Friday
---

# Microsoft Teams Credentials in the Clear

> Source: [https://www.reddit.com/r/crowdstrike/comments/xfqtyb/20220916_cool_query_friday_microsoft_teams/](https://www.reddit.com/r/crowdstrike/comments/xfqtyb/20220916_cool_query_friday_microsoft_teams/) — by Andrew-CS (CrowdStrike) — 2022-09-16

Welcome to our forty-ninth installment of [Cool Query Friday](https://www.reddit.com/r/crowdstrike/collection/8016c539-c284-442c-9726-6bc05053d7a9/). The format will be: (1) description of what we're doing (2) walk through of each step (3) application in the wild.

## Query 1
```cql
event_platform IN (win, mac, lin) event_simpleName=ProcessRollup2
| regex CommandLine="(?i).*(\\\\|\/)microsoft(\\\\|\/)(microsoft\s)?teams(\\\\|\/)(cookies|local\s+storage(\\\\|\/)leveldb).*"
```

## Query 2
```cql
event_platform IN (win, mac, lin) event_simpleName=ProcessRollup2
| regex CommandLine="(?i).*(\\\\|\/)microsoft(\\\\|\/)(microsoft\s)?teams(\\\\|\/)(cookies|local\s+storage(\\\\|\/)leveldb).*"
| stats dc(aid) as uniqueEndpoints, count(aid) as invocationCount, earliest(ProcessStartTime_decimal) as firstRun, latest(ProcessStartTime_decimal) as lastRun, values(CommandLine) as cmdLines by ParentBaseFileName, FileName
| convert ctime(firstRun), ctime(lastRun)
```

## Query 3
```cql
Rule Type: Process Creation
Action To Take: <choose>
Severity: <choose>
GRANDPARENT IMAGE FILENAME: .*
GRANDPARENT COMMAND LINE: .*
PARENT IMAGE FILENAME: .*
PARENT COMMAND LINE: .*
IMAGE FILENAME: .*
COMMAND LINE: .*\\Microsoft\\Teams\\(Cookies|Local\s+Storage\\leveldb).*
```

## Query 4
```cql
Rule Type: Process Creation
Action To Take: <choose>
Severity: <choose>
GRANDPARENT IMAGE FILENAME: .*
GRANDPARENT COMMAND LINE: .*
PARENT IMAGE FILENAME: .*
PARENT COMMAND LINE: .*
IMAGE FILENAME: .*
COMMAND LINE: .*\/Library\/Application\s+Support\/Microsoft\/Teams\/(Cookies|Local\s+Storage\/leveldb).*
```

## Query 5
```cql
Rule Type: Process Creation
Action To Take: <choose>
Severity: <choose>
GRANDPARENT IMAGE FILENAME: .*
GRANDPARENT COMMAND LINE: .*
PARENT IMAGE FILENAME: .*
PARENT COMMAND LINE: .*
IMAGE FILENAME: .*
COMMAND LINE: .*\/\.config\/Microsoft\/Microsoft\sTeams\/(Cookies|Local\s+Storage\/leveldb).*
```

## Query 6
```cql
#event_simpleName=ProcessRollup2
| CommandLine=/(\/|\\)Microsoft(\/|\\)(Microsoft\s)?Teams(\/|\\)(Cookies|Local\s+Storage(\/|\\)leveldb)/i
| CommandLine=/Teams(\\|\/)(local\sstorage(\\|\/))?(?<teamsFile>(leveldb|cookies))/i
| groupBy([ParentBaseFileName, ImageFileName, teamsFile, CommandLine])
```

## Query 7
```cql
#event_simpleName=ProcessRollup2
| CommandLine=/(\/|\\)Microsoft(\/|\\)(Microsoft\s)?Teams(\/|\\)(Cookies|Local\s+Storage(\/|\\)leveldb)/i
| CommandLine=/Teams(\\|\/)(local\sstorage(\\|\/))?(?<teamsFile>(leveldb|cookies))/i
| sankey(source="ImageFileName",target="teamsFile", weight=count(aid))
```
