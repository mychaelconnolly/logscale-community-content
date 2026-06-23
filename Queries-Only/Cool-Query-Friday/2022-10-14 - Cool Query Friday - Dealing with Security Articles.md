---
title: "Dealing with Security Articles"
date: 2022-10-14
author: "Andrew-CS"
source_url: "https://www.reddit.com/r/crowdstrike/comments/y3w8bt/20221014_cool_query_friday_dealing_with_security/"
mitre: []
series: Cool Query Friday
---

# Dealing with Security Articles

> Source: [https://www.reddit.com/r/crowdstrike/comments/y3w8bt/20221014_cool_query_friday_dealing_with_security/](https://www.reddit.com/r/crowdstrike/comments/y3w8bt/20221014_cool_query_friday_dealing_with_security/) — by Andrew-CS (CrowdStrike) — 2022-10-14

Welcome to our fifty-first installment of [Cool Query Friday](https://www.reddit.com/r/crowdstrike/collection/8016c539-c284-442c-9726-6bc05053d7a9/). The format will be: (1) description of what we're doing (2) walk through of each step (3) application in the wild.

## Query 1
```cql
event_platform=win event_simpleName=ProcessRollup2 "ADSelfService" "ManageEngine"
| stats values(aid) as aids, values(FileName) as fileNames, values(FilePath) as filePaths by cid
```

## Query 2
```cql
event_platform=win event_simpleName IN (NewScriptWritten, ZipFileWritten) "ADSelfService" "ManageEngine"
| stats dc(aid) as endpointCount, count(aid) as writeCount by TargetFileName
```

## Query 3
```cql
event_platform=win event_simpleName IN (NewScriptWritten, ZipFileWritten) "ADSelfService" "ManageEngine"
| regex TargetFileName=".*\\\\webapps\\\\adssp\\\\help\\\\admin-guide\\\\reports\\\\.*"
| stats dc(aid) as endpointCount, count(aid) as writeCount by TargetFileName
```

## Query 4
```cql
RULE TYPE: File Creation

ACTION TO TAKE: Detect

SEVERITY: <choose>

RULE NAME: <choose>

FILE PATH: .*\\ManageEngine\\ADSelfService\s+Plus\\webapps\\adssp\\help\\admin\-guide\\reports\\.+\.(jsp|zip)

FILE TYPE: ZIP, SCRIPT, OTHER
```
