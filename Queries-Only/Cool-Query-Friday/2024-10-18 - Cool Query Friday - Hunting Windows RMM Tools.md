---
title: "Hunting Windows RMM Tools"
date: 2024-10-18
author: "Andrew-CS"
source_url: "https://www.reddit.com/r/crowdstrike/comments/1g6iupi/20241018_cool_query_friday_hunting_windows_rmm/"
mitre: []
series: Cool Query Friday
---

# Hunting Windows RMM Tools

> Source: [https://www.reddit.com/r/crowdstrike/comments/1g6iupi/20241018_cool_query_friday_hunting_windows_rmm/](https://www.reddit.com/r/crowdstrike/comments/1g6iupi/20241018_cool_query_friday_hunting_windows_rmm/) — by Andrew-CS (CrowdStrike) — 2024-10-18

Welcome to our eightieth installment of Cool Query Friday. The format will be: (1) description of what we're doing (2) walk through of each step (3) application in the wild.

## Query 1
```cql
grep -ERi "\-\s\w+\.exe" . | awk -F\- '{ print $2 }' | sed "s/^[ \t]*//" | awk '{print tolower($0)}' | sort -u
```

## Query 2
```cql
// Get all Windows Process Executions
#event_simpleName=ProcessRollup2 event_platform=Win

// Check to see if FileName matches our list of RMM tools
| match(file="rmm_executables_list.csv", field=[FileName], column=rmm, ignoreCase=true)

// Create short file path field
| FilePath=/\\Device\\HarddiskVolume\d+(?<ShortPath>.+$)/

// Aggregate results by FileName
| groupBy([FileName], function=([count(), count(aid, distinct=true, as=UniqueEndpoints), collect([ShortPath])]))

// Sort in descending order so most prevalent binaries appear first
| sort(_count, order=desc, limit=5000)
```

## Query 3
```cql
// Get all Windows Process Executions
#event_simpleName=ProcessRollup2 event_platform=Win

// Create exclusions for approved filenames
| !in(field="FileName", values=[mstsc.exe], ignoreCase=true)

// Check to see if FileName matches our list of RMM tools
| match(file="rmm_executables_list.csv", field=[FileName], column=rmm, ignoreCase=true)
```

## Query 4
```cql
// Get all Windows Process Executions
#event_simpleName=ProcessRollup2 event_platform=Win

// Create exclusions for approved filenames
| !in(field="FileName", values=[mstsc.exe], ignoreCase=true)

// Check to see if FileName matches our list of RMM tools
| match(file="rmm_executables_list.csv", field=[FileName], column=rmm, ignoreCase=true)

// Create pretty ExecutionChain field
| ExecutionChain:=format(format="%s\n\t└ %s (%s)", field=[ParentBaseFileName, FileName, RawProcessId])

// Perform aggregation
| groupBy([@timestamp, aid, ComputerName, UserName, ExecutionChain, CommandLine, TargetProcessId, SHA256HashData], function=[], limit=max)

// Create link to VirusTotal to search SHA256
| format("[Virus Total](https://www.virustotal.com/gui/file/%s)", field=[SHA256HashData], as="VT")

// SET FLACON CLOUD; ADJUST COMMENTS TO YOUR CLOUD
| rootURL := "https://falcon.crowdstrike.com/" /* US-1*/
//rootURL  := "https://falcon.eu-1.crowdstrike.com/" ; /*EU-1 */
//rootURL  := "https://falcon.us-2.crowdstrike.com/" ; /*US-2 */
//rootURL  := "https://falcon.laggar.gcw.crowdstrike.com/" ; /*GOV-1 */

// Create link to Indicator Graph for easier scoping by SHA256
| format("[Indicator Graph](%sintelligence/graph?indicators=hash:'%s')", field=["rootURL", "SHA256HashData"], as="Indicator Graph")

// Create link to Graph Explorer for process specific investigation
| format("[Graph Explorer](%sgraphs/process-explorer/graph?id=pid:%s:%s)", field=["rootURL", "aid", "TargetProcessId"], as="Graph Explorer")

// Drop unneeded fields
| drop([SHA256HashData, TargetProcessId, rootURL])
```

## Query 5
```cql
// Create exclusions for approved users
| !in(field="UserName", values=[Admin, Administrator, Bob, Alice], ignoreCase=true)
```
