---
title: "Custom Lookup Files in Raptor"
date: 2024-06-07
author: "Andrew-CS"
source_url: "https://www.reddit.com/r/crowdstrike/comments/1dal47a/20240607_cool_query_friday_custom_lookup_files_in/"
mitre: []
series: Cool Query Friday
---

# Custom Lookup Files in Raptor

> Source: [https://www.reddit.com/r/crowdstrike/comments/1dal47a/20240607_cool_query_friday_custom_lookup_files_in/](https://www.reddit.com/r/crowdstrike/comments/1dal47a/20240607_cool_query_friday_custom_lookup_files_in/) — by Andrew-CS (CrowdStrike) — 2024-06-07

Welcome to our seventy-fifth installment of Cool Query Friday. The format will be: (1) description of what we're doing (2) walk through of each step (3) application in the wild.

## Query 1
```cql
| readFile("win_lolbins.csv")
```

## Query 2
```cql
// Get all process executions for Windows systems
#event_simpleName=ProcessRollup2 event_platform="Win"
// Check to make sure FileName is on our LOLBINS list located in lookup file
| match(file="win_lolbins.csv", field="FileName", column=FileName, include=[FileName, Description, Paths, URL], strict=true)
```

## Query 3
```cql
// Massage ImageFileName so a true key pair value can be created that combines file path and file name
| regex("(\\\\Device\\\\HarddiskVolume\\d+)?(?<ShortFN>.+)", field=ImageFileName, strict=false)
| ShortFN:=lower("ShortFN")
| FileNameLower:=lower("FileName")
| RunningKey:=format(format="%s_%s", field=[FileNameLower, ShortFN])
// Check to see where the executing file's key doesn't match an expected key value for an LOLBIN
| !match(file="win_lolbins.csv", field="RunningKey", column=key, strict=true)
```

## Query 4
```cql
// Output results to table
| table([aid, ComputerName, UserName, ParentProcessId, ParentBaseFileName, FileName, ShortFN, Paths, CommandLine, Description, Paths, URL])
// Clean up "Paths" to make it easier to read
| Paths =~replace("\, ", with="\n")
// Rename two fields so they are more explicit
| rename([[ShortFN, ExecutingFilePath], [Paths, ExpectFilePath]])
// Add Link for Process Explorer
| rootURL := "https://falcon.crowdstrike.com/" /* US-1 */
//| rootURL  := "https://falcon.us-2.crowdstrike.com/" /* US-2 */
//| rootURL  := "https://falcon.laggar.gcw.crowdstrike.com/" /* Gov */
//| rootURL  := "https://falcon.eu-1.crowdstrike.com/"  /* EU */
| format("[PrEx](%sgraphs/process-explorer/tree?id=pid:%s:%s)", field=["rootURL", "aid", "ParentProcessId"], as="ProcessExplorer")
// Add link back to LOLBAS Project
| format("[LOLBAS](%s)", field=[URL], as="Link")
// Remove unneeded fields
| drop([rootURL, ParentProcessId, URL])
The syntax is well commented, so you can see what’s going on.
```

## Query 5
```cql
// Get all process executions for Windows systems
#event_simpleName=ProcessRollup2 event_platform="Win"
// Check to make sure FileName is on our LOLBINS list located in lookup file
| match(file="win_lolbins.csv", field="FileName", column=FileName, include=[FileName, Description, Paths, URL], strict=true)
// Massage ImageFileName so a true key pair value can be created that combines file path and file name
| regex("(\\\\Device\\\\HarddiskVolume\\d+)?(?<ShortFN>.+)", field=ImageFileName, strict=false)
| ShortFN:=lower("ShortFN")
| FileNameLower:=lower("FileName")
| RunningKey:=format(format="%s_%s", field=[FileNameLower, ShortFN])
// Check to see where the executing file's key doesn't match an expected key value for an LOLBIN
| !match(file="win_lolbins.csv", field="RunningKey", column=key, strict=true)
// Output results to table
| table([aid, ComputerName, UserName, ParentProcessId, ParentBaseFileName, FileName, ShortFN, Paths, CommandLine, Description, Paths, URL])
// Clean up "Paths" to make it easier to read
| Paths =~replace("\, ", with="\n")
// Rename two fields so they are more explicit
| rename([[ShortFN, ExecutingFilePath], [Paths, ExpectFilePath]])
// Add Link for Process Explorer
| rootURL := "https://falcon.crowdstrike.com/" /* US-1 */
//| rootURL  := "https://falcon.us-2.crowdstrike.com/" /* US-2 */
//| rootURL  := "https://falcon.laggar.gcw.crowdstrike.com/" /* Gov */
//| rootURL  := "https://falcon.eu-1.crowdstrike.com/"  /* EU */
| format("[PrEx](%sgraphs/process-explorer/tree?id=pid:%s:%s)", field=["rootURL", "aid", "ParentProcessId"], as="ProcessExplorer")
// Add link back to LOLBAS Project
| format("[LOLBAS](%s)", field=[URL], as="Link")
// Remove unneeded fields
| drop([rootURL, ParentProcessId, URL])
Once executed, you will have output that looks similar to this:
```
