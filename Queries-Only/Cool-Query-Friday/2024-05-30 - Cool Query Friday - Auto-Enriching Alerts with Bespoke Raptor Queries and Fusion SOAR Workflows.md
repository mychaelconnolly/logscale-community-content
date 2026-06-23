---
title: "Auto-Enriching Alerts with Bespoke Raptor Queries and Fusion SOAR Workflows"
date: 2024-05-30
author: "Andrew-CS"
source_url: "https://www.reddit.com/r/crowdstrike/comments/1d46szz/20240530_cool_query_friday_autoenriching_alerts/"
mitre: []
series: Cool Query Friday
---

# Auto-Enriching Alerts with Bespoke Raptor Queries and Fusion SOAR Workflows

> Source: [https://www.reddit.com/r/crowdstrike/comments/1d46szz/20240530_cool_query_friday_autoenriching_alerts/](https://www.reddit.com/r/crowdstrike/comments/1d46szz/20240530_cool_query_friday_autoenriching_alerts/) — by Andrew-CS (CrowdStrike) — 2024-05-30

Welcome to our seventy-fourth installment of Cool Query Friday. The format will be: (1) description of what we're doing (2) walk through of each step (3) application in the wild.

## Query 1
```cql
// Create parameter for Agent ID; Get AssociateIndicator Events and ProcessRollup2 Events
aid=?aid (#event_simpleName=AssociateIndicator OR #event_simpleName=ProcessRollup2)
// Use selfJoinFilter to join events
| selfJoinFilter(field=[aid, TargetProcessId], where=[{#event_simpleName=AssociateIndicator}, {#event_simpleName=ProcessRollup2}])
```

## Query 2
```cql
// Create parameter for Agent ID; Get AssociateIndicator Events and ProcessRollup2 Events
aid=?aid (#event_simpleName=AssociateIndicator OR #event_simpleName=ProcessRollup2)
// Use selfJoinFilter to join events
| selfJoinFilter(field=[aid, TargetProcessId], where=[{#event_simpleName=AssociateIndicator}, {#event_simpleName=ProcessRollup2}])
// Create pretty process tree for ProcessRollup2 events
| case {
#event_simpleName="ProcessRollup2" | ExecutionChain:=format(format="%s → %s (%s)", field=[ParentBaseFileName, FileName, RawProcessId]);
*;
}
// Use groupBy to aggregate
| groupBy([aid, TargetProcessId], function=([count(aid, as=Occurrences), selectFromMin(field="@timestamp", include=[@timestamp]), collect([ComputerName, UserName, ExecutionChain, Tactic, Technique, DetectDescription, CommandLine])]))
```

## Query 3
```cql
// Create parameter for Agent ID; Get AssociateIndicator Events and ProcessRollup2 Events
aid=?aid (#event_simpleName=AssociateIndicator OR #event_simpleName=ProcessRollup2)
// Use selfJoinFilter to join events
| selfJoinFilter(field=[aid, TargetProcessId], where=[{#event_simpleName=AssociateIndicator}, {#event_simpleName=ProcessRollup2}])
// Create pretty process tree for ProcessRollup2 events
| case {
#event_simpleName="ProcessRollup2" | ExecutionChain:=format(format="%s → %s (%s)", field=[ParentBaseFileName, FileName, RawProcessId]);
*;
}
// Use groupBy to aggregate
| groupBy([aid, TargetProcessId], function=([count(aid, as=Occurrences), selectFromMin(field="@timestamp", include=[@timestamp]), collect([ComputerName, UserName, ExecutionChain, Tactic, Technique, DetectDescription, CommandLine])]))
// Add Process Tree link to ease investigation; Uncomment your cloud
| rootURL := "https://falcon.crowdstrike.com/" /* US-1 */
//| rootURL  := "https://falcon.us-2.crowdstrike.com/" /* US-2 */
//| rootURL  := "https://falcon.laggar.gcw.crowdstrike.com/" /* Gov */
//| rootURL  := "https://falcon.eu-1.crowdstrike.com/"  /* EU */
| format("[Process Explorer](%sgraphs/process-explorer/tree?id=pid:%s:%s)", field=["rootURL", "aid", "TargetProcessId"], as="Falcon")
| drop([rootURL])
| sort(@timestamp, order=desc, limit=20000)
```
