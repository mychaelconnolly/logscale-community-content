---
title: "Historic MITRE ATT&CK Footprint Data"
date: 2020-03-19
author: "Andrew-CS"
source_url: "https://www.reddit.com/r/crowdstrike/comments/m8gpto/20200319_cool_query_friday_historic_mitre_attck/"
mitre: []
series: Cool Query Friday
---

# Historic MITRE ATT&CK Footprint Data

> Source: [https://www.reddit.com/r/crowdstrike/comments/m8gpto/20200319_cool_query_friday_historic_mitre_attck/](https://www.reddit.com/r/crowdstrike/comments/m8gpto/20200319_cool_query_friday_historic_mitre_attck/) — by Andrew-CS (CrowdStrike) — 2020-03-19

Welcome to our third installment of [Cool Query Friday](https://www.reddit.com/r/crowdstrike/?f=flair_name%3A%22CQF%22). The format will be: (1) description of what we're doing (2) walk though of each step (3) application in the wild.

## Query 1
```cql
earliest=-365d ExternalApiType=Event_DetectionSummaryEvent 
| stats dc(AgentIdString) as uniqueEndpoints count(AgentIdString) as detectionCount by Tactic, Technique
| sort - detectionCount
```

## Query 2
```cql
earliest=-365d ExternalApiType=Event_DetectionSummaryEvent 
| stats dc(AgentIdString) as uniqueEndpoints count(AgentIdString) as detectionCount by Tactic, Technique
| eval detectsPerEndpoint=round(detectionCount/uniqueEndpoints,0)
| sort - detectionCount
```

## Query 3
```cql
earliest=-365d ExternalApiType=Event_DetectionSummaryEvent 
| timechart count(AgentIdString) as detectionCount by Tactic span=1month
| sort + _time
```

## Query 4
```cql
earliest=-7d@d ExternalApiType=Event_DetectionSummaryEvent 
| timechart count(AgentIdString) as detectionCount by Tactic span=1d
| sort + _time
```

## Query 5
```cql
earliest=-1month ExternalApiType=Event_DetectionSummaryEvent 
| timechart count(AgentIdString) as detectionCount by Tactic span=1w
| sort + _time
```

## Query 6
```cql
earliest=-1month ExternalApiType=Event_DetectionSummaryEvent MachineDomain="acme.co"
| timechart count(AgentIdString) as detectionCount by Tactic span=1w
| sort + _time
```
