---
title: "Live from Fal.Con - Up-leveling Teams With Multipurpose, Text-box Driven Queries"
date: 2023-09-20
author: "Andrew-CS"
source_url: "https://www.reddit.com/r/crowdstrike/comments/16soii4/20230920_cool_query_friday_live_from_falcon/"
mitre: []
series: Cool Query Friday
---

# Live from Fal.Con - Up-leveling Teams With Multipurpose, Text-box Driven Queries

> Source: [https://www.reddit.com/r/crowdstrike/comments/16soii4/20230920_cool_query_friday_live_from_falcon/](https://www.reddit.com/r/crowdstrike/comments/16soii4/20230920_cool_query_friday_live_from_falcon/) — by Andrew-CS (CrowdStrike) — 2023-09-20

Welcome to our sixty-third installment of Cool Query Friday. The format will be: (1) description of what we're doing (2) walk through of each step (3) application in the wild.

## Query 1
```cql
// Get all execution and DNS request events
#event_simpleName=/^(ProcessRollup2|DnsRequest)$/
```

## Query 2
```cql
// Normalize Falcon PID value
| falconPID:=TargetProcessId
| falconPID:=ContextProcessId
```

## Query 3
```cql
// Use selfJoin to filter our instances on only one event happening
| selfJoinFilter(field=[aid, falconPID], where=[{#event_simpleName=ProcessRollup2}, {#event_simpleName=DnsRequest}])
```

## Query 4
```cql
// Aggregate to include desired fields
| groupBy([aid, falconPID], function=([collect([ComputerName, UserName, ParentBaseFileName, FileName, DomainName, CommandLine])]))
```

## Query 5
```cql
// Get specific events and provide option to specify host
#event_simpleName=/^(ProcessRollup2|DnsRequest)$/

// Normalize UPID value
| falconPID:=TargetProcessId
| falconPID:=ContextProcessId

// Use selfJoin to filter our instances on only one event happening
| selfJoinFilter(field=[aid, falconPID], where=[{#event_simpleName=ProcessRollup2}, {#event_simpleName=DnsRequest}])

// Aggregate to include desired fields
| groupBy([aid, falconPID], function=([collect([ComputerName, UserName, ParentBaseFileName, FileName, DomainName, CommandLine])]))
```

## Query 6
```cql
// Get specific events and provide option to specify host
#event_simpleName=/^(ProcessRollup2|DnsRequest)$/
```

## Query 7
```cql
// Get specific events and provide option to specify host
#event_simpleName=/^(ProcessRollup2|DnsRequest)$/

// Check for ComputerName
| ComputerName=~wildcard(?ComputerName, ignoreCase=true)
```

## Query 8
```cql
// Create case statement to manipulate fields based on event type and provide option to specify parameters based on event

| case {
    #event_simpleName=ProcessRollup2
       | UserName=~wildcard(?UserName, ignoreCase=true)
       | FileName=~wildcard(?FileName, ignoreCase=true)
       | ParentBaseFileName=~wildcard(?ParentBaseFileName, ignoreCase=true)
       | ExecutionChain:=format(format="%s\n\t└ %s (%s)", field=[ParentBaseFileName, FileName, RawProcessId]);
    #event_simpleName=DnsRequest
       | DomainName=~wildcard(?DomainName, ignoreCase=true);
}
```

## Query 9
```cql
| ExecutionChain:=format(format="%s\n\t└ %s (%s)", field=[ParentBaseFileName, FileName, RawProcessId]);
```

## Query 10
```cql
// Add link to graph explorer in US-2
| format("[Graph Explorer](https://falcon.us-2.crowdstrike.com/graphs/process-explorer/graph?id=pid:%s:%s)", field=["aid", "falconPID"], as="Graph Explorer")
```

## Query 11
```cql
// Get specific events and provide option to specify host
#event_simpleName=/^(ProcessRollup2|DnsRequest)$/

// Check for ComputerName
| ComputerName=~wildcard(?ComputerName, ignoreCase=true)

// Create case statement to manipulate fields based on event type and provide option to specify parameters based on file type
| case {
    #event_simpleName=ProcessRollup2
        | UserName=~wildcard(?UserName, ignoreCase=true)
        | FileName=~wildcard(?FileName, ignoreCase=true)
        | ParentBaseFileName=~wildcard(?ParentBaseFileName, ignoreCase=true)
        | ExecutionChain:=format(format="%s\n\t└ %s (%s)", field=[ParentBaseFileName, FileName, RawProcessId]);
    #event_simpleName=DnsRequest
        | DomainName=~wildcard(?DomainName, ignoreCase=true);
}

// Normalize UPID value
| falconPID:=TargetProcessId
| falconPID:=ContextProcessId

// Use selfJoin to filter our instances on only one event happening
| selfJoinFilter(field=[aid, falconPID], where=[{#event_simpleName=ProcessRollup2}, {#event_simpleName=DnsRequest}])

// Aggregate to include desired fields
| groupBy([aid, falconPID], function=([collect([ComputerName, UserName, ExecutionChain, DomainName, CommandLine])]))

// Add link to graph explorer in US-2
| format("[Graph Explorer](https://falcon.us-2.crowdstrike.com/graphs/process-explorer/graph?id=pid:%s:%s)", field=["aid", "falconPID"], as="Graph Explorer")
```
