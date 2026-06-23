---
title: "PSFalcon, Bulk RTR Queuing, and STDOUT Redirection to LogScale"
date: 2022-11-03
author: "Andrew-CS"
source_url: "https://www.reddit.com/r/crowdstrike/comments/yl8hv8/20221103_cool_query_friday_psfalcon_bulk_rtr/"
mitre: []
series: Cool Query Friday
---

# PSFalcon, Bulk RTR Queuing, and STDOUT Redirection to LogScale

> Source: [https://www.reddit.com/r/crowdstrike/comments/yl8hv8/20221103_cool_query_friday_psfalcon_bulk_rtr/](https://www.reddit.com/r/crowdstrike/comments/yl8hv8/20221103_cool_query_friday_psfalcon_bulk_rtr/) — by Andrew-CS (CrowdStrike) — 2022-11-03

Welcome to our fifty-second installment of [Cool Query Friday](https://www.reddit.com/r/crowdstrike/collection/8016c539-c284-442c-9726-6bc05053d7a9/). The format will be: (1) description of what we're doing (2) walk through of each step (3) application in the wild.

## Query 1
```cql
Get-FalconHost -Filter "platform_name:'Windows'" -All | Invoke-FalconRtr -Command runscript -Argument "-CloudFile='list-browser-extensions'" -QueueOffline $true
```

## Query 2
```cql
| format(format="%s | %s | %s", field=[Name,  Version, Id], as="pluginDetails")
| groupBy([aid, host, Browser], function=stats(collect([pluginDetails])))
```

## Query 3
```cql
Get-FalconHost -Limit 100 -Detailed | Send-FalconEvent
```
