---
title: "Hunting AI Tools, Models, Services, Agents, and SDKs with Falcon for IT"
date: 2026-04-24
author: "Andrew-CS"
source_url: "https://www.reddit.com/r/crowdstrike/comments/1suff2t/20260424_cool_query_friday_hunting_ai_tools/"
mitre: []
series: Cool Query Friday
---

# Hunting AI Tools, Models, Services, Agents, and SDKs with Falcon for IT

> Source: [https://www.reddit.com/r/crowdstrike/comments/1suff2t/20260424_cool_query_friday_hunting_ai_tools/](https://www.reddit.com/r/crowdstrike/comments/1suff2t/20260424_cool_query_friday_hunting_ai_tools/) — by Andrew-CS (CrowdStrike) — 2026-04-24

Welcome to our eighty-ninth installment of Cool Query Friday. The format will be: (1) description of what we're doing (2) walk through of each step (3) application in the wild.

```cql
| groupBy([aid, _tools_f, _models_f, _mcp_f, _sdks_f, _agents_f, _total], function=[], limit=max)
| match(file="aid_master_main.csv", field=[aid], column=aid)
| formatTime(format="%F %T %Z", as="FirstSeen", field=FirstSeen)
| formatTime(format="%F %T %Z", as="LastSeen", field=LastSeen)
```
