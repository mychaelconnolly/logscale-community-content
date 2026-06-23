---
title: "explain:asTable()"
date: 2026-03-20
author: "Andrew-CS"
source_url: "https://www.reddit.com/r/crowdstrike/comments/1ryw8kr/20260320_cool_query_friday_explainastable/"
mitre: []
series: Cool Query Friday
---

# explain:asTable()

> Source: [https://www.reddit.com/r/crowdstrike/comments/1ryw8kr/20260320_cool_query_friday_explainastable/](https://www.reddit.com/r/crowdstrike/comments/1ryw8kr/20260320_cool_query_friday_explainastable/) — by Andrew-CS (CrowdStrike) — 2026-03-20

Welcome to our [eighty-eighth](https://www.youtube.com/watch?v=HWoW-vX4HT8) installment of Cool Query Friday. The format will be: (1) description of what we're doing (2) walk through of each step (3) application in the wild.

```cql
#event_simpleName=ProcessRollup2 
| CommandLine=/\-(e(nc|ncodedcommand|ncoded)?)\s+/iF
| groupBy([ComputerName, event_platform], function=([count(CommandLine, distinct=true, as=uniqueCmdLines), count(aid, as=totalExecutions)]), limit=max)
```
