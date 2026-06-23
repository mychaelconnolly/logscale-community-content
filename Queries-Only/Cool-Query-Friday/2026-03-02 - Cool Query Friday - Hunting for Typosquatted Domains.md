---
title: "Hunting for Typosquatted Domains"
date: 2026-03-02
author: "Dylan-CS"
source_url: "https://www.reddit.com/r/crowdstrike/comments/1rixd9d/20260302_cool_query_friday_hunting_for/"
mitre: []
series: Cool Query Friday
---

# Hunting for Typosquatted Domains

> Source: [https://www.reddit.com/r/crowdstrike/comments/1rixd9d/20260302_cool_query_friday_hunting_for/](https://www.reddit.com/r/crowdstrike/comments/1rixd9d/20260302_cool_query_friday_hunting_for/) — by Dylan-CS (CrowdStrike) — 2026-03-02

Welcome back to another installment of [Cool Query Friday](https://www.reddit.com/r/crowdstrike/?f=flair_name%3A%22CQF%22) (on a Monday). I’ll be your guest host for today’s session. As always, the format will be: (1) description of what we're doing (2) walk through of each step (3) application in the wild.

## Query 1
```cql
// Normalize input as a URI so we can reliably work with hostnames
| parseUri(DomainName, defaultBase="https://")

// Extract the registrable/base domain into base_domain (extend TLD list as needed)
| DomainName.host=/(?<base_domain>[-a-zA-Z0-9]+\.(?:co\.uk|com\.tr|com|net|org|edu|gov|io|co))$/
```

## Query 2
```cql
// Compare the observed base_domain against the provided reference domain
| text:editDistance(
    target=base_domain,
    reference="crowdstrike.com",
    maxDistance=10,
    ignoreCase=true,
    as=lev_dist)
```

## Query 3
```cql
// Remove exact matches (distance 0 means it is one of our legitimate reference domains)
| lev_dist != 0

// Keep only near matches for triage (tune as needed)
| lev_dist <=3
```

## Query 4
```cql
// Get DNS request telemetry from Falcon sensor
#event_simpleName=DnsRequest

// Normalize input as a URI so we can reliably work with hostnames
| parseUri(DomainName, defaultBase="https://")

// Extract the registrable/base domain into base_domain (extend TLD list as needed)
| DomainName.host=/(?<base_domain>[-a-zA-Z0-9]+\.(?:co\.uk|com\.tr|com|net|org|edu|gov|io|co))$/

// Compare the observed base_domain against the provided reference domain
| text:editDistance(
    target=base_domain,
    reference="crowdstrike.com",
    maxDistance=10,
    ignoreCase=true,
    as=lev_dist)

// Remove exact matches (distance 0 means it is one of our legitimate reference domains)
| lev_dist != 0

// Keep only near matches for triage (tune as needed)
| lev_dist <=3
```

## Query 5
```cql
// Compare the observed base_domain to multiple reference domains
| text:editDistanceAsArray(
    target=base_domain,
    references=["crowdstrike.com","servicenowservices.com"],
    maxDistance=10
)
```

## Query 6
```cql
// Split the _distance[] object array so each reference comparison becomes its own row
| split(_distance)

// Remove exact matches (distance 0 means it is one of our legitimate reference domains)
| _distance.distance != 0

// Keep only near matches for triage (tune as needed)
| _distance.distance <= 3
```

## Query 7
```cql
// Rename fields for clarity in the output
| Reference_Domain:=_distance.reference
| Observed_Domain:=base_domain
| lev_dist:=_distance.distance

// Output results and sort by closest match first
| groupBy([Observed_Domain,Reference_Domain,lev_dist], function=collect([DomainName,ComputerName,aid]), limit=max)
| sort(lev_dist, order=asc)

// Intelligence Graph; uncomment out one cloud
| rootURL := "https://falcon.crowdstrike.com/"
// | rootURL := "https://falcon.laggar.gcw.crowdstrike.com/"
// | rootURL := "https://falcon.eu-1.crowdstrike.com/"
// | rootURL := "https://falcon.us-2.crowdstrike.com/"
| format("[Link](%sinvestigate/dashboards/domain-search?isLive=false&sharedTime=true&start=7d&domain=*%s)", field=["rootURL", "Observed_Domain"], as="Domain Search")

| drop(rootURL)
```

## Query 8
```cql
// Get DNS request telemetry from Falcon sensor
#event_simpleName=DnsRequest

// Normalize input as a URI so we can reliably work with hostnames
| parseUri(DomainName, defaultBase="https://")

// Extract the registrable/base domain into base_domain (extend TLD list as needed)
| DomainName.host=/(?<base_domain>[-a-zA-Z0-9]+\.(?:co\.uk|com\.tr|com|net|org|edu|gov|io|co))$/

// Compare the observed base_domain to multiple reference domains
| text:editDistanceAsArray(
    target=base_domain,
    references=["crowdstrike.com","servicenowservices.com"],
    maxDistance=10
)

// Split the _distance[] object array so each reference comparison becomes its own row
| split(_distance)

// Remove exact matches (distance 0 means it is one of our legitimate reference domains)
| _distance.distance != 0

// Keep only near matches for triage (tune as needed)
| _distance.distance <= 3

// Rename fields for clarity in the output
| Reference_Domain:=_distance.reference
| Observed_Domain:=base_domain
| lev_dist:=_distance.distance

// Output results and sort by closest match first
| groupBy([Observed_Domain,Reference_Domain,lev_dist], function=collect([DomainName,ComputerName,aid]), limit=max)
| sort(lev_dist, order=asc)

// Intelligence Graph; uncomment out one cloud
| rootURL := "https://falcon.crowdstrike.com/"
// | rootURL := "https://falcon.laggar.gcw.crowdstrike.com/"
// | rootURL := "https://falcon.eu-1.crowdstrike.com/"
// | rootURL := "https://falcon.us-2.crowdstrike.com/"
| format("[Link](%sinvestigate/dashboards/domain-search?isLive=false&sharedTime=true&start=7d&domain=*%s)", field=["rootURL", "Observed_Domain"], as="Domain Search")

| drop(rootURL)
```
