---
title: "User Added To Group"
date: 2021-06-18
author: "Andrew-CS"
source_url: "https://www.reddit.com/r/crowdstrike/comments/o2onsf/20210618_cool_query_friday_user_added_to_group/"
mitre: [T1098]
series: Cool Query Friday
---

# User Added To Group

> Source: [https://www.reddit.com/r/crowdstrike/comments/o2onsf/20210618_cool_query_friday_user_added_to_group/](https://www.reddit.com/r/crowdstrike/comments/o2onsf/20210618_cool_query_friday_user_added_to_group/) — by Andrew-CS (CrowdStrike) — 2021-06-18

Welcome to our fourteenth installment of [Cool Query Friday](https://www.reddit.com/r/crowdstrike/collection/8016c539-c284-442c-9726-6bc05053d7a9/). The format will be: (1) description of what we're doing (2) walk though of each step (3) application in the wild.

## Query 1
```cql
event_simpleName=UserAccountAddedToGroup 
| fields aid, ComputerName, ContextTimeStamp_decimal, DomainSid, GroupRid, LocalAddressIP4, UserRid, timestamp
```

## Query 2
```cql
event_simpleName=UserAccountAddedToGroup 
| fields aid, ComputerName, ContextTimeStamp_decimal, DomainSid, GroupRid, LocalAddressIP4, UserRid, timestamp
| eval GroupRid_dec=tonumber(ltrim(tostring(GroupRid), "0"), 16)
| eval UserRid_dec=tonumber(ltrim(tostring(UserRid), "0"), 16)
```

## Query 3
```cql
event_simpleName=UserAccountAddedToGroup 
| fields aid, ComputerName, ContextTimeStamp_decimal, DomainSid, GroupRid, LocalAddressIP4, UserRid, timestamp
| eval GroupRid_dec=tonumber(ltrim(tostring(GroupRid), "0"), 16)
| eval UserRid_dec=tonumber(ltrim(tostring(UserRid), "0"), 16)
| eval UserSid_readable=DomainSid. "-" .UserRid_dec
```

## Query 4
```cql
[...]
| lookup local=true usersid_username_win.csv UserSid_readable OUTPUT UserName
| lookup local=true grouprid_wingroup.csv GroupRid_dec OUTPUT WinGroup
```

## Query 5
```cql
[...]
| fillnull value="Unknown" UserName, WinGroup
| stats values(ContextTimeStamp_decimal) as endpointTime values(timestamp) as cloudTime by UserSid_readable, UserName, WinGroup, GroupRid_dec, ComputerName, aid
| eval cloudTime=cloudTime/1000
| convert ctime(endpointTime) ctime(cloudTime)
| sort + endpointTime
```

## Query 6
```cql
event_simpleName=UserAccountAddedToGroup 
| fields aid, ComputerName, ContextTimeStamp_decimal, DomainSid, GroupRid, LocalAddressIP4, UserRid, timestamp
| eval GroupRid_dec=tonumber(ltrim(tostring(GroupRid), "0"), 16)
| eval UserRid_dec=tonumber(ltrim(tostring(UserRid), "0"), 16)
| eval UserSid_readable=DomainSid. "-" .UserRid_dec
| lookup local=true usersid_username_win.csv UserSid_readable OUTPUT UserName
| lookup local=true grouprid_wingroup.csv GroupRid_dec OUTPUT WinGroup
| fillnull value="Unknown" UserName, WinGroup
| stats values(ContextTimeStamp_decimal) as endpointTime values(timestamp) as cloudTime by UserSid_readable, UserName, WinGroup, GroupRid_dec, ComputerName, aid
| eval cloudTime=cloudTime/1000
| convert ctime(endpointTime) ctime(cloudTime)
| sort + endpointTime
```

## Query 7
```cql
event_simpleName=UserAccountAddedToGroup 
| fields aid, ComputerName, ContextTimeStamp_decimal, DomainSid, GroupRid, LocalAddressIP4, UserRid, timestamp
| eval GroupRid_dec=tonumber(ltrim(tostring(GroupRid), "0"), 16)
| eval UserRid_dec=tonumber(ltrim(tostring(UserRid), "0"), 16)
| eval UserSid_readable=DomainSid. "-" .UserRid_dec
| lookup local=true usersid_username_win.csv UserSid_readable OUTPUT UserName
| lookup local=true grouprid_wingroup.csv GroupRid_dec OUTPUT WinGroup
| fillnull value="Unknown" UserName, WinGroup
| stats dc(UserSid_readable) as userAccountsAdded values(WinGroup) as windowsGroupsManipulated values(GroupRid_dec) as groupRIDs by ComputerName, aid
| eval cloudTime=cloudTime/1000
| convert ctime(endpointTime) ctime(cloudTime)
| sort + endpointTime
```
