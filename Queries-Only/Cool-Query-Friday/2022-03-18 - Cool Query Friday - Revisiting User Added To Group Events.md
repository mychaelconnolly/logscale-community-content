---
title: "Revisiting User Added To Group Events"
date: 2022-03-18
author: "Andrew-CS"
source_url: "https://www.reddit.com/r/crowdstrike/comments/th06gy/20220318_cool_query_friday_revisiting_user_added/"
mitre: []
series: Cool Query Friday
---

# Revisiting User Added To Group Events

> Source: [https://www.reddit.com/r/crowdstrike/comments/th06gy/20220318_cool_query_friday_revisiting_user_added/](https://www.reddit.com/r/crowdstrike/comments/th06gy/20220318_cool_query_friday_revisiting_user_added/) — by Andrew-CS (CrowdStrike) — 2022-03-18

Welcome to our fortieth(!!) installment of [Cool Query Friday](https://www.reddit.com/r/crowdstrike/collection/8016c539-c284-442c-9726-6bc05053d7a9/). The format will be: (1) description of what we're doing (2) walk through of each step (3) application in the wild.

## Query 1
```cql
[...]
| eval falconPID=coalesce(TargetProcessId_decimal, RpcClientProcessId_decimal)
This takes the value of TargetProcessId_decimal, which exists in ProcessRollup2 events, and the value RpcClientProcessId_decimal, which exists in UserAccountAddedToGroup events, and makes a new variable named falconPID.
```

## Query 2
```cql
[...]
| rename UserName as responsibleUserName
| rename UserSid_readable as responsibleUserSID
```

## Query 3
```cql
[...]
| eval GroupRid_dec=tonumber(ltrim(tostring(GroupRid), "0"), 16)
| eval UserRid_dec=tonumber(ltrim(tostring(UserRid), "0"), 16)
| eval UserSid_readable=DomainSid. "-" .UserRid_dec
```

## Query 4
```cql
[...]
| lookup local=true userinfo.csv UserSid_readable OUTPUT UserName
| lookup local=true grouprid_wingroup.csv GroupRid_dec OUTPUT WinGroup
| fillnull value="-" UserName responsibleUserName
```

## Query 5
```cql
[...]
| stats dc(event_simpleName) as eventCount, values(ProcessStartTime_decimal) as processStartTime, values(FileName) as responsibleFile, values(CommandLine) as responsibleCmdLine, values(responsibleUserSID) as responsibleUserSID, values(responsibleUserName) as responsibleUserName, values(WinGroup) as windowsGroupName, values(GroupRid_dec) as windowsGroupRID, values(UserName) as addedUserName, values(UserSid_readable) as addedUserSID by aid, falconPID
| where eventCount>1
```

## Query 6
```cql
(index=main sourcetype=UserAccountAddedToGroup* event_platform=win event_simpleName=UserAccountAddedToGroup) OR (index=main sourcetype=ProcessRollup2* event_platform=win event_simpleName=ProcessRollup2)
| eval falconPID=coalesce(TargetProcessId_decimal, RpcClientProcessId_decimal)
| rename UserName as responsibleUserName
| rename UserSid_readable as responsibleUserSID
| eval GroupRid_dec=tonumber(ltrim(tostring(GroupRid), "0"), 16)
| eval UserRid_dec=tonumber(ltrim(tostring(UserRid), "0"), 16)
| eval UserSid_readable=DomainSid. "-" .UserRid_dec
| lookup local=true userinfo.csv UserSid_readable OUTPUT UserName
| lookup local=true grouprid_wingroup.csv GroupRid_dec OUTPUT WinGroup
| fillnull value="-" UserName responsibleUserName
| stats dc(event_simpleName) as eventCount, values(ProcessStartTime_decimal) as processStartTime, values(FileName) as responsibleFile, values(CommandLine) as responsibleCmdLine, values(responsibleUserSID) as responsibleUserSID, values(responsibleUserName) as responsibleUserName, values(WinGroup) as windowsGroupName, values(GroupRid_dec) as windowsGroupRID, values(UserName) as addedUserName, values(UserSid_readable) as addedUserSID by aid, falconPID
| where eventCount>1
```

## Query 7
```cql
[...]
| eval ProcExplorer=case(falconPID!="","https://falcon.us-2.crowdstrike.com/investigate/process-explorer/" .aid. "/" . falconPID)
| convert ctime(processStartTime)
| table processStartTime, aid, responsibleUserSID, responsibleUserName, responsibleFile, responsibleCmdLine, addedUserSID, addedUserName, windowsGroupRID, windowsGroupName, ProcExplorer
```

## Query 8
```cql
(index=main sourcetype=UserAccountAddedToGroup* event_platform=win event_simpleName=UserAccountAddedToGroup) OR (index=main sourcetype=ProcessRollup2* event_platform=win event_simpleName=ProcessRollup2)
| eval falconPID=coalesce(TargetProcessId_decimal, RpcClientProcessId_decimal)
| rename UserName as responsibleUserName
| rename UserSid_readable as responsibleUserSID
| eval GroupRid_dec=tonumber(ltrim(tostring(GroupRid), "0"), 16)
| eval UserRid_dec=tonumber(ltrim(tostring(UserRid), "0"), 16)
| eval UserSid_readable=DomainSid. "-" .UserRid_dec
| lookup local=true userinfo.csv UserSid_readable OUTPUT UserName
| lookup local=true grouprid_wingroup.csv GroupRid_dec OUTPUT WinGroup
| fillnull value="-" UserName responsibleUserName
| stats dc(event_simpleName) as eventCount, values(ProcessStartTime_decimal) as processStartTime, values(FileName) as responsibleFile, values(CommandLine) as responsibleCmdLine, values(responsibleUserSID) as responsibleUserSID, values(responsibleUserName) as responsibleUserName, values(WinGroup) as windowsGroupName, values(GroupRid_dec) as windowsGroupRID, values(UserName) as addedUserName, values(UserSid_readable) as addedUserSID by aid, falconPID
| where eventCount>1 
| eval ProcExplorer=case(falconPID!="","https://falcon.us-2.crowdstrike.com/investigate/process-explorer/" .aid. "/" . falconPID)
| convert ctime(processStartTime)
| table processStartTime, aid, responsibleUserSID, responsibleUserName, responsibleFile, responsibleCmdLine, addedUserSID, addedUserName, windowsGroupRID, windowsGroupName, ProcExplorer
```
