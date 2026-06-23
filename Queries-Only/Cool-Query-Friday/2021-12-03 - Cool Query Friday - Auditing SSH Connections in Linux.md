---
title: "Auditing SSH Connections in Linux"
date: 2021-12-03
author: "Andrew-CS"
source_url: "https://www.reddit.com/r/crowdstrike/comments/r80usb/20211203_cool_query_friday_auditing_ssh/"
mitre: []
series: Cool Query Friday
---

# Auditing SSH Connections in Linux

> Source: [https://www.reddit.com/r/crowdstrike/comments/r80usb/20211203_cool_query_friday_auditing_ssh/](https://www.reddit.com/r/crowdstrike/comments/r80usb/20211203_cool_query_friday_auditing_ssh/) — by Andrew-CS (CrowdStrike) — 2021-12-03

Welcome to our thirty-first installment of [Cool Query Friday](https://www.reddit.com/r/crowdstrike/collection/8016c539-c284-442c-9726-6bc05053d7a9/). The format will be: (1) description of what we're doing (2) walk though of each step (3) application in the wild.

## Query 1
```cql
event_platform=lin event_simpleName=CriticalEnvironmentVariableChanged, EnvironmentVariableName IN (SSH_CONNECTION, USER) 
| eventstats list(EnvironmentVariableName) as EnvironmentVariableName,list(EnvironmentVariableValue) as EnvironmentVariableValue by aid, ContextProcessId_decimal
```

## Query 2
```cql
event_platform=lin event_simpleName=CriticalEnvironmentVariableChanged, EnvironmentVariableName IN (SSH_CONNECTION, USER) 
| eventstats list(EnvironmentVariableName) as EnvironmentVariableName,list(EnvironmentVariableValue) as EnvironmentVariableValue by aid, ContextProcessId_decimal
| eval tempData=mvzip(EnvironmentVariableName,EnvironmentVariableValue,":")
```

## Query 3
```cql
event_platform=lin event_simpleName=CriticalEnvironmentVariableChanged, EnvironmentVariableName IN (SSH_CONNECTION, USER) 
| eventstats list(EnvironmentVariableName) as EnvironmentVariableName,list(EnvironmentVariableValue) as EnvironmentVariableValue by aid, ContextProcessId_decimal
| eval tempData=mvzip(EnvironmentVariableName,EnvironmentVariableValue,":") 
| table ComputerName tempData
```

## Query 4
```cql
[...]
| rex field=tempData "SSH_CONNECTION\:((?<clientIP>\d+\.\d+\.\d+\.\d+)\s+(?<rPort>\d+)\s+(?<serverIP>\d+\.\d+\.\d+\.\d+)\s+(?<lPort>\d+))"
| rex field=tempData "USER\:(?<userName>.*)"
```

## Query 5
```cql
event_platform=lin event_simpleName=CriticalEnvironmentVariableChanged, EnvironmentVariableName IN (SSH_CONNECTION, USER) 
| eventstats list(EnvironmentVariableName) as EnvironmentVariableName,list(EnvironmentVariableValue) as EnvironmentVariableValue by aid, ContextProcessId_decimal
| eval tempData=mvzip(EnvironmentVariableName,EnvironmentVariableValue,":")
| rex field=tempData "SSH_CONNECTION\:((?<clientIP>\d+\.\d+\.\d+\.\d+)\s+(?<rPort>\d+)\s+(?<serverIP>\d+\.\d+\.\d+\.\d+)\s+(?<lPort>\d+))"
| rex field=tempData "USER\:(?<userName>.*)"
| where isnotnull(clientIP)
| table ComputerName userName serverIP lPort clientIP rPort
```

## Query 6
```cql
[...]
| iplocation clientIP
| lookup local=true aid_master aid OUTPUT Version as osVersion, Country as sshServerCountry
| fillnull City, Country, Region value="-"
```

## Query 7
```cql
[...]
| table _time aid ComputerName sshServerCountry osVersion serverIP lPort userName clientIP rPort City Region Country
| where isnotnull(userName)
| sort +ComputerName, +_time
```

## Query 8
```cql
event_platform=lin event_simpleName=CriticalEnvironmentVariableChanged, EnvironmentVariableName IN (SSH_CONNECTION, USER) 
| eventstats list(EnvironmentVariableName) as EnvironmentVariableName,list(EnvironmentVariableValue) as EnvironmentVariableValue by aid, ContextProcessId_decimal
| eval tempData=mvzip(EnvironmentVariableName,EnvironmentVariableValue,":")
| rex field=tempData "SSH_CONNECTION\:((?<clientIP>\d+\.\d+\.\d+\.\d+)\s+(?<rPort>\d+)\s+(?<serverIP>\d+\.\d+\.\d+\.\d+)\s+(?<lPort>\d+))"
| rex field=tempData "USER\:(?<userName>.*)"
| where isnotnull(clientIP)
| iplocation clientIP
| lookup local=true aid_master aid OUTPUT Version as osVersion, Country as sshServerCountry
| fillnull City, Country, Region value="-"
| table _time aid ComputerName sshServerCountry osVersion serverIP lPort userName clientIP rPort City Region Country
| where isnotnull(userName)
| sort +ComputerName, +_time
```

## Query 9
```cql
[...]
| search NOT Country IN ("-", "United States")
```

## Query 10
```cql
[...]
| search userName=root
```

## Query 11
```cql
[...]
| search NOT clientIP IN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.1)
```
