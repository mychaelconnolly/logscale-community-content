---
title: "macOS, HostInfo, and System Preferences"
date: 2022-04-22
author: "Andrew-CS"
source_url: "https://www.reddit.com/r/crowdstrike/comments/u9f2z6/20220422_cool_query_friday_macos_hostinfo_and/"
mitre: []
series: Cool Query Friday
---

# macOS, HostInfo, and System Preferences

> Source: [https://www.reddit.com/r/crowdstrike/comments/u9f2z6/20220422_cool_query_friday_macos_hostinfo_and/](https://www.reddit.com/r/crowdstrike/comments/u9f2z6/20220422_cool_query_friday_macos_hostinfo_and/) — by Andrew-CS (CrowdStrike) — 2022-04-22

Welcome to our forty-third installment of [Cool Query Friday](https://www.reddit.com/r/crowdstrike/collection/8016c539-c284-442c-9726-6bc05053d7a9/). The format will be: (1) description of what we're doing (2) walk through of each step (3) application in the wild.

## Query 1
```cql
[...]
| where isnotnull(AnalyticsAndImprovementsIsSet_decimal)
| stats latest(AnalyticsAndImprovementsIsSet_decimal) as AnalyticsAndImprovementsIsSet, latest(ApplicationFirewallIsSet_decimal) as ApplicationFirewallIsSet, latest(AutoUpdate_decimal) as AutoUpdate, latest(FullDiskAccessForFalconIsSet_decimal) as FullDiskAccessForFalconIsSet, latest(FullDiskAccessForOthersIsSet_decimal) as FullDiskAccessForOthersIsSet, latest(GatekeeperIsSet_decimal) as GatekeeperIsSet, latest(InternetSharingIsSet_decimal) as InternetSharingIsSet, latest(PasswordRequiredIsSet_decimal) as PasswordRequiredIsSet, latest(RemoteLoginIsSet_decimal) as RemoteLoginIsSet, latest(SIPIsEnabled_decimal) as SIPIsEnabled, latest(StealthModeIsSet_decimal) as StealthModeIsSet by aid
```

## Query 2
```cql
[...]
|  eval remediationAnalytic=case(AnalyticsAndImprovementsIsSet=1, "Disable Analytics and Improvements in macOS")
```

## Query 3
```cql
[...]
|  eval remediationAnalytic=case(AnalyticsAndImprovementsIsSet=1, "Disable Analytics and Improvements in macOS")
|  eval remediationFirewall=case(ApplicationFirewallIsSet=0, "Enable Application Firewall")
|  eval remediationUpdate=case(AutoUpdate!=31, "Check macOS Update Settings")
|  eval remediationFalcon=case(FullDiskAccessForFalconIsSet=0, "Enable Full Disk Access for Falcon")
|  eval remediationGatekeeper=case(GatekeeperIsSet=0, "Enable macOS Gatekeeper")
|  eval remediationInternet=case(InternetSharingIsSet=1, "Disable Internet Sharing")
|  eval remediationPassword=case(PasswordRequiredIsSet=0, "Disable Automatic Logon")
|  eval remediationSSH=case(RemoteLoginIsSet=1, "Disable Remote Logon")
|  eval remediationSIP=case(SIPIsEnabled=0, "System Integrity Protection is disabled")
|  eval remediationStealth=case(StealthModeIsSet=0, "Enable Stealth Mode")
```

## Query 4
```cql
event_platform=mac sourcetype=HostInfo* event_simpleName=HostInfo 
| where isnotnull(AnalyticsAndImprovementsIsSet_decimal)
| stats latest(AnalyticsAndImprovementsIsSet_decimal) as AnalyticsAndImprovementsIsSet, latest(ApplicationFirewallIsSet_decimal) as ApplicationFirewallIsSet, latest(AutoUpdate_decimal) as AutoUpdate, latest(FullDiskAccessForFalconIsSet_decimal) as FullDiskAccessForFalconIsSet, latest(FullDiskAccessForOthersIsSet_decimal) as FullDiskAccessForOthersIsSet, latest(GatekeeperIsSet_decimal) as GatekeeperIsSet, latest(InternetSharingIsSet_decimal) as InternetSharingIsSet, latest(PasswordRequiredIsSet_decimal) as PasswordRequiredIsSet, latest(RemoteLoginIsSet_decimal) as RemoteLoginIsSet, latest(SIPIsEnabled_decimal) as SIPIsEnabled, latest(StealthModeIsSet_decimal) as StealthModeIsSet by aid
|  eval remediationAnalytic=case(AnalyticsAndImprovementsIsSet=1, "Disable Analytics and Improvements in macOS")
|  eval remediationFirewall=case(ApplicationFirewallIsSet=0, "Enable Application Firewall")
|  eval remediationUpdate=case(AutoUpdate!=31, "Check macOS Update Settings")
|  eval remediationFalcon=case(FullDiskAccessForFalconIsSet=0, "Enable Full Disk Access for Falcon")
|  eval remediationGatekeeper=case(GatekeeperIsSet=0, "Enable macOS Gatekeeper")
|  eval remediationInternet=case(InternetSharingIsSet=1, "Disable Internet Sharing")
|  eval remediationPassword=case(PasswordRequiredIsSet=0, "Disable Automatic Logon")
|  eval remediationSSH=case(RemoteLoginIsSet=1, "Disable Remote Logon")
|  eval remediationSIP=case(SIPIsEnabled=0, "System Integrity Protection is disabled")
|  eval remediationStealth=case(StealthModeIsSet=0, "Enable Stealth Mode")
```

## Query 5
```cql
[...]
|  eval macosRemediations=mvappend(remediationAnalytic, remediationFirewall, remediationUpdate, remediationFalcon, remediationGatekeeper, remediationInternet, remediationPassword, remediationSSH, remediationSIP, remediationStealth)
```

## Query 6
```cql
[...]
| lookup local=true aid_master aid OUTPUT HostHiddenStatus, ComputerName, SystemManufacturer, SystemProductName, Version, Timezone, AgentVersion
```

## Query 7
```cql
[...]
| search HostHiddenStatus=Visible
```

## Query 8
```cql
[...]
| table aid, ComputerName, SystemManufacturer, SystemProductName, Version, Timezone, AgentVersion, macosRemediations
```

## Query 9
```cql
[...]
| sort +ComputerName
| rename aid as "Falcon Agent ID", ComputerName as "Endpoint", SystemManufacturer as "System Maker", SystemProductName as "Product Name", Version as "OS", AgentVersion as "Falcon Version", macosRemediations as "Configuration Issues"
```

## Query 10
```cql
event_platform=mac sourcetype=HostInfo* event_simpleName=HostInfo 
| where isnotnull(AnalyticsAndImprovementsIsSet_decimal)
| stats latest(AnalyticsAndImprovementsIsSet_decimal) as AnalyticsAndImprovementsIsSet, latest(ApplicationFirewallIsSet_decimal) as ApplicationFirewallIsSet, latest(AutoUpdate_decimal) as AutoUpdate, latest(FullDiskAccessForFalconIsSet_decimal) as FullDiskAccessForFalconIsSet, latest(FullDiskAccessForOthersIsSet_decimal) as FullDiskAccessForOthersIsSet, latest(GatekeeperIsSet_decimal) as GatekeeperIsSet, latest(InternetSharingIsSet_decimal) as InternetSharingIsSet, latest(PasswordRequiredIsSet_decimal) as PasswordRequiredIsSet, latest(RemoteLoginIsSet_decimal) as RemoteLoginIsSet, latest(SIPIsEnabled_decimal) as SIPIsEnabled, latest(StealthModeIsSet_decimal) as StealthModeIsSet by aid
|  eval remediationAnalytic=case(AnalyticsAndImprovementsIsSet=1, "Disable Analytics and Improvements in macOS")
|  eval remediationFirewall=case(ApplicationFirewallIsSet=0, "Enable Application Firewall")
|  eval remediationUpdate=case(AutoUpdate!=31, "Check macOS Update Settings")
|  eval remediationFalcon=case(FullDiskAccessForFalconIsSet=0, "Enable Full Disk Access for Falcon")
|  eval remediationGatekeeper=case(GatekeeperIsSet=0, "Enable macOS Gatekeeper")
|  eval remediationInternet=case(InternetSharingIsSet=1, "Disable Internet Sharing")
|  eval remediationPassword=case(PasswordRequiredIsSet=0, "Disable Automatic Logon")
|  eval remediationSSH=case(RemoteLoginIsSet=1, "Disable Remote Logon")
|  eval remediationSIP=case(SIPIsEnabled=0, "System Integrity Protection is disabled")
|  eval remediationStealth=case(StealthModeIsSet=0, "Enable Stealth Mode")
|  eval macosRemediations=mvappend(remediationAnalytic, remediationFirewall, remediationUpdate, remediationFalcon, remediationGatekeeper, remediationInternet, remediationPassword, remediationSSH, remediationSIP, remediationStealth)
| lookup local=true aid_master aid OUTPUT HostHiddenStatus, ComputerName, SystemManufacturer, SystemProductName, Version, Timezone, AgentVersion
| search HostHiddenStatus=Visible
| table aid, ComputerName, SystemManufacturer, SystemProductName, Version, Timezone, AgentVersion, macosRemediations 
| sort +ComputerName
| rename aid as "Falcon Agent ID", ComputerName as "Endpoint", SystemManufacturer as "System Maker", SystemProductName as "Product Name", Version as "OS", AgentVersion as "Falcon Version", macosRemediations as "Configuration Issues"
```
