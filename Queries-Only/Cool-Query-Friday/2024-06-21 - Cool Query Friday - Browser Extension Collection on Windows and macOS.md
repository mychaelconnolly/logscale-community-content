---
title: "Browser Extension Collection on Windows and macOS"
date: 2024-06-21
author: "Andrew-CS"
source_url: "https://www.reddit.com/r/crowdstrike/comments/1dl3bo5/20240621_cool_query_friday_browser_extension/"
mitre: []
series: Cool Query Friday
---

# Browser Extension Collection on Windows and macOS

> Source: [https://www.reddit.com/r/crowdstrike/comments/1dl3bo5/20240621_cool_query_friday_browser_extension/](https://www.reddit.com/r/crowdstrike/comments/1dl3bo5/20240621_cool_query_friday_browser_extension/) — by Andrew-CS (CrowdStrike) — 2024-06-21

Welcome to our seventy-sixth installment of Cool Query Friday. The format will be: (1) description of what we're doing (2) walk through of each step (3) application in the wild.

## Query 1
```cql
#event_simpleName=InstalledBrowserExtension
| fieldstats()
```

## Query 2
```cql
#event_simpleName=InstalledBrowserExtension BrowserExtensionId!="no-extension-available"
| groupBy([event_platform, BrowserName, BrowserExtensionId, BrowserExtensionName], function=([count(aid, distinct=true, as=TotalEndpoints)]))
```

## Query 3
```cql
// Get browser extension event
#event_simpleName=InstalledBrowserExtension BrowserExtensionId!="no-extension-available"
// Aggregate by event_platform, BrowserName, ExtensionID and ExtensionName
| groupBy([event_platform, BrowserName, BrowserExtensionId, BrowserExtensionName], function=([count(aid, distinct=true, as=TotalEndpoints)]))
// Check to see if the extension is installed on fewer than 50 systems
| test(TotalEndpoints<50)
// Create a link to the Chrome Extension Store
| format("[See Extension](https://chromewebstore.google.com/detail/%s)", field=[BrowserExtensionId], as="Chrome Store Link")
// Sort in descending order
| sort(order=desc, TotalEndpoints, limit=1000)
// Convert the browser name from decimal to human-readable
| case{
BrowserName="3" | BrowserName:="Chrome";
BrowserName="4" | BrowserName:="Edge";
*;
}
```

## Query 4
```cql
// Get browser extension event
#event_simpleName=InstalledBrowserExtension BrowserExtensionId!="no-extension-available"
// Aggregate by BrowserName
| groupBy([BrowserExtensionName], function=([count(aid, distinct=true, as=TotalEndpoints)]))
| sort(TotalEndpoints, order=desc)
```

## Query 5
```cql
// Get browser extension event
#event_simpleName=InstalledBrowserExtension BrowserExtensionId!="no-extension-available"
// Look for string "vpn" in extension name
| BrowserExtensionName=/vpn/i
// Make a new field that includes the extension ID and Name
| Extension:=format(format="%s (%s)", field=[BrowserExtensionId, BrowserExtensionName])
// Aggregate by endpoint and browser profile
| groupBy([event_platform, aid, ComputerName, UserName, BrowserProfileId, BrowserName], function=([collect([Extension])]))
// Get unnecessary field
| drop([_count])
// Convert browser name from decimal to human readable
| case{
BrowserName="3" | BrowserName:="Chrome";
BrowserName="4" | BrowserName:="Edge";
*;
}
```

## Query 6
```cql
// Get browser extension event
#event_simpleName=InstalledBrowserExtension BrowserExtensionId!="no-extension-available"
// Look for side loaded extensions or extensions from third-party stores
| in(field="BrowserExtensionInstallMethod", values=[4,5])
// Make a new field that includes the extension ID and Name
| Extension:=format(format="%s (%s)", field=[BrowserExtensionId, BrowserExtensionName])
// Aggregate by endpoint and browser profile
| groupBy([event_platform, aid, ComputerName, UserName, BrowserProfileId, BrowserName, BrowserExtensionInstallMethod], function=([collect([Extension])]))
// Get unnecessary field
| drop([_count])
// Convert browser name from decimal to human readable
| case{
BrowserName="3" | BrowserName:="Chrome";
BrowserName="4" | BrowserName:="Edge";
*;
}
// Convert install method from decimal to human readable
| case{
BrowserExtensionInstallMethod="4" | BrowserExtensionInstallMethod:="Sideload";
BrowserExtensionInstallMethod="5" | BrowserExtensionInstallMethod:="Third-Party Store";
*;
}
```
