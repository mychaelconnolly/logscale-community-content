---
title: "Size and case Statements"
date: 2024-02-02
author: "Andrew-CS"
source_url: "https://www.reddit.com/r/crowdstrike/comments/1ah8sn1/20240202_cool_query_friday_size_and_case/"
mitre: []
series: Cool Query Friday
---

# Size and case Statements

> Source: [https://www.reddit.com/r/crowdstrike/comments/1ah8sn1/20240202_cool_query_friday_size_and_case/](https://www.reddit.com/r/crowdstrike/comments/1ah8sn1/20240202_cool_query_friday_size_and_case/) — by Andrew-CS (CrowdStrike) — 2024-02-02

Welcome to our seventy-third installment of Cool Query Friday. The format will be: (1) description of what we're doing (2) walk through of each step (3) application in the wild.

## Query 1
```cql
#event_simpleName=/FileWritten$/ FilePath=/(\\|\/)Downloads(\\|\/)/
```

## Query 2
```cql
| case {
    Size<1024 | SizeCommon:=format("%,.2f Bytes",field=["Size"]);
    *;
}
```

## Query 3
```cql
| case {
    Size>=1024 | SizeCommon:=unit:convert(Size, to=k) | format("%,.2f KB",field=["SizeCommon"], as="SizeCommon");
    Size<1024 | SizeCommon:=format("%,.2f Bytes",field=["Size"]);
    *;
}
```

## Query 4
```cql
| case {
    Size>=1048576| SizeCommon:=unit:convert(Size, to=M) | format("%,.2f MB",field=["SizeCommon"], as="SizeCommon");
    Size>=1024 | SizeCommon:=unit:convert(Size, to=k) | format("%,.2f KB",field=["SizeCommon"], as="SizeCommon");
    Size<1024 | SizeCommon:=format("%,.2f Bytes",field=["Size"]);
    *;
}
```

## Query 5
```cql
| case {
    Size>=1073741824 | SizeCommon:=unit:convert(Size, to=G) | format("%,.2f GB",field=["SizeCommon"], as="SizeCommon");
    Size>=1048576| SizeCommon:=unit:convert(Size, to=M) | format("%,.2f MB",field=["SizeCommon"], as="SizeCommon");
    Size>=1024 | SizeCommon:=unit:convert(Size, to=k) | format("%,.2f KB",field=["SizeCommon"], as="SizeCommon");
    Size<1024 | SizeCommon:=format("%,.2f Bytes",field=["Size"]);
    *;
}
```

## Query 6
```cql
| case {
    Size>=1099511627776 | SizeCommon:=unit:convert(SumSize, to=T) | format("%,.2f TB",field=["SizeCommon"], as="SizeCommon");
    Size>=1073741824 | SizeCommon:=unit:convert(Size, to=G) | format("%,.2f GB",field=["SizeCommon"], as="SizeCommon");
    Size>=1048576| SizeCommon:=unit:convert(Size, to=M) | format("%,.2f MB",field=["SizeCommon"], as="SizeCommon");
    Size>=1024 | SizeCommon:=unit:convert(Size, to=k) | format("%,.2f KB",field=["SizeCommon"], as="SizeCommon");
    Size<1024 | SizeCommon:=format("%,.2f Bytes",field=["Size"]);
    *;
}
```

## Query 7
```cql
#event_simpleName=/FileWritten$/ FilePath=/(\\|\/)Downloads(\\|\/)/
| case {
    Size>=1099511627776 | SizeCommon:=unit:convert(SumSize, to=T) | format("%,.2f TB",field=["SizeCommon"], as="SizeCommon");
    Size>=1073741824 | SizeCommon:=unit:convert(Size, to=G) | format("%,.2f GB",field=["SizeCommon"], as="SizeCommon");
    Size>=1048576| SizeCommon:=unit:convert(Size, to=M) | format("%,.2f MB",field=["SizeCommon"], as="SizeCommon");
    Size>=1024 | SizeCommon:=unit:convert(Size, to=k) | format("%,.2f KB",field=["SizeCommon"], as="SizeCommon");
    Size<1024 | SizeCommon:=format("%,.2f Bytes",field=["Size"]);
    *;
}
| select([aid, ComputerName, FileName, Size, SizeCommon, FilePath])
```

## Query 8
```cql
| TargetFileName=/(\\Device\\HarddiskVolume\d+)?(?<ShortFile>.+$)/
| ShortFile:=format(format="%s (%s)", field=[ShortFile, SizeCommon])
```

## Query 9
```cql
| groupBy([aid, ComputerName], function=([count(aid, as=TotalWrites), collect([ShortFile])]))
```

## Query 10
```cql
| groupBy([aid, ComputerName], function=([count(aid, as=TotalWrites), sum(Size, as=TotalWritten), collect([ShortFile])]))
```

## Query 11
```cql
#event_simpleName=/FileWritten$/ FilePath=/(\\|\/)Downloads(\\|\/)/
| case {
    Size>=1099511627776 | SizeCommon:=unit:convert(SumSize, to=T) | format("%,.2f TB",field=["SizeCommon"], as="SizeCommon");
    Size>=1073741824 | SizeCommon:=unit:convert(Size, to=G) | format("%,.2f GB",field=["SizeCommon"], as="SizeCommon");
    Size>=1048576| SizeCommon:=unit:convert(Size, to=M) | format("%,.2f MB",field=["SizeCommon"], as="SizeCommon");
    Size>=1024 | SizeCommon:=unit:convert(Size, to=k) | format("%,.2f KB",field=["SizeCommon"], as="SizeCommon");
    Size<1024 | SizeCommon:=format("%,.2f Bytes",field=["Size"]);
    *;
}
| TargetFileName=/(\\Device\\HarddiskVolume\d+)?(?<ShortFile>.+$)/
| ShortFile:=format(format="%s (%s)", field=[ShortFile, SizeCommon])
| groupBy([aid, ComputerName], function=([count(aid, as=TotalWrites), sum(Size, as=TotalWritten), collect([ShortFile])]), limit=max)
| sort(order=desc, TotalWritten, limit=200)
```
