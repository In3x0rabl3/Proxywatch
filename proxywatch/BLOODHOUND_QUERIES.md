# ProxyWatch BloodHound Queries

These queries match the current collector schema.

Important:
- Known destinations are stored as `(:Host)` via `SuspConnectsToHost*`.
- Unknown destinations are stored as `(:Endpoint)` via `SuspConnectsTo*`.
- If a query returns empty, run the schema check first to confirm relationship types in your current ingest.

## 1) Schema Check

```cypher
MATCH (n)
RETURN DISTINCT labels(n) AS labels
ORDER BY labels
```

```cypher
MATCH ()-[r]->()
RETURN DISTINCT type(r) AS rel
ORDER BY rel
```

## 2) Suspicious Process Inventory

```cypher
MATCH (h:Host)-[r:HasSuspProcess]->(p:Process)
RETURN h, r, p
```

```cypher
MATCH (u:User)-[r:UserHasSuspProcess]->(p:Process)
RETURN u, r, p
```

```cypher
MATCH (p:Process)
WHERE coalesce(p.role, "") STARTS WITH "susp-"
RETURN p
```

```cypher
MATCH (h:Host)-[r1:HasSuspProcess]->(p:Process)<-[r2:UserHasSuspProcess]-(u:User)
RETURN h, r1, p, r2, u
```

## 3) Host + Process + Any Destination (Works for Host or Endpoint Model)

```cypher
MATCH (h:Host)-[r1:HasSuspProcess]->(p:Process)-[r2:SuspConnectsToHostInternal|SuspConnectsToHostExternal|SuspConnectsToHostLoopback]->(d:Host)
RETURN h, r1, p, r2, d
UNION ALL
MATCH (h:Host)-[r1:HasSuspProcess]->(p:Process)-[r2:SuspConnectsToInternal|SuspConnectsToExternal|SuspConnectsToLoopback]->(d:Endpoint)
RETURN h, r1, p, r2, d
```

## 4) External Traffic

```cypher
MATCH (h:Host)-[r1:HasSuspProcess]->(p:Process)-[r2:SuspConnectsToHostExternal]->(d:Host)
RETURN h, r1, p, r2, d
UNION ALL
MATCH (h:Host)-[r1:HasSuspProcess]->(p:Process)-[r2:SuspConnectsToExternal]->(d:Endpoint)
RETURN h, r1, p, r2, d
```

```cypher
MATCH (u:User)-[r:UserSuspTrafficHostExternal]->(d:Host)
RETURN u, r, d
UNION ALL
MATCH (u:User)-[r:UserSuspTrafficExternal]->(d:Endpoint)
RETURN u, r, d
```

```cypher
MATCH (p:Process)-[r:SuspConnectsToHostExternal]->(d:Host)
WHERE coalesce(p.role, "") STARTS WITH "susp-"
RETURN p, r, d
UNION ALL
MATCH (p:Process)-[r:SuspConnectsToExternal]->(d:Endpoint)
WHERE coalesce(p.role, "") STARTS WITH "susp-"
RETURN p, r, d
```

```cypher
MATCH (p:Process)-[:SuspConnectsToHostExternal]->(d:Host)
WITH d, count(p) AS hits, collect(p) AS procs
WHERE hits > 1
UNWIND procs AS p
RETURN p, d
UNION ALL
MATCH (p:Process)-[:SuspConnectsToExternal]->(d:Endpoint)
WITH d, count(p) AS hits, collect(p) AS procs
WHERE hits > 1
UNWIND procs AS p
RETURN p, d
```

## 5) Internal Traffic

```cypher
MATCH (h:Host)-[r1:HasSuspProcess]->(p:Process)-[r2:SuspConnectsToHostInternal]->(d:Host)
RETURN h, r1, p, r2, d
UNION ALL
MATCH (h:Host)-[r1:HasSuspProcess]->(p:Process)-[r2:SuspConnectsToInternal]->(d:Endpoint)
RETURN h, r1, p, r2, d
```

```cypher
MATCH (u:User)-[r:UserSuspTrafficHostInternal]->(d:Host)
RETURN u, r, d
UNION ALL
MATCH (u:User)-[r:UserSuspTrafficInternal]->(d:Endpoint)
RETURN u, r, d
```

```cypher
MATCH (p:Process)-[r:SuspConnectsToHostInternal]->(d:Host)
WHERE coalesce(p.role, "") STARTS WITH "susp-"
RETURN p, r, d
UNION ALL
MATCH (p:Process)-[r:SuspConnectsToInternal]->(d:Endpoint)
WHERE coalesce(p.role, "") STARTS WITH "susp-"
RETURN p, r, d
```

```cypher
MATCH (p:Process)-[:SuspConnectsToHostInternal]->(d:Host)
WITH d, count(p) AS hits, collect(p) AS procs
WHERE hits > 1
UNWIND procs AS p
RETURN p, d
UNION ALL
MATCH (p:Process)-[:SuspConnectsToInternal]->(d:Endpoint)
WITH d, count(p) AS hits, collect(p) AS procs
WHERE hits > 1
UNWIND procs AS p
RETURN p, d
```

## 6) Loopback Traffic

```cypher
MATCH (p:Process)-[r:SuspConnectsToHostLoopback]->(d:Host)
WHERE coalesce(p.role, "") STARTS WITH "susp-"
RETURN p, r, d
UNION ALL
MATCH (p:Process)-[r:SuspConnectsToLoopback]->(d:Endpoint)
WHERE coalesce(p.role, "") STARTS WITH "susp-"
RETURN p, r, d
```

## 7) Local Endpoint Chains

```cypher
MATCH (h:Host)-[r1:HostHasLocalEndpoint]->(le:Endpoint)-[r2:LocalEndpointUsedBySuspProcess]->(p:Process)
RETURN h, r1, le, r2, p
```

```cypher
MATCH (h:Host)-[r1:HostHasLocalEndpoint]->(le:Endpoint)-[r2:LocalEndpointConnectsToHostExternal]->(d:Host)
RETURN h, r1, le, r2, d
UNION ALL
MATCH (h:Host)-[r1:HostHasLocalEndpoint]->(le:Endpoint)-[r2:LocalEndpointConnectsToExternal]->(d:Endpoint)
RETURN h, r1, le, r2, d
```

```cypher
MATCH (h:Host)-[r1:HostHasLocalEndpoint]->(le:Endpoint)-[r2:LocalEndpointConnectsToHostInternal]->(d:Host)
RETURN h, r1, le, r2, d
UNION ALL
MATCH (h:Host)-[r1:HostHasLocalEndpoint]->(le:Endpoint)-[r2:LocalEndpointConnectsToInternal]->(d:Endpoint)
RETURN h, r1, le, r2, d
```

```cypher
MATCH (h:Host)-[r1:HostHasLocalEndpoint]->(le:Endpoint)-[r2:LocalEndpointUsedBySuspProcess]->(p:Process)-[r3:SuspConnectsToHostExternal]->(d:Host)
RETURN h, r1, le, r2, p, r3, d
UNION ALL
MATCH (h:Host)-[r1:HostHasLocalEndpoint]->(le:Endpoint)-[r2:LocalEndpointUsedBySuspProcess]->(p:Process)-[r3:SuspConnectsToExternal]->(d:Endpoint)
RETURN h, r1, le, r2, p, r3, d
```

```cypher
MATCH (h:Host)-[r1:HostHasLocalEndpoint]->(le:Endpoint)-[r2:LocalEndpointUsedBySuspProcess]->(p:Process)-[r3:SuspConnectsToHostInternal]->(d:Host)
RETURN h, r1, le, r2, p, r3, d
UNION ALL
MATCH (h:Host)-[r1:HostHasLocalEndpoint]->(le:Endpoint)-[r2:LocalEndpointUsedBySuspProcess]->(p:Process)-[r3:SuspConnectsToInternal]->(d:Endpoint)
RETURN h, r1, le, r2, p, r3, d
```

## 8) Host Pivots

```cypher
MATCH (h:Host)-[r1:HasSuspProcess]->(p:Process)-[r2:SuspConnectsToHostInternal|SuspConnectsToHostExternal|SuspConnectsToHostLoopback]->(h2:Host)
RETURN h, r1, p, r2, h2
```

```cypher
MATCH (h:Host)-[r:HostHasIP]->(hip:Host)
RETURN h, r, hip
```

```cypher
MATCH (h1:Host)-[:HasSuspProcess]->(p1:Process)-[r1:SuspConnectsToHostInternal|SuspConnectsToHostExternal|SuspConnectsToHostLoopback]->(h2:Host)
MATCH (h2)-[:HasSuspProcess]->(p2:Process)-[r2:SuspConnectsToHostInternal|SuspConnectsToHostExternal|SuspConnectsToHostLoopback]->(h3:Host)
RETURN h1, p1, r1, h2, p2, r2, h3
```

## 9) Role-Specific

```cypher
MATCH (p:Process)-[r:SuspConnectsToHostInternal|SuspConnectsToHostExternal|SuspConnectsToHostLoopback]->(d:Host)
WHERE p.role = "susp-beacon"
RETURN p, r, d
UNION ALL
MATCH (p:Process)-[r:SuspConnectsToInternal|SuspConnectsToExternal|SuspConnectsToLoopback]->(d:Endpoint)
WHERE p.role = "susp-beacon"
RETURN p, r, d
```

```cypher
MATCH (p:Process)-[r:SuspConnectsToHostInternal|SuspConnectsToHostExternal|SuspConnectsToHostLoopback]->(d:Host)
WHERE p.role = "susp-tun"
RETURN p, r, d
UNION ALL
MATCH (p:Process)-[r:SuspConnectsToInternal|SuspConnectsToExternal|SuspConnectsToLoopback]->(d:Endpoint)
WHERE p.role = "susp-tun"
RETURN p, r, d
```
