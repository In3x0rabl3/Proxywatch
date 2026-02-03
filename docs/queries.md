# ProxyWatch BloodHound Queries

Use these in the BloodHound Cypher tab. They return graph relationships (not just lists).

## Suspicious process inventory

1) Hosts → Susp processes
```cypher
MATCH (h:Host)-[r:HasSuspProcess]->(p:Process)
RETURN h, r, p
```

2) Users → Susp processes
```cypher
MATCH (u:User)-[r:UserHasSuspProcess]->(p:Process)
RETURN u, r, p
```

3) All susp processes
```cypher
MATCH (p:Process)
WHERE p.role STARTS WITH "susp-"
RETURN p
```

4) Hosts with susp processes and users
```cypher
MATCH (h:Host)-[r1:HasSuspProcess]->(p:Process)-[r2:UserHasSuspProcess]-(u:User)
RETURN h, r1, p, r2, u
```

## External traffic

5) Host → Process → External endpoint
```cypher
MATCH (h:Host)-[r1:HasSuspProcess]->(p:Process)-[r2:SuspConnectsToExternal]->(e:Endpoint)
RETURN h, r1, p, r2, e
```

6) User → External traffic
```cypher
MATCH (u:User)-[r:UserSuspTrafficExternal]->(e:Endpoint)
RETURN u, r, e
```

7) Susp processes with any external traffic
```cypher
MATCH (p:Process)-[r:SuspConnectsToExternal]->(e:Endpoint)
WHERE p.role STARTS WITH "susp-"
RETURN p, r, e
```

8) External endpoints with multiple susp processes
```cypher
MATCH (p:Process)-[r:SuspConnectsToExternal]->(e:Endpoint)
WITH e, count(p) AS hits, collect(p) AS procs
WHERE hits > 1
UNWIND procs AS p
RETURN p, e
```

## Host pivots (IP-backed hosts)

9) Host → Process → Remote host (any scope)
```cypher
MATCH (h:Host)-[r1:HasSuspProcess]->(p:Process)-[r2]->(h2:Host)
WHERE type(r2) STARTS WITH "SuspConnectsToHost"
RETURN h, r1, p, r2, h2
```

10) Host → Process → Internal host (lateral)
```cypher
MATCH (h:Host)-[r1:HasSuspProcess]->(p:Process)-[r2:SuspConnectsToHostInternal]->(h2:Host)
RETURN h, r1, p, r2, h2
```

11) Host name ↔ host IP links
```cypher
MATCH (h:Host)-[r:HostHasIP]->(hip:Host)
RETURN h, r, hip
```

12) Double pivot (host → process → host → process → host)
```cypher
MATCH (h1:Host)-[:HasSuspProcess]->(p1:Process)-[r1]->(hip:Host)
MATCH (h2:Host)-[:HostHasIP]->(hip)
MATCH (h2)-[:HasSuspProcess]->(p2:Process)-[r2]->(h3:Host)
WHERE type(r1) STARTS WITH "SuspConnectsToHost"
  AND type(r2) STARTS WITH "SuspConnectsToHost"
RETURN h1, p1, hip, h2, p2, h3
```

## Internal traffic

13) Host → Process → Internal endpoint
```cypher
MATCH (h:Host)-[r1:HasSuspProcess]->(p:Process)-[r2:SuspConnectsToInternal]->(e:Endpoint)
RETURN h, r1, p, r2, e
```

14) User → Internal traffic
```cypher
MATCH (u:User)-[r:UserSuspTrafficInternal]->(e:Endpoint)
RETURN u, r, e
```

15) Susp processes with any internal traffic
```cypher
MATCH (p:Process)-[r:SuspConnectsToInternal]->(e:Endpoint)
WHERE p.role STARTS WITH "susp-"
RETURN p, r, e
```

16) Internal endpoints contacted by multiple susp processes
```cypher
MATCH (p:Process)-[r:SuspConnectsToInternal]->(e:Endpoint)
WITH e, count(p) AS hits, collect(p) AS procs
WHERE hits > 1
UNWIND procs AS p
RETURN p, e
```

## Loopback traffic

17) Susp processes using loopback endpoints
```cypher
MATCH (p:Process)-[r:SuspConnectsToLoopback]->(e:Endpoint)
WHERE p.role STARTS WITH "susp-"
RETURN p, r, e
```

## Local endpoint chains

18) Host → LocalEndpoint → SuspProcess
```cypher
MATCH (h:Host)-[r1:HostHasLocalEndpoint]->(le:Endpoint)-[r2:LocalEndpointUsedBySuspProcess]->(p:Process)
RETURN h, r1, le, r2, p
```

19) Host → LocalEndpoint → External endpoint (full chain)
```cypher
MATCH (h:Host)-[r1:HostHasLocalEndpoint]->(le:Endpoint)-[r2:LocalEndpointConnectsToExternal]->(e:Endpoint)
RETURN h, r1, le, r2, e
```

20) Host → LocalEndpoint → Internal endpoint (full chain)
```cypher
MATCH (h:Host)-[r1:HostHasLocalEndpoint]->(le:Endpoint)-[r2:LocalEndpointConnectsToInternal]->(e:Endpoint)
RETURN h, r1, le, r2, e
```

21) Full chain with process context (external)
```cypher
MATCH (h:Host)-[r1:HostHasLocalEndpoint]->(le:Endpoint)
      -[r2:LocalEndpointUsedBySuspProcess]->(p:Process)
      -[r3:SuspConnectsToExternal]->(e:Endpoint)
RETURN h, r1, le, r2, p, r3, e
```

22) Full chain with process context (internal)
```cypher
MATCH (h:Host)-[r1:HostHasLocalEndpoint]->(le:Endpoint)
      -[r2:LocalEndpointUsedBySuspProcess]->(p:Process)
      -[r3:SuspConnectsToInternal]->(e:Endpoint)
RETURN h, r1, le, r2, p, r3, e
```

## Role-specific views

23) Susp-beacon only
```cypher
MATCH (p:Process)-[r]->(e:Endpoint)
WHERE p.role = "susp-beacon" AND type(r) STARTS WITH "SuspConnectsTo"
RETURN p, r, e
```

24) Susp-tun only
```cypher
MATCH (p:Process)-[r]->(e:Endpoint)
WHERE p.role = "susp-tun" AND type(r) STARTS WITH "SuspConnectsTo"
RETURN p, r, e
```
