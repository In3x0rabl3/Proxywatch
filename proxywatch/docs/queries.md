# ProxyWatch BloodHound Queries (Role-Based Schema)

Use these in BloodHound Cypher tab. They return graph relationships (not just lists).

These are parser-safe: no `CASE`, no `type()`, no `STARTS WITH`/`ENDS WITH`.

## Suspicious process inventory (role-based)

1) Hosts → role-labeled processes
```cypher
MATCH (h:Host)-[r:SessionProcessOnHost|BeaconProcessOnHost|TunnelProcessOnHost|ListenerProcessOnHost|OutboundProcessOnHost|ProcessProcessOnHost]->(p:Process)
RETURN h, r, p
```

2) Users → role-labeled processes
```cypher
MATCH (u:User)-[r:UserSessionProcess|UserBeaconProcess|UserTunnelProcess|UserListenerProcess|UserOutboundProcess|UserProcessProcess]->(p:Process)
RETURN u, r, p
```

3) All role-labeled processes
```cypher
MATCH (:Host)-[:SessionProcessOnHost|BeaconProcessOnHost|TunnelProcessOnHost|ListenerProcessOnHost|OutboundProcessOnHost|ProcessProcessOnHost]->(p:Process)
RETURN DISTINCT p
```

4) Hosts with role-labeled processes and users
```cypher
MATCH (h:Host)-[r1:SessionProcessOnHost|BeaconProcessOnHost|TunnelProcessOnHost|ListenerProcessOnHost|OutboundProcessOnHost|ProcessProcessOnHost]->(p:Process)<-[r2:UserSessionProcess|UserBeaconProcess|UserTunnelProcess|UserListenerProcess|UserOutboundProcess|UserProcessProcess]-(u:User)
RETURN h, r1, p, r2, u
```

## External traffic

5) Host → Process → External endpoint
```cypher
MATCH (h:Host)-[r1:SessionProcessOnHost|BeaconProcessOnHost|TunnelProcessOnHost|ListenerProcessOnHost|OutboundProcessOnHost|ProcessProcessOnHost]->(p:Process)-[r2:SessionConnectsToExternal|BeaconConnectsToExternal|TunnelConnectsToExternal|ListenerConnectsToExternal|OutboundConnectsToExternal|ProcessConnectsToExternal]->(e:Endpoint)
RETURN h, r1, p, r2, e
```

6) User → External traffic
```cypher
MATCH (u:User)-[r:UserSessionTrafficExternal|UserBeaconTrafficExternal|UserTunnelTrafficExternal|UserListenerTrafficExternal|UserOutboundTrafficExternal|UserProcessTrafficExternal]->(e:Endpoint)
RETURN u, r, e
```

7) Role-labeled processes with any external traffic
```cypher
MATCH (p:Process)-[r:SessionConnectsToExternal|BeaconConnectsToExternal|TunnelConnectsToExternal|ListenerConnectsToExternal|OutboundConnectsToExternal|ProcessConnectsToExternal]->(e:Endpoint)
RETURN p, r, e
```

8) External endpoints with multiple role-labeled processes
```cypher
MATCH (p:Process)-[:SessionConnectsToExternal|BeaconConnectsToExternal|TunnelConnectsToExternal|ListenerConnectsToExternal|OutboundConnectsToExternal|ProcessConnectsToExternal]->(e:Endpoint)
WITH e, count(DISTINCT p) AS hits, collect(DISTINCT p) AS procs
WHERE hits > 1
UNWIND procs AS p
RETURN p, e
```

## Host pivots (IP-backed hosts)

9) Host → Process → Remote host (any scope)
```cypher
MATCH (h:Host)-[r1:SessionProcessOnHost|BeaconProcessOnHost|TunnelProcessOnHost|ListenerProcessOnHost|OutboundProcessOnHost|ProcessProcessOnHost]->(p:Process)-[r2:SessionConnectsToHostExternal|SessionConnectsToHostInternal|SessionConnectsToHostLoopback|BeaconConnectsToHostExternal|BeaconConnectsToHostInternal|BeaconConnectsToHostLoopback|TunnelConnectsToHostExternal|TunnelConnectsToHostInternal|TunnelConnectsToHostLoopback|ListenerConnectsToHostExternal|ListenerConnectsToHostInternal|ListenerConnectsToHostLoopback|OutboundConnectsToHostExternal|OutboundConnectsToHostInternal|OutboundConnectsToHostLoopback|ProcessConnectsToHostExternal|ProcessConnectsToHostInternal|ProcessConnectsToHostLoopback]->(h2:Host)
RETURN h, r1, p, r2, h2
```

10) Host → Process → Internal host (lateral)
```cypher
MATCH (h:Host)-[r1:SessionProcessOnHost|BeaconProcessOnHost|TunnelProcessOnHost|ListenerProcessOnHost|OutboundProcessOnHost|ProcessProcessOnHost]->(p:Process)-[r2:SessionConnectsToHostInternal|BeaconConnectsToHostInternal|TunnelConnectsToHostInternal|ListenerConnectsToHostInternal|OutboundConnectsToHostInternal|ProcessConnectsToHostInternal]->(h2:Host)
RETURN h, r1, p, r2, h2
```

11) Host name ↔ host IP links
```cypher
MATCH (h:Host)-[r:HostHasIP]->(hip:Host)
RETURN h, r, hip
```

12) Double pivot (host → process → host → process → host)
```cypher
MATCH (h1:Host)-[:SessionProcessOnHost|BeaconProcessOnHost|TunnelProcessOnHost|ListenerProcessOnHost|OutboundProcessOnHost|ProcessProcessOnHost]->(p1:Process)-[r1:SessionConnectsToHostExternal|SessionConnectsToHostInternal|SessionConnectsToHostLoopback|BeaconConnectsToHostExternal|BeaconConnectsToHostInternal|BeaconConnectsToHostLoopback|TunnelConnectsToHostExternal|TunnelConnectsToHostInternal|TunnelConnectsToHostLoopback|ListenerConnectsToHostExternal|ListenerConnectsToHostInternal|ListenerConnectsToHostLoopback|OutboundConnectsToHostExternal|OutboundConnectsToHostInternal|OutboundConnectsToHostLoopback|ProcessConnectsToHostExternal|ProcessConnectsToHostInternal|ProcessConnectsToHostLoopback]->(hip:Host)
MATCH (h2:Host)-[:HostHasIP]->(hip)
MATCH (h2)-[:SessionProcessOnHost|BeaconProcessOnHost|TunnelProcessOnHost|ListenerProcessOnHost|OutboundProcessOnHost|ProcessProcessOnHost]->(p2:Process)-[r2:SessionConnectsToHostExternal|SessionConnectsToHostInternal|SessionConnectsToHostLoopback|BeaconConnectsToHostExternal|BeaconConnectsToHostInternal|BeaconConnectsToHostLoopback|TunnelConnectsToHostExternal|TunnelConnectsToHostInternal|TunnelConnectsToHostLoopback|ListenerConnectsToHostExternal|ListenerConnectsToHostInternal|ListenerConnectsToHostLoopback|OutboundConnectsToHostExternal|OutboundConnectsToHostInternal|OutboundConnectsToHostLoopback|ProcessConnectsToHostExternal|ProcessConnectsToHostInternal|ProcessConnectsToHostLoopback]->(h3:Host)
RETURN h1, p1, hip, h2, p2, h3
```

## Internal traffic

13) Host → Process → Internal endpoint
```cypher
MATCH (h:Host)-[r1:SessionProcessOnHost|BeaconProcessOnHost|TunnelProcessOnHost|ListenerProcessOnHost|OutboundProcessOnHost|ProcessProcessOnHost]->(p:Process)-[r2:SessionConnectsToInternal|BeaconConnectsToInternal|TunnelConnectsToInternal|ListenerConnectsToInternal|OutboundConnectsToInternal|ProcessConnectsToInternal]->(e:Endpoint)
RETURN h, r1, p, r2, e
```

14) User → Internal traffic
```cypher
MATCH (u:User)-[r:UserSessionTrafficInternal|UserBeaconTrafficInternal|UserTunnelTrafficInternal|UserListenerTrafficInternal|UserOutboundTrafficInternal|UserProcessTrafficInternal]->(e:Endpoint)
RETURN u, r, e
```

15) Role-labeled processes with any internal traffic
```cypher
MATCH (p:Process)-[r:SessionConnectsToInternal|BeaconConnectsToInternal|TunnelConnectsToInternal|ListenerConnectsToInternal|OutboundConnectsToInternal|ProcessConnectsToInternal]->(e:Endpoint)
RETURN p, r, e
```

16) Internal endpoints contacted by multiple role-labeled processes
```cypher
MATCH (p:Process)-[:SessionConnectsToInternal|BeaconConnectsToInternal|TunnelConnectsToInternal|ListenerConnectsToInternal|OutboundConnectsToInternal|ProcessConnectsToInternal]->(e:Endpoint)
WITH e, count(DISTINCT p) AS hits, collect(DISTINCT p) AS procs
WHERE hits > 1
UNWIND procs AS p
RETURN p, e
```

## Loopback traffic

17) Role-labeled processes using loopback endpoints
```cypher
MATCH (p:Process)-[r:SessionConnectsToLoopback|BeaconConnectsToLoopback|TunnelConnectsToLoopback|ListenerConnectsToLoopback|OutboundConnectsToLoopback|ProcessConnectsToLoopback]->(e:Endpoint)
RETURN p, r, e
```

## Local endpoint chains

18) Host → LocalEndpoint → Role-labeled process
```cypher
MATCH (h:Host)-[r1:HostHasLocalEndpoint]->(le:Endpoint)-[r2:LocalEndpointUsedBySession|LocalEndpointUsedByBeacon|LocalEndpointUsedByTunnel|LocalEndpointUsedByListener|LocalEndpointUsedByOutbound|LocalEndpointUsedByProcess]->(p:Process)
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
MATCH (h:Host)-[r1:HostHasLocalEndpoint]->(le:Endpoint)-[r2:LocalEndpointUsedBySession|LocalEndpointUsedByBeacon|LocalEndpointUsedByTunnel|LocalEndpointUsedByListener|LocalEndpointUsedByOutbound|LocalEndpointUsedByProcess]->(p:Process)-[r3:SessionConnectsToExternal|BeaconConnectsToExternal|TunnelConnectsToExternal|ListenerConnectsToExternal|OutboundConnectsToExternal|ProcessConnectsToExternal]->(e:Endpoint)
RETURN h, r1, le, r2, p, r3, e
```

22) Full chain with process context (internal)
```cypher
MATCH (h:Host)-[r1:HostHasLocalEndpoint]->(le:Endpoint)-[r2:LocalEndpointUsedBySession|LocalEndpointUsedByBeacon|LocalEndpointUsedByTunnel|LocalEndpointUsedByListener|LocalEndpointUsedByOutbound|LocalEndpointUsedByProcess]->(p:Process)-[r3:SessionConnectsToInternal|BeaconConnectsToInternal|TunnelConnectsToInternal|ListenerConnectsToInternal|OutboundConnectsToInternal|ProcessConnectsToInternal]->(e:Endpoint)
RETURN h, r1, le, r2, p, r3, e
```

## Role-specific views

23) Beacon only
```cypher
MATCH (p:Process)-[r:BeaconConnectsToExternal|BeaconConnectsToInternal|BeaconConnectsToLoopback]->(e:Endpoint)
RETURN p, r, e
```

24) Tunnel only
```cypher
MATCH (p:Process)-[r:TunnelConnectsToExternal|TunnelConnectsToInternal|TunnelConnectsToLoopback]->(e:Endpoint)
RETURN p, r, e
```
