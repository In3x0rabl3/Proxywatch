# ProxyWatch OpenCypher Queries

Use these in the BloodHound Cypher tab or any Neo4j-compatible graph viewer.

---

## Process Inventory

### All control-role processes
```cypher
MATCH (p:Process)
WHERE p.role STARTS WITH "control-"
RETURN p
```

### Hosts → All detected processes
```cypher
MATCH path = (h:Host)-[r]->(p:Process)
WHERE type(r) STARTS WITH "Has"
RETURN path
```

### Users → All detected processes
```cypher
MATCH path = (u:User)-[r]->(p:Process)
WHERE type(r) STARTS WITH "Runs"
RETURN path
```

### Full context: Host → Process ← User
```cypher
MATCH path = (h:Host)-[r1]->(p:Process)<-[r2]-(u:User)
WHERE type(r1) STARTS WITH "Has" AND type(r2) STARTS WITH "Runs"
RETURN path
```

### Full context: Host → Process ← User → External endpoint
```cypher
MATCH path1 = (h:Host)-[r1]->(p:Process)<-[r2]-(u:User),
      path2 = (p)-[:ConnectsTo]->(e:Endpoint)
WHERE type(r1) STARTS WITH "Has" AND type(r2) STARTS WITH "Runs"
RETURN path1, path2
```

#### Filter by host, user, or process name
```cypher
MATCH path1 = (h:Host)-[r1]->(p:Process)<-[r2]-(u:User),
      path2 = (p)-[:ConnectsTo]->(e:Endpoint)
WHERE type(r1) STARTS WITH "Has" AND type(r2) STARTS WITH "Runs"
  AND h.name = "YOURHOST"        // pick host
  // AND u.name = "YOURUSER"     // pick user
  // AND p.name = "YOURPROCESS"  // pick process
RETURN path1, path2
```

### Full context: Host → Process ← User → Internal endpoint
```cypher
MATCH path1 = (h:Host)-[r1]->(p:Process)<-[r2]-(u:User),
      path2 = (p)-[:ConnectsToInternal]->(e:Endpoint)
WHERE type(r1) STARTS WITH "Has" AND type(r2) STARTS WITH "Runs"
RETURN path1, path2
```

### Full context: Host → Local endpoint → Process ← User → External endpoint
```cypher
MATCH path1 = (h:Host)-[:HasEndpoint]->(le:Endpoint)-[:BoundBy]->(p:Process)<-[r]-(u:User),
      path2 = (p)-[:ConnectsTo]->(e:Endpoint)
WHERE type(r) STARTS WITH "Runs"
RETURN path1, path2
```

---

## C2 Sessions

### All sessions
```cypher
MATCH path = (h:Host)-[:HasSession]->(p:Process)
RETURN path
```

### Session → External C2 target
```cypher
MATCH path = (h:Host)-[:HasSession]->(p:Process)-[:ConnectsTo]->(e:Endpoint)
RETURN path
```

### Sessions with persistent control channels (>60s)
```cypher
MATCH (p:Process)
WHERE p.role = "control-session" AND p.control_duration_seconds > 60
RETURN p, p.control_target AS target, p.control_duration_seconds AS duration
```

### Users running C2 sessions
```cypher
MATCH path = (u:User)-[:RunsSession]->(p:Process)-[:ConnectsTo]->(e:Endpoint)
RETURN path
```

---

## Beacons

### All beacons
```cypher
MATCH path = (h:Host)-[:HasBeacon]->(p:Process)
RETURN path
```

### Beacon → Callback target
```cypher
MATCH path = (h:Host)-[:HasBeacon]->(p:Process)-[:ConnectsTo]->(e:Endpoint)
RETURN path
```

### Shared C2: multiple beacons calling same endpoint
```cypher
MATCH (p:Process)-[:ConnectsTo]->(e:Endpoint)
WHERE p.role = "control-beacon"
WITH e, collect(p) AS beacons, count(p) AS cnt
WHERE cnt > 1
UNWIND beacons AS p
MATCH path = (p)-[:ConnectsTo]->(e)
RETURN path
```

---

## Tunnels

### All tunnels
```cypher
MATCH path = (h:Host)-[:HasTunnel]->(p:Process)
RETURN path
```

### Tunnel → External endpoint
```cypher
MATCH path = (h:Host)-[:HasTunnel]->(p:Process)-[:ConnectsTo]->(e:Endpoint)
RETURN path
```

### Tunnels actively proxying internal traffic
```cypher
MATCH path = (p:Process)-[:ConnectsToInternal]->(e:Endpoint)
WHERE p.role = "control-tunnel"
RETURN path
```

### Tunnel with both external and internal connections
```cypher
MATCH path1 = (p:Process)-[:ConnectsTo]->(ext:Endpoint),
      path2 = (p)-[:ConnectsToInternal]->(int:Endpoint)
WHERE p.role = "control-tunnel"
RETURN path1, path2
```

---

## Pivots & Lateral Movement

### All pivots
```cypher
MATCH path = (h:Host)-[:HasPivot]->(p:Process)
RETURN path
```

### Pivot → Internal host (lateral movement)
```cypher
MATCH path = (h1:Host)-[:HasPivot]->(p:Process)-[:ReachesHostInternal]->(h2:Host)
RETURN path
```

### SMB and named pipe pivots
```cypher
MATCH path = (p:Process)-[:ConnectsToInternal]->(e:Endpoint)
WHERE p.control_subtype IN ["smb-pivot", "pipe-pivot"]
RETURN path
```

### Double pivot chain
```cypher
MATCH path = (h1:Host)-[:HasPivot]->(p1:Process)-[:ReachesHostInternal]->(mid:Host)-[:HasPivot]->(p2:Process)-[:ReachesHostInternal]->(h3:Host)
RETURN path
```

### Internal targets hit by multiple control processes
```cypher
MATCH (p:Process)-[:ConnectsToInternal]->(e:Endpoint)
WHERE p.role STARTS WITH "control-"
WITH e, collect(p) AS procs, count(p) AS cnt
WHERE cnt > 1
UNWIND procs AS p
MATCH path = (p)-[:ConnectsToInternal]->(e)
RETURN path
```

### Connections to admin ports
```cypher
MATCH path = (p:Process)-[:ConnectsToInternal]->(e:Endpoint)
WHERE e.port IN [22, 135, 139, 445, 3389, 5985, 5986]
RETURN path
```

### Connections to credential ports (Kerberos, LDAP)
```cypher
MATCH path = (p:Process)-[:ConnectsToInternal]->(e:Endpoint)
WHERE e.port IN [88, 389, 636, 3268, 3269]
RETURN path
```

---

## External Traffic

### All external connections
```cypher
MATCH path = (p:Process)-[:ConnectsTo]->(e:Endpoint)
RETURN path
```

### External endpoints with multiple processes (shared infra)
```cypher
MATCH (p:Process)-[:ConnectsTo]->(e:Endpoint)
WHERE p.role STARTS WITH "control-"
WITH e, collect(p) AS procs, count(p) AS cnt
WHERE cnt > 1
UNWIND procs AS p
MATCH path = (p)-[:ConnectsTo]->(e)
RETURN path
```

### Connections on uncommon ports
```cypher
MATCH path = (p:Process)-[:ConnectsTo]->(e:Endpoint)
WHERE p.role STARTS WITH "control-" AND NOT e.port IN [80, 443, 22, 53]
RETURN path
```

---

## Internal Traffic

### All internal connections
```cypher
MATCH path = (p:Process)-[:ConnectsToInternal]->(e:Endpoint)
RETURN path
```

### Internal fan-out (single process → 3+ internal targets)
```cypher
MATCH (p:Process)-[:ConnectsToInternal]->(e:Endpoint)
WHERE p.role STARTS WITH "control-"
WITH p, count(e) AS targets
WHERE targets >= 3
MATCH path = (p)-[:ConnectsToInternal]->(e:Endpoint)
RETURN path
```

---

## Host Relationships

### Host ↔ IP mappings
```cypher
MATCH path = (h:Host)-[:HostHasIP]->(hip:Host)
RETURN path
```

### Process reaches remote host
```cypher
MATCH path = (h1:Host)-[r1]->(p:Process)-[:ReachesHost]->(h2:Host)
WHERE type(r1) STARTS WITH "Has"
RETURN path
```

### Process reaches internal host
```cypher
MATCH path = (h1:Host)-[r1]->(p:Process)-[:ReachesHostInternal]->(h2:Host)
WHERE type(r1) STARTS WITH "Has"
RETURN path
```

---

## Local Endpoints

### Process binds to local port
```cypher
MATCH path = (p:Process)-[:BindsTo]->(e:Endpoint)
RETURN path
```

### Host → Endpoint → Process chain
```cypher
MATCH path = (h:Host)-[:HasEndpoint]->(le:Endpoint)-[:BoundBy]->(p:Process)
RETURN path
```

### Full chain: Local → Process → External
```cypher
MATCH path = (h:Host)-[:HasEndpoint]->(le:Endpoint)-[:BoundBy]->(p:Process)-[:ConnectsTo]->(e:Endpoint)
RETURN path
```

### Full chain: Local → Process → Internal
```cypher
MATCH path = (h:Host)-[:HasEndpoint]->(le:Endpoint)-[:BoundBy]->(p:Process)-[:ConnectsToInternal]->(e:Endpoint)
RETURN path
```

---

## Analyzing

### Processes under analysis
```cypher
MATCH (p:Process)
WHERE p.role = "analyzing"
RETURN p
```

### Hosts with analyzing processes
```cypher
MATCH path = (h:Host)-[r]->(p:Process)
WHERE p.role = "analyzing" AND type(r) STARTS WITH "Has"
RETURN path
```

---

## Cross-Role Analysis

### Process count by role
```cypher
MATCH (p:Process)
WHERE p.role STARTS WITH "control-"
RETURN p.role AS role, count(p) AS count
ORDER BY count DESC
```

### Hosts with multiple roles (compromised)
```cypher
MATCH (h:Host)-[r]->(p:Process)
WHERE type(r) STARTS WITH "Has" AND p.role STARTS WITH "control-"
WITH h, collect(DISTINCT p.role) AS roles
WHERE size(roles) > 1
RETURN h.name AS host, roles
```

### Users with multiple control processes
```cypher
MATCH (u:User)-[r]->(p:Process)
WHERE type(r) STARTS WITH "Runs" AND p.role STARTS WITH "control-"
WITH u, count(p) AS total, collect(DISTINCT p.role) AS roles
WHERE total > 1
RETURN u.name AS user, total, roles
```

### High-score processes
```cypher
MATCH (p:Process)
WHERE p.score > 70
RETURN p ORDER BY p.score DESC
```

### Strong evidence
```cypher
MATCH (p:Process)
WHERE p.strong_evidence = true
RETURN p
```

### Active proxying
```cypher
MATCH (p:Process)
WHERE p.active_proxying = true
RETURN p
```

---

## Attack Path Reconstruction

### Full chain: External C2 → Session → Pivot → Internal target
```cypher
MATCH path = (ext:Endpoint)<-[:ConnectsTo]-(sess:Process)<-[:HasSession]-(h1:Host)-[:HasPivot]->(piv:Process)-[:ReachesHostInternal]->(h2:Host)
RETURN path
```

### Tunnel → Internal scanning
```cypher
MATCH path = (ext:Endpoint)<-[:ConnectsTo]-(tun:Process)-[:ConnectsToInternal]->(int:Endpoint)
WHERE tun.role = "control-tunnel"
RETURN path
```

### Beacon → Session upgrade on same host
```cypher
MATCH path1 = (h:Host)-[:HasBeacon]->(b:Process),
      path2 = (h)-[:HasSession]->(s:Process)
WHERE b <> s
RETURN path1, path2
```

### Full kill chain: C2 → Session → Tunnel → Pivot → Target
```cypher
MATCH path1 = (c2:Endpoint)<-[:ConnectsTo]-(sess:Process)<-[:HasSession]-(h1:Host)-[:HasTunnel]->(tun:Process)-[:ConnectsToInternal]->(int:Endpoint),
      path2 = (h1)-[:HasPivot]->(piv:Process)-[:ReachesHostInternal]->(h2:Host)
RETURN path1, path2
```
