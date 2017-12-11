A take-home-assigment from Booking, by Javier Igua.

## Hacker Detection System

This intrusion detection system is:
- Signature-based: It uses a couple of fields in a log line to clasify an anomaly (e.g. IP and username).
- Relies on Pattern matching: The mechanism used to detect an anomaly (e.g. a failed login).
- Is distributed: In an Akka cluster, as an architectural desition to support high availability.
- Is cooperative: Each node contributes to a distributed replicated data map (with entries indexed by the log signature). It can make reads and updates on the local node during a network partition.

The actor [LogSignatureDetector.java](src/main/java/com/booking/security/hackertest/detector/actors/LogSignatureDetector.java) shares data between nodes in an Akka Cluster by means of a _Conflict Free Replicated Data Type_ (CRDT) Map.
