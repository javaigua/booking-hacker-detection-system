A take-home-assigment from Booking, by Javier Igua.

## Hacker Detection System

This intrusion detection system is:
- Signature-based: It uses a couple of fields in a log line to clasify an anomaly.
- Relies on Pattern matching: The mechanism used to detect an anomaly.
- Is distributed: on an Akka Cluster, an architectural desition to support high availability.
- Is cooperative: data is shared between nodes (of the same log signature), but can even make updates on the local node during a network partition.

The actor [LogSignatureDetector.java](src/main/java/com/booking/security/hackertest/detector/actors/LogSignatureDetector.java) shares data between nodes in an Akka Cluster by means of a _Conflict Free Replicated Data Type_ (CRDT) Map.
