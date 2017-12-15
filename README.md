# Hacker Detection System
A take-home-assigment from Booking, by Javier Igua.

This intrusion detection system is:
- Signature-based: It uses a couple of fields in a log line to clasify an anomaly (e.g. IP and username).
- Relies on pattern matching: The mechanism used to detect an anomaly (e.g. a failed login).
- Is distributed and reactive: Distributed in an Akka cluster, as an architectural desition to support high availability and performance. Reactive by streaming data from an input sources (e.g. a log file).
- Is cooperative: Each node in the cluster contributes to a distributed replicated data map of detected anomalies (e.g. indexed log signatures and anomalies count).

## Execution

### [Optional] To generate a sample log for the first time, or an incremental addition to previous generated one.
sbt clean "runMain com.booking.security.hackertest.detector.util.LogFileGenerator [FILE_NAME]"

### To run (the main actor system) on a single machine
sbt clean "runMain com.booking.security.hackertest.detector.HackerDetectionSystemMain [FILE_NAME]"

### To run (the main actor system) on a cluster of nodes
// TODO: Add development/staging/production AKKA config files.

## Unit Testing (Multi JVM)
sbt clean "multi-jvm:test-only com.booking.security.hackertest.detector.actors.LogSignatureDetectorActorSpec"

## Implementations details

Every instance of the actor [LogSignatureDetectorActor.java](src/main/java/com/booking/security/hackertest/detector/actors/LogSignatureDetectorActor.java) shares data between nodes in an Akka Cluster by means of a _Conflict Free Replicated Data Type_ (CRDT) map.  It can make reads and updates on the local node during a network partition, converging again by means of replication on this AKKA distributed data map, with 'Last Writer Wins Register' semantics.

Main instance of this application [HackerDetectionSystemMain.java](src/main/java/com/booking/security/hackertest/detector/HackerDetectionSystemMain.java) instanciates the actor system, opens a file tail source on the log file and streams every line into its own log signature dector actor for processing. After that it queries the the cluster about the processed log signature, and if an anomaly was detected the IP is printed on the standard output, along whith some other digested data.