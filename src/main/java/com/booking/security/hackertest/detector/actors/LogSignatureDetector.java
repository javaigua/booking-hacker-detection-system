package com.booking.security.hackertest.detector.actors;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Optional;
import java.util.List;
import java.util.stream.Stream;
import java.util.stream.Collectors;
import static java.util.concurrent.TimeUnit.SECONDS;

import scala.concurrent.duration.Duration;

import akka.actor.AbstractActor;
import akka.actor.ActorRef;
import akka.actor.Props;
import akka.cluster.Cluster;
import akka.cluster.ddata.DistributedData;
import akka.cluster.ddata.Key;
import akka.cluster.ddata.LWWMap;
import akka.cluster.ddata.LWWMapKey;
import akka.cluster.ddata.Replicator;
import akka.cluster.ddata.Replicator.GetFailure;
import akka.cluster.ddata.Replicator.GetResponse;
import akka.cluster.ddata.Replicator.GetSuccess;
import akka.cluster.ddata.Replicator.NotFound;
import akka.cluster.ddata.Replicator.ReadConsistency;
import akka.cluster.ddata.Replicator.ReadMajority;
import akka.cluster.ddata.Replicator.Update;
import akka.cluster.ddata.Replicator.UpdateFailure;
import akka.cluster.ddata.Replicator.UpdateSuccess;
import akka.cluster.ddata.Replicator.UpdateTimeout;
import akka.cluster.ddata.Replicator.WriteConsistency;
import akka.cluster.ddata.Replicator.WriteMajority;

@SuppressWarnings("unchecked")
public class LogSignatureDetector extends AbstractActor {
  // Get log signature message
  public static final String GET_LOG_SIGNATURE = "getLogSignature";

  // Add log line message
  public static class AddLogLine {
    public final LogLine logLine;

    public AddLogLine(LogLine logLine) {
      this.logLine = logLine;
    }
  }

  // Log signature message
  public static class LogSignature {
    public final List<LogLine> lines;

    public LogSignature(List<LogLine> lines) {
      this.lines = lines;
    }
  }

  // Log line entity, stored in distributed data map
  public static class LogLine implements Serializable {
    private static final long serialVersionUID = 1L;
    public final String ip;
    public final String username;
    public final List<Long> dates;

    public LogLine(String ip, String username, List<Long> dates) {
      this.ip = ip;
      this.username = username;
      this.dates = dates;
    }

    public String getLogSignatureId() {
      return new StringBuffer(ip).append("-").append(username).toString();
    }

    @Override
    public int hashCode() {
      final int prime = 31;
      int result = 1;
      result = prime * result + ((ip == null) ? 0 : ip.hashCode());
      result = prime * result + ((username == null) ? 0 : username.hashCode());
      return result;
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj)
        return true;
      if (obj == null)
        return false;
      if (getClass() != obj.getClass())
        return false;
      
      LogLine other = (LogLine) obj;
      if (ip == null) {
        if (other.ip != null)
          return false;
      } else if (!ip.equals(other.ip))
        return false;
      
      if (username == null) {
        if (other.username != null)
          return false;
      } else if (!username.equals(other.username))
        return false;
      
      return true;
    }

    @Override
    public String toString() {
      return "LogLine [ip=" + ip + 
        ", username=" + username + 
        ", dates=[" + dates.stream().map(d -> d.toString()).collect(Collectors.joining(", ")) + "]]";
    }

  }

  // Actor constructor
  public static Props props(String logSignatureId) {
    return Props.create(LogSignatureDetector.class, logSignatureId);
  }

  // Read/write majority config for distributed data
  private final WriteConsistency writeMajority =  new WriteMajority(Duration.create(3, SECONDS));
  private final static ReadConsistency readMajority =  new ReadMajority(Duration.create(3, SECONDS));

  // Distributed data replicator
  private final ActorRef replicator = DistributedData.get(context().system()).replicator();
  
  // Cluster node
  private final Cluster node = Cluster.get(context().system());

  @SuppressWarnings("unused")
  private final String logSignatureId;
  private final Key<LWWMap<String, LogLine>> dataKey;

  public LogSignatureDetector(String logSignatureId) {
    this.logSignatureId = logSignatureId;
    this.dataKey = LWWMapKey.create(logSignatureId);
  }

  // Main message receiver for this actor
  @Override
  public Receive createReceive() {
    return matchGetLogSignature()
      .orElse(matchAddLogLine())
      .orElse(matchOther());
  }

  // get logSignature
  private Receive matchGetLogSignature() {
    return receiveBuilder()
      .matchEquals((GET_LOG_SIGNATURE), s -> receiveGetLogSignature())
      .match(GetSuccess.class, this::isResponseToGetLogSignature,
          g -> receiveGetSuccess((GetSuccess<LWWMap<String, LogLine>>) g))
        .match(NotFound.class, this::isResponseToGetLogSignature,
          n -> receiveNotFound((NotFound<LWWMap<String, LogLine>>) n))
        .match(GetFailure.class, this::isResponseToGetLogSignature,
          f -> receiveGetFailure((GetFailure<LWWMap<String, LogLine>>) f))
      .build();
  }


  private void receiveGetLogSignature() {
    Optional<Object> ctx = Optional.of(sender());
    replicator.tell(new Replicator.Get<>(dataKey, readMajority, ctx),
        self());
  }

  private boolean isResponseToGetLogSignature(GetResponse<?> response) {
    return response.key().equals(dataKey) && 
        (response.getRequest().orElse(null) instanceof ActorRef);
  }

  private void receiveGetSuccess(GetSuccess<LWWMap<String, LogLine>> g) {
    List<LogLine> logLines = new ArrayList<>(g.dataValue().getEntries().values());
    System.out.println(">>>>> logLines: " + logLines.toString());
    ActorRef replyTo = (ActorRef) g.getRequest().get();
    replyTo.tell(new LogSignature(logLines), self());
  }

  private void receiveNotFound(NotFound<LWWMap<String, LogLine>> n) {
    System.out.println(">>>>> not found!");
    ActorRef replyTo = (ActorRef) n.getRequest().get();
    replyTo.tell(new LogSignature(new ArrayList<>()), self());
  }

  private void receiveGetFailure(GetFailure<LWWMap<String, LogLine>> f) {
    System.out.println(">>>>> failure!");
    // ReadMajority failure, try again with local read
    Optional<Object> ctx = Optional.of(sender());
    replicator.tell(new Replicator.Get<>(dataKey, Replicator.readLocal(), ctx), self());
  }

  // add logLine
  private Receive matchAddLogLine() {
    return receiveBuilder()
      .match(AddLogLine.class, this::receiveAddLogLine)
      .build();
  }

  private void receiveAddLogLine(AddLogLine add) {
    Update<LWWMap<String, LogLine>> update = new Update<>(dataKey, LWWMap.create(), writeMajority,
        logSignature -> updateLogSignature(logSignature, add.logLine));
    replicator.tell(update, self());
  }

  private LWWMap<String, LogLine> updateLogSignature(LWWMap<String, LogLine> data, LogLine logLine) {
    if (data.contains(logLine.getLogSignatureId())) {
      LogLine existingLogLine = data.get(logLine.getLogSignatureId()).get();
      List<Long> newDates = Stream.concat(existingLogLine.dates.stream(), logLine.dates.stream())
        .sorted((l1, l2) -> Long.compare(l1, l2))
        .collect(Collectors.toList());
      LogLine newLogLine = new LogLine(logLine.ip, logLine.username, newDates);
      return data.put(node, logLine.getLogSignatureId(), newLogLine);
    } else {
      return data.put(node, logLine.getLogSignatureId(), logLine);
    }
  }

  // receiver for other messages
  private Receive matchOther() {
    return receiveBuilder()
      .match(UpdateSuccess.class, u -> {
        // ok
      })
      .match(UpdateTimeout.class, t -> {
        // will eventually be replicated
      })
      .match(UpdateFailure.class, f -> {
        throw new IllegalStateException("Unexpected failure: " + f);
      })
      .build();
  }

}
