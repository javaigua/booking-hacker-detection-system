package com.booking.security.hackertest.detector.actors;

import java.util.Set;
import java.util.HashSet;
import java.util.Optional;
import java.util.Collection;
import java.io.Serializable;
import java.util.stream.Stream;
import java.util.stream.Collectors;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import static java.util.concurrent.TimeUnit.SECONDS;

import scala.concurrent.duration.Duration;

import akka.actor.Cancellable;
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
public class LogSignatureDetectorActor extends AbstractActor {
  
  // Remove stale dates message
  public static final String REMOVE_STALE_DATA = "removeStaleData";
  
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
    public final LogLine logLine;

    public LogSignature(LogLine logLine) {
      this.logLine = logLine;
    }
    
    public String getLogSignatureId() {
      if (logLine != null) {
        return logLine.getLogSignatureId();
      }
      return null;
    }
    
    public int countAnomalies() {
      if (logLine != null) {
        return logLine.getDatesCount();
      }
      return 0;
    }
    
    public boolean isAbovePermitedThreshold() {
      return countAnomalies() > 5;
    }
    
  }
  
  // Get data command
  private static class GetDataCommand {
    public final ActorRef replyTo;
    public final String message;

    public GetDataCommand(ActorRef replyTo, String message) {
      this.replyTo = replyTo;
      this.message = message;
    }    
  }

  // Log line entity, stored in distributed data map
  public static class LogLine implements Serializable {
    private static final long serialVersionUID = 1L;
    public final String ip;
    public final String username;
    public final Set<Long> dates;

    public LogLine(String ip, String username, Set<Long> dates) {
      this.ip = ip;
      this.username = username;
      this.dates = dates;
    }

    public String getLogSignatureId() {
      return new StringBuffer().append(ip).append("-").append(username).toString();
    }
    
    public int getDatesCount() {
      if (dates != null) {
        return dates.size();
      }
      return 0;
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
    return Props.create(LogSignatureDetectorActor.class, logSignatureId);
  }

  // Read/write majority config for distributed data
  private final WriteConsistency writeMajority =  new WriteMajority(Duration.create(3, SECONDS));
  private final static ReadConsistency readMajority =  new ReadMajority(Duration.create(3, SECONDS));

  // Distributed data replicator
  private final ActorRef replicator = DistributedData.get(context().system()).replicator();
  
  // Cluster node
  private final Cluster node = Cluster.get(context().system());

  // Distributed data
  @SuppressWarnings("unused")
  private final String logSignatureId;
  private final Key<LWWMap<String, LogLine>> dataKey;

  public LogSignatureDetectorActor(String logSignatureId) {
    this.logSignatureId = logSignatureId;
    this.dataKey = LWWMapKey.create(logSignatureId);
  }

  // Scheduler
  int STALE_DATA_SECONDS = 300;
  Cancellable cancellable = context().system().scheduler().schedule(
    Duration.create(STALE_DATA_SECONDS, SECONDS), 
    Duration.create(STALE_DATA_SECONDS, SECONDS), 
    getSelf(), 
    REMOVE_STALE_DATA,
    context().system().dispatcher(), 
    getSelf());

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
      .matchEquals((GET_LOG_SIGNATURE), s -> receiveGetData(GET_LOG_SIGNATURE))
      .matchEquals((REMOVE_STALE_DATA), r -> receiveGetData(REMOVE_STALE_DATA))
      .match(GetSuccess.class, this::isResponseToGetData,
          g -> receiveGetSuccess((GetSuccess<LWWMap<String, LogLine>>) g))
        .match(NotFound.class, this::isResponseToGetData,
          n -> receiveNotFound((NotFound<LWWMap<String, LogLine>>) n))
        .match(GetFailure.class, this::isResponseToGetData,
          f -> receiveGetFailure((GetFailure<LWWMap<String, LogLine>>) f))
      .build();
  }

  private void receiveGetData(String message) {
    Optional<Object> ctx = Optional.of(new GetDataCommand(sender(), message));
    replicator.tell(new Replicator.Get<>(dataKey, readMajority, ctx), self());
  }

  private boolean isResponseToGetData(GetResponse<?> response) {
    return response.key().equals(dataKey) && 
        (response.getRequest().orElse(null) instanceof LogSignatureDetectorActor.GetDataCommand &&
          ((LogSignatureDetectorActor.GetDataCommand) response.getRequest().get()).replyTo instanceof ActorRef);
  }

  private void receiveGetSuccess(GetSuccess<LWWMap<String, LogLine>> g) {
    Collection<LogLine> logLines = g.dataValue().getEntries().values();
    GetDataCommand command = (LogSignatureDetectorActor.GetDataCommand) g.getRequest().get();

    if (logLines != null && logLines.size() >= 1) {
      if (GET_LOG_SIGNATURE.equals(command.message)) {
        command.replyTo.tell(new LogSignature((LogLine) logLines.toArray()[0]), self());
      } else if (REMOVE_STALE_DATA.equals(command.message)) {
        removeStaleData((LogLine) logLines.toArray()[0]);
      }
    }
  }

  private void removeStaleData(LogLine logLine) {
    Long minutesAgo = LocalDateTime.now().minusSeconds(STALE_DATA_SECONDS).atOffset(ZoneOffset.UTC).toInstant().toEpochMilli();
    Set<Long> newDates = logLine.dates.stream()
      .filter(date -> date >= minutesAgo)
      .collect(Collectors.toSet());
    if (newDates.size() > 0) {
      LogLine newLogLine = new LogLine(logLine.ip, logLine.username, newDates);
      Update<LWWMap<String, LogLine>> update = new Update<>(dataKey, LWWMap.create(), writeMajority,
        logSignature -> logSignature.put(node, logLine.getLogSignatureId(), newLogLine));
      replicator.tell(update, self());
    } else {
      Update<LWWMap<String, LogLine>> update = new Update<>(dataKey, LWWMap.create(), writeMajority,
        logSignature -> logSignature.remove(node, logLine.getLogSignatureId()));
    }
  }

  private void receiveNotFound(NotFound<LWWMap<String, LogLine>> n) {
    GetDataCommand command = (LogSignatureDetectorActor.GetDataCommand) n.getRequest().get();
    command.replyTo.tell(new LogSignature(null), self());
  }

  private void receiveGetFailure(GetFailure<LWWMap<String, LogLine>> f) {
    // ReadMajority failure, try again with local read
    GetDataCommand command = (LogSignatureDetectorActor.GetDataCommand) f.getRequest().get();
    Optional<Object> ctx = Optional.of(new GetDataCommand(sender(), command.message));
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
      Set<Long> newDates = Stream.concat(existingLogLine.dates.stream(), logLine.dates.stream())
        .collect(Collectors.toSet());
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
