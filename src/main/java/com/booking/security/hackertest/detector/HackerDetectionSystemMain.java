package com.booking.security.hackertest.detector;

import scala.concurrent.Future;
import scala.concurrent.ExecutionContext;
import scala.concurrent.duration.Duration;
import scala.concurrent.duration.FiniteDuration;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.time.Instant;
import java.time.ZoneOffset;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.util.Collection;
import java.util.stream.Collectors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.CompletionStage;

import akka.util.Timeout;
import akka.util.ByteString;
import akka.actor.ActorRef;
import akka.actor.ActorSystem;
import akka.actor.ActorSelection;
import akka.actor.ActorNotFound;
import akka.dispatch.OnComplete;
import akka.pattern.Patterns;
import akka.stream.Materializer;
import akka.stream.ActorMaterializer;
import akka.stream.javadsl.Sink;
import akka.stream.javadsl.Source;
import akka.stream.alpakka.csv.javadsl.CsvParsing;
import akka.stream.alpakka.file.javadsl.FileTailSource;

import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;

import com.booking.security.hackertest.detector.actors.LogSignatureDetectorActor;
import com.booking.security.hackertest.detector.actors.LogSignatureDetectorActor.*;

public class HackerDetectionSystemMain {
  public static void main(String[] args) {
    System.out.println("\n status: starting_system ");
    final String DEFAULT_FILE_NAME = "login.log.sample";
    
    // Usage and default param values
    String fileName = DEFAULT_FILE_NAME;
    if(args.length != 0 && args.length > 1) {
      throw new IllegalArgumentException("Usage: HackerDetectionSystemMain [path]");
    } else if(args.length == 1) {
      fileName = args[0];
    }
    
    // Actor system set up
    final Config config = ConfigFactory.load();
    final ActorSystem system = ActorSystem.create("hacker-detection-system", config);
    final ExecutionContext ec = system.dispatcher();
    final Timeout timeout = new Timeout(Duration.create(3, "seconds"));
    
    // Stream log file
    final int maxLineSize = 8192;
    final FileSystem fs = FileSystems.getDefault();
    final Materializer materializer = ActorMaterializer.create(system);
    final FiniteDuration pollingInterval = FiniteDuration.create(250, TimeUnit.MILLISECONDS);
    
    try {
      System.out.println(" status: detecting_anomalies, file: " + fs.getPath(fileName));
      // Starting file tail source (a reactive streamming Alpakka integration)
      FileTailSource.createLines(fs.getPath(fileName), maxLineSize, pollingInterval).runForeach((line) -> {
        try {
          // Parsing the streamed log line
          CompletionStage<Collection<ByteString>> completionStage = Source.single(ByteString.fromString(line))
            .via(CsvParsing.lineScanner())
            .runWith(Sink.head(), materializer);
          Collection<ByteString> list = completionStage.toCompletableFuture().get(5, TimeUnit.SECONDS);
          String[] res = list.stream().map(ByteString::utf8String).toArray(String[]::new);
          
          // Parsed log fields
          Long lineDate = Instant.ofEpochMilli(Long.valueOf(res[0])).atOffset(ZoneOffset.UTC).toInstant().toEpochMilli();
          String lineIp = res[1];
          String lineUsername = res[2];
          String lineAction = res[3];
          
          // Log line and signature abstraction of parsed data
          LogLine newLogLine = new LogLine(lineIp, lineUsername, new HashSet<>(Arrays.asList(lineDate)));
          String logSignatureId = newLogLine.getLogSignatureId();
          
          // Processing only failed ones
          if (!"SUCCESS".equalsIgnoreCase(lineAction)) {
            
            // Creating or getting actor for the log signature
            Future<ActorRef> actorFuture = system.actorSelection("/user/" + logSignatureId).resolveOne(timeout);
            actorFuture.onComplete(new OnComplete<ActorRef>() {
              public void onComplete(Throwable failure, ActorRef actorResult) {
                ActorRef actor = actorResult;
                if (failure != null) {
                  actor = system.actorOf(LogSignatureDetectorActor.props(logSignatureId), logSignatureId);
                }
                
                // Sending add log line message to actor
                actor.tell(new AddLogLine(newLogLine), ActorRef.noSender());
                
                // Asking about the log line signature processing
                Future<Object> askFuture = Patterns.ask(actor, LogSignatureDetectorActor.GET_LOG_SIGNATURE, timeout);
                askFuture.onComplete(new OnComplete<Object>() {
                  public void onComplete(Throwable failure, Object askResult) {
                    if (askResult != null) {
                      final LogSignature logSignature = (LogSignature) askResult;
                      if(logSignature.isAbovePermitedThreshold()) {
                        System.out.println( new StringBuffer(" status: anomaly_detected")
                          .append(", IP: ").append(logSignature.getIP())
                          .append(", signature: ").append(logSignature.getLogSignatureId())
                          .append(", anomalies: ").append(logSignature.countAnomalies())
                          .append(", latest: ").append(logSignature.getLatestAnomalyDate().orElse(null))
                          .toString());
                      }
                    }
                  }
                }, ec);
              }
            }, ec);
          }
        } catch (Exception e) {
          System.out.println(" status: error_detecting_anomalies, error: " + e.toString());
        }
      }, materializer);
    } catch (Exception e) {
      System.out.println(" status: error_detecting_anomalies, error: " + e.toString());
    }
  }
}
