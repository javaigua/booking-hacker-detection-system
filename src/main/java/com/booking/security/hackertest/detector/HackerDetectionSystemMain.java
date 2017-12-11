package com.booking.security.hackertest.detector;

import scala.concurrent.Future;
import scala.concurrent.ExecutionContext;
import scala.concurrent.duration.Duration;
import scala.concurrent.duration.FiniteDuration;

import java.util.Arrays;
import java.time.ZoneId;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.LocalDateTime;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.util.Collection;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.CompletionStage;

import akka.Done;
import akka.NotUsed;
import akka.util.Timeout;
import akka.util.ByteString;
import akka.actor.ActorRef;
import akka.actor.ActorSelection;
import akka.actor.ActorNotFound;
import akka.dispatch.OnComplete;
import akka.pattern.Patterns;
import akka.actor.ActorSystem;
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
    if(args.length != 1) throw new IllegalArgumentException("Usage: HackerDetectionSystemMain [path]");
    final String path = args[0];
    
    final Config config = ConfigFactory.load();
    final ActorSystem system = ActorSystem.create("hacker-detection-system", config);
    final ExecutionContext ec = system.dispatcher();
    final Materializer materializer = ActorMaterializer.create(system);
    Timeout timeout = new Timeout(Duration.create(3, "seconds"));
    
    try {
      final int maxLineSize = 8192;
      final FileSystem fs = FileSystems.getDefault();
      final FiniteDuration pollingInterval = FiniteDuration.create(250, TimeUnit.MILLISECONDS);
      final Source<String, NotUsed> lines = FileTailSource.createLines(fs.getPath(path), maxLineSize, pollingInterval);
      
      final CompletionStage<Done> done = lines.runForeach((line) -> {
        CompletionStage<Collection<ByteString>> completionStage = Source.single(ByteString.fromString(line))
          .via(CsvParsing.lineScanner())
          .runWith(Sink.head(), materializer);

        Collection<ByteString> list = completionStage.toCompletableFuture().get(5, TimeUnit.SECONDS);
        String[] res = list.stream().map(ByteString::utf8String).toArray(String[]::new);

        Long lineDate = LocalDateTime.ofInstant(Instant.ofEpochMilli(Long.valueOf(res[0])), ZoneId.systemDefault())
          .atOffset(ZoneOffset.UTC).toInstant().toEpochMilli();
        String lineIp = res[1];
        String lineUsername = res[2];
        String lineAction = res[3];
        String logSignatureId = lineIp+"-"+lineUsername;

        if (!"SUCCESS".equalsIgnoreCase(lineAction)) {
          // create or get actor
          Future<ActorRef> actorFuture = system.actorSelection("/user/" + logSignatureId).resolveOne(timeout);
          actorFuture.onComplete(new OnComplete<ActorRef>() {
            public void onComplete(Throwable failure, ActorRef actorResult) {
              ActorRef actor = null;
              if (failure != null) {
                actor = system.actorOf(LogSignatureDetectorActor.props(logSignatureId), logSignatureId);
              } else {
                actor = actorResult;
              }
              
              // send add log line message
              actor.tell(new LogSignatureDetectorActor.AddLogLine(
                new LogLine(lineIp, lineUsername, Arrays.asList(lineDate))), ActorRef.noSender());
              
              // send retrieve message
              Future<Object> askFuture = Patterns.ask(actor, LogSignatureDetectorActor.GET_LOG_SIGNATURE, timeout);
              askFuture.onComplete(new OnComplete<Object>() {
                public void onComplete(Throwable failure, Object askResult) {
                  if (askResult != null) {
                    final LogSignature logSignature = (LogSignatureDetectorActor.LogSignature) askResult;
                    if(logSignature.logLine.dates != null && logSignature.logLine.dates.size() >= 5) {
                      System.out.println(logSignature.logLine.ip + 
                        " -> anomaly detected for " + logSignature.logLine.username + ", count:" + logSignature.logLine.dates.size());
                    }
                  }
                }
              }, ec);
            }
          }, ec);
        }
      }, materializer);
    } catch (Exception e) {
      System.out.println(">>> Error <<< " + e.toString());
    }
  }
}
