package com.booking.security.hackertest.detector;

import scala.concurrent.Future;
import scala.concurrent.Await;
import scala.concurrent.Promise;
import scala.concurrent.ExecutionContext;
import scala.concurrent.duration.Duration;

import java.util.Arrays;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

import akka.util.Timeout;
import akka.actor.ActorRef;
import akka.pattern.Patterns;
import akka.actor.ActorSystem;

import com.booking.security.hackertest.detector.actors.LogSignatureDetector;
import com.booking.security.hackertest.detector.actors.LogSignatureDetector.*;

public class HackerDetectionSystemMain {
  public static void main(String[] args) {
    Timeout timeout = new Timeout(Duration.create(3, "seconds"));
    final ActorSystem system = ActorSystem.create("hacker-detection-system");
    final ExecutionContext ec = system.dispatcher();
    
    // send messages
    String lineIp = "187.218.83.136";
    String lineUsername = "John.Smith";
    Long lineDate = LocalDateTime.now().atOffset(ZoneOffset.UTC).toInstant().toEpochMilli();
    String logSignatureId = lineIp+"-"+lineUsername;
    
    try {  
      // create actors
      final ActorRef actor1 = system.actorOf(LogSignatureDetector.props(logSignatureId), logSignatureId);
      
      actor1.tell(new LogSignatureDetector.AddLogLine(new LogLine(lineIp, lineUsername, Arrays.asList(lineDate))), ActorRef.noSender());
      
      Future<Object> future = Patterns.ask(actor1, LogSignatureDetector.GET_LOG_SIGNATURE, timeout);
      LogSignatureDetector.LogSignature result = (LogSignatureDetector.LogSignature) Await.result(future, timeout.duration());
      System.out.println(">>> result: " + result.logLine.toString());
      
    } catch (Exception e) {
      System.out.println(">>> Error <<<" + e.toString());
    } finally {
      system.terminate();
    }
  }
}
