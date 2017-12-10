package com.booking.security.hackertest.detector;

import scala.concurrent.Future;
import scala.concurrent.Await;
import scala.concurrent.Promise;
import scala.concurrent.ExecutionContext;
import scala.concurrent.duration.Duration;

import java.util.Arrays;
import java.util.Random;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

import akka.util.Timeout;
import akka.actor.ActorRef;
import akka.actor.ActorSelection;
import akka.actor.ActorNotFound;
import akka.pattern.Patterns;
import akka.actor.ActorSystem;

import com.booking.security.hackertest.detector.actors.LogSignatureDetector;
import com.booking.security.hackertest.detector.actors.LogSignatureDetector.*;

public class HackerDetectionSystemMain {
  public static void main(String[] args) {
    Timeout timeout = new Timeout(Duration.create(3, "seconds"));
    final ActorSystem system = ActorSystem.create("hacker-detection-system");
    try {
      Random r = new Random();
      for(int i = 0; i < 100000; i++) {
        // send messages
        String lineIp = "187.218.83.136";
          //new StringBuffer().append(r.nextInt(256)).append(".").append(r.nextInt(256))
          //.append(".").append(r.nextInt(256)).append(".").append(r.nextInt(256)).toString();
        String lineUsername = "John.Smith."+(i % 20);
        Long lineDate = LocalDateTime.now().atOffset(ZoneOffset.UTC).toInstant().toEpochMilli();
        String logSignatureId = lineIp+"-"+lineUsername;
        
        // create or get actor
        ActorRef actor = null;
        try {
          Future<ActorRef> actorFuture = system.actorSelection("/user/" + logSignatureId).resolveOne(timeout);
          actor = Await.result(actorFuture, timeout.duration());
        } catch (ActorNotFound e) {
          actor = system.actorOf(LogSignatureDetector.props(logSignatureId), logSignatureId);
        }
        // send store message
        actor.tell(new LogSignatureDetector.AddLogLine(new LogLine(lineIp, lineUsername, Arrays.asList(lineDate))), ActorRef.noSender());
        // send retrieve message
        Future<Object> askFuture = Patterns.ask(actor, LogSignatureDetector.GET_LOG_SIGNATURE, timeout);
        LogSignatureDetector.LogSignature result = (LogSignatureDetector.LogSignature) Await.result(askFuture, timeout.duration());
        System.out.println(">>> result[" + i + "]: "  + result.logLine.toString());
      }
    } catch (Exception e) {
      System.out.println(">>> Error <<< " + e.toString());
    } finally {
      system.terminate();
    }
  }
}
