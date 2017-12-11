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
import java.util.concurrent.ThreadLocalRandom;

import akka.util.Timeout;
import akka.actor.ActorRef;
import akka.actor.ActorSelection;
import akka.actor.ActorNotFound;
import akka.dispatch.OnComplete;
import akka.pattern.Patterns;
import akka.actor.ActorSystem;

import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;

import com.booking.security.hackertest.detector.actors.LogSignatureDetector;
import com.booking.security.hackertest.detector.actors.LogSignatureDetector.*;

public class HackerDetectionSystemMain {
  public static void main(String[] args) {
    Timeout timeout = new Timeout(Duration.create(3, "seconds"));
    
    final Config config = ConfigFactory.load();
    final ActorSystem system = ActorSystem.create("hacker-detection-system", config);
    final ExecutionContext ec = system.dispatcher();
    try {
      ThreadLocalRandom r = ThreadLocalRandom.current();
      for(int i = 0; i < 850000; i++) {
        // send messages
        String lineIp = new StringBuffer().append(r.nextInt(1, 256)).append(".").append(r.nextInt(1, 120))
          .append(".").append(r.nextInt(1, 2)).append(".").append(r.nextInt(1, 2)).toString();
        String lineUsername = "John.Smith."+(i % 20);
        Long lineDate = LocalDateTime.now().atOffset(ZoneOffset.UTC).toInstant().toEpochMilli();
        String logSignatureId = lineIp+"-"+lineUsername;
        
        if (i % 25000 == 0)
          System.out.println(">>> i: " + i);
        
        // create or get actor
        Future<ActorRef> actorFuture = system.actorSelection("/user/" + logSignatureId).resolveOne(timeout);
        actorFuture.onComplete(new OnComplete<ActorRef>() {
          public void onComplete(Throwable failure, ActorRef actorResult) {
            ActorRef actor = null;
            if (failure != null) {
              actor = system.actorOf(LogSignatureDetector.props(logSignatureId), logSignatureId);
            } else {
              actor = actorResult;
            }
            
            // send store message
            actor.tell(new LogSignatureDetector.AddLogLine(new LogLine(lineIp, lineUsername, Arrays.asList(lineDate))), ActorRef.noSender());
            
            // send retrieve message
            Future<Object> askFuture = Patterns.ask(actor, LogSignatureDetector.GET_LOG_SIGNATURE, timeout);
            askFuture.onComplete(new OnComplete<Object>() {
              public void onComplete(Throwable failure, Object askResult) {
                if (askResult != null) {
                  final LogSignatureDetector.LogSignature logSignature = (LogSignatureDetector.LogSignature) askResult;
                  if(logSignature.logLine.dates != null && logSignature.logLine.dates.size() >= 5) {
                    System.out.println(">>> "  + logSignature.logLine.ip + " -> anomaly detected for " + logSignature.logLine.username + ", count:" + logSignature.logLine.dates.size());
                  }
                }
              }
            }, ec);
          }
        }, ec);
      }
    } catch (Exception e) {
      System.out.println(">>> Error <<< " + e.toString());
    } finally {
      system.terminate();
    }
  }
}
