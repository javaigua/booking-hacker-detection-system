package com.booking.security.hackertest.detector.actors

import scala.concurrent.duration._
import scala.collection.JavaConverters._

import java.util.Arrays

import akka.cluster.Cluster
import akka.cluster.ddata.DistributedData
import akka.cluster.ddata.Replicator.GetReplicaCount
import akka.cluster.ddata.Replicator.ReplicaCount
import akka.remote.testconductor.RoleName
import akka.remote.testkit.MultiNodeConfig
import akka.remote.testkit.MultiNodeSpec

import akka.testkit._

import com.typesafe.config.ConfigFactory


object LogSignatureDetectorSpec extends MultiNodeConfig {
  val node1 = role("node-1")
  val node2 = role("node-2")
  val node3 = role("node-3")

  commonConfig(ConfigFactory.parseString("""
    akka.loglevel = INFO
    akka.actor.provider = "cluster"
    akka.log-dead-letters-during-shutdown = off
    """))
}

class LogSignatureDetectorSpecMultiJvmNode1 extends LogSignatureDetectorSpec
class LogSignatureDetectorSpecMultiJvmNode2 extends LogSignatureDetectorSpec
class LogSignatureDetectorSpecMultiJvmNode3 extends LogSignatureDetectorSpec

class LogSignatureDetectorSpec extends MultiNodeSpec(LogSignatureDetectorSpec) with STMultiNodeSpec with ImplicitSender {
  import LogSignatureDetectorSpec._
  import LogSignatureDetector._

  override def initialParticipants = roles.size

  val fixedIp: String = "187.218.83.136"
  val fixedUsername: String = "John.Smith"
  val fixedDate: Long = 1507365137L
  val logSignatureId: String = fixedIp+"-"+fixedUsername

  val cluster = Cluster(system)
  val logSignatureDetector = system.actorOf(LogSignatureDetector.props(logSignatureId))

  def join(from: RoleName, to: RoleName): Unit = {
    runOn(from) {
      cluster join node(to).address
    }
    enterBarrier(from.name + "-joined")
  }

  "Demo of a replicated log signature detector" must {
    "join cluster" in within(20.seconds) {
      join(node1, node1)
      join(node2, node1)
      join(node3, node1)

      awaitAssert {
        DistributedData(system).replicator ! GetReplicaCount
        expectMsg(ReplicaCount(roles.size))
      }
      enterBarrier("after-1")
    }

    "handle updates directly after start" in within(15.seconds) {
      runOn(node1) {
        logSignatureDetector ! new LogSignatureDetector.AddLogLine(new LogLine(fixedIp, fixedUsername, Arrays.asList(fixedDate)))
      }
      enterBarrier("updates-done")

      awaitAssert {
        logSignatureDetector ! LogSignatureDetector.GET_LOG_SIGNATURE
        val logSignature = expectMsgType[LogSignature]
        logSignature.lines.asScala.toList should be(List(
            new LogLine(fixedIp, fixedUsername, Arrays.asList())))
      }

      enterBarrier("after-2")
    }

    "handle updates from different nodes in the cluster" in within(15.seconds) {
      runOn(node1) {
        logSignatureDetector ! new LogSignatureDetector.AddLogLine(new LogLine(fixedIp, fixedUsername, Arrays.asList(fixedDate)))
      }
      runOn(node2) {
        logSignatureDetector ! new LogSignatureDetector.AddLogLine(new LogLine(fixedIp, fixedUsername, Arrays.asList(fixedDate)))
      }
      runOn(node3) {
        logSignatureDetector ! new LogSignatureDetector.AddLogLine(new LogLine(fixedIp, fixedUsername, Arrays.asList(fixedDate)))
      }
      enterBarrier("updates-done")

      awaitAssert {
        logSignatureDetector ! LogSignatureDetector.GET_LOG_SIGNATURE
        val logSignature = expectMsgType[LogSignature]
        // println(">>>>>>>>>>>>>>>>>>>>> Found data: " + logSignature.lines.asScala.toList);
        logSignature.lines.asScala.toList should be(List(
            new LogLine(fixedIp, fixedUsername, Arrays.asList())))
      }

      enterBarrier("after-3")
    }

  }

}

