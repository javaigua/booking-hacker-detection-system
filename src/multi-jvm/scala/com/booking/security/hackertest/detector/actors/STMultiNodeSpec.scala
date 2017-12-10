package com.booking.security.hackertest.detector.actors

import akka.remote.testkit.MultiNodeSpecCallbacks

import org.scalatest.{ BeforeAndAfterAll, WordSpecLike }
import org.scalatest.Matchers

/**
 * Hooks up MultiNodeSpec with ScalaTest
 */
trait STMultiNodeSpec extends MultiNodeSpecCallbacks
  with WordSpecLike with Matchers with BeforeAndAfterAll {

  override def beforeAll() = multiNodeSpecBeforeAll()

  override def afterAll() = multiNodeSpecAfterAll()
}
