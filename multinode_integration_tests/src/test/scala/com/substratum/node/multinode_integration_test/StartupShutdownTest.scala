package com.substratum.node.multinode_integration_test

import java.io.IOException
import java.net._

import com.substratum.node.multinode_integration_test.utils._
import org.scalatest.{BeforeAndAfterEach, FunSuite}

import scala.util.matching.Regex

class StartupShutdownTest extends FunSuite with BeforeAndAfterEach {

  test ("Starts and stops SubstratumNodes") {
    val subject: SubstratumNodeCluster = new SubstratumNodeCluster (NodeStartupConfig (Array (1234)),
      NodeStartupConfig (Array (2345)), NodeStartupConfig (Array (3456)))

    assert (subject.runningNodeNames === Set ("test_node_1", "test_node_2", "test_node_3"))
    checkNode (subject, "test_node_1", 1234, "172.18.1.1")
    checkNode (subject, "test_node_2", 2345, "172.18.1.2")
    checkNode (subject, "test_node_3", 3456, "172.18.1.3")
    assert (subject ("test_node_4") === None)

    val result = subject("test_node_1").get.stop ()

    assert (result === true)
    assert (subject.runningNodeNames === Set ("test_node_2", "test_node_3"))
    assert (subject ("test_node_1") === None)
    checkNode (subject, "test_node_2", 2345, "172.18.1.2")
    checkNode (subject, "test_node_3", 3456, "172.18.1.3")

    subject.stopAll ()

    assert (subject.runningNodeNames === Set ())
    assert (subject ("test_node_1") === None)
    assert (subject ("test_node_2") === None)
    assert (subject ("test_node_3") === None)
    checkContainersNonexistent ("test_node_1", "test_node_2", "test_node_3")
  }

  override def beforeEach (): Unit = {
    // TODO: Consider repurposing this code into SubstratumNodeCluster.stopAll ()
    val namesToStop = findRunningContainerNames ()
    if (namesToStop.isEmpty) {
      return
    }
    else {
      println (s"Stopping leaked containers: $namesToStop")
    }
    val parameters = namesToStop.foldLeft (List("docker", "stop", "-t", "0").reverse) {(soFar, nameToStop) =>
      nameToStop :: soFar
    }.reverse
    val stopCommand = CommandLine.makeCommand (parameters:_*)
    assert (stopCommand.waitForExit() === 0, s"Couldn't stop leaked containers $namesToStop:\n${stopCommand.stderrAsString ()}")
  }

  override def afterEach (): Unit = {
    val leakedContainers = findRunningContainerNames()
    assert (leakedContainers.isEmpty, s"ERROR: Some SubstratumNode containers leaked out of the test: $leakedContainers")
  }

  private def findRunningContainerNames (): Seq[String] = {
    val psCommand = CommandLine.makeCommand ("docker", "ps")
    assert (psCommand.waitForExit() === 0, "Couldn't get container list")
    val psOutput = psCommand.stdoutAsString()
    val regex = new Regex ("(test_node_\\d+)")
    regex.findAllIn(psOutput).toSeq
  }

  private def checkNode (cluster: SubstratumNodeCluster, name: String, port: Int, ipAddress: String): Unit = {
    val node = cluster (name).get
    assert (node.name === name)
    assert (node.startupConfig.portNumbers === Array (port))
    assert (node.ipAddress === InetAddress.getByName (ipAddress))
    ensureNodeIsRunning(name, ipAddress)
  }

  private def nodeIsRunning(ipAddress: String): Boolean = {
    try {
      val socket = new Socket()
      val address = new InetSocketAddress(InetAddress.getByName(ipAddress), 80)
      socket.connect(address, 100)
      socket.close()
      true
    }
    catch {
      case _: SocketTimeoutException => {
        false // expected; don't bother with stack trace
      }
      case e: IOException => {
        e.printStackTrace(System.out)
        false
      }
    }
  }

  private def checkContainersNonexistent (names: String*): Unit = {
    val command = CommandLine.makeCommand("docker", "ps", "-a")
    val exitCode = command.waitForExit()
    assert (exitCode === 0)
    val output = command.stdoutAsString()
    names.foreach (name => assert (output.contains (name) === false, s"Container $name should be gone, but isn't:\n$output"))
  }

  private def ensureNodeIsRunning (containerName: String, ipAddress: String): Unit = {
    assert(nodeIsRunning(ipAddress) === true, s"$containerName should be running on $ipAddress, but isn't")
  }
}
