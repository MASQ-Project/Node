// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
package com.substratum.node.multinode_integration_test

import java.io.{File, IOException}
import java.net.{InetAddress, InetSocketAddress, Socket, SocketTimeoutException}

import com.substratum.node.multinode_integration_test.utils.{Command, CommandLine}
import org.scalatest.FunSuite

object NakedScriptTest {
  val MODULE_DIR_NAME: String = "multinode_integration_tests"
  val DOCKER_DIR: File = {
    val currentDir = new File(".")
    val possibleModuleDir = new File(currentDir, MODULE_DIR_NAME)
    val dockerDir = if (possibleModuleDir.exists()) {
      new File(possibleModuleDir, "docker")
    }
    else {
      new File(currentDir, "docker")
    }
    assert(dockerDir.exists && dockerDir.isDirectory, "Test must be run from a directory containing either docker or " +
      MODULE_DIR_NAME + "/docker, not " + currentDir.getCanonicalPath)
    dockerDir
  }
}

class NakedScriptTest extends FunSuite {

  import NakedScriptTest._

  test("Containers can be started and stopped") {
    ensureNodeIsNotRunning ("test_node_1", "172.18.1.1")
    ensureNodeIsNotRunning ("test_node_2", "172.18.1.2")

    val startNodesSh = new File(DOCKER_DIR, "start_nodes.sh")
    val startCommand = CommandLine.makeCommand(startNodesSh.getCanonicalPath, "1234", "2345")
    val exitCode = startCommand.waitForExit()

    dumpOutput (startCommand)
    assert(exitCode === 0)

    ensureNodeIsRunning ("test_node_1", "172.18.1.1")
    ensureNodeIsRunning ("test_node_2", "172.18.1.2")

    stopAndVerify ("test_node_1", "172.18.1.1")
    stopAndVerify ("test_node_2", "172.18.1.2")
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

  private def stopAndVerify (containerName: String, ipAddress: String): Unit = {
    val stopNodeSh = new File(DOCKER_DIR, "stop_node.sh")
    val command = CommandLine.makeCommand(stopNodeSh.getCanonicalPath, containerName)
    val exitCode = command.waitForExit()
    dumpOutput (command)
    assert(exitCode === 0)
    ensureNodeIsNotRunning (containerName, ipAddress)
  }

  private def ensureNodeIsRunning (containerName: String, ipAddress: String): Unit = {
    assert(nodeIsRunning(ipAddress) === true, s"$containerName should be running on $ipAddress, but isn't")
  }

  private def ensureNodeIsNotRunning (containerName: String, ipAddress: String): Unit = {
    assert(nodeIsRunning(ipAddress) === false, s"$containerName should not be running but is, on $ipAddress")
  }

  private def dumpOutput (command: Command): Unit = {
    println("------ stdout ------\n" + command.stdoutAsString ())
    println("------ stderr ------\n" + command.stderrAsString ())
    println("--------------------")
  }
}
