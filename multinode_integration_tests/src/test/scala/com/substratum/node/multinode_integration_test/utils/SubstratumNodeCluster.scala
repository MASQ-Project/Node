package com.substratum.node.multinode_integration_test.utils

import java.io.File
import java.net.InetAddress
import scala.collection.immutable.Set

import scala.collection.mutable

object Constants {
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

case class NodeStartupConfig(
  portNumbers: Array[Int]
) {
  def asCommandLineParameter: String = {
    "booga"
  }
}

class SubstratumNode (cluster: SubstratumNodeCluster, val startupConfig: NodeStartupConfig, idx: Int) {
  val name: String = s"test_node_$idx"
  val ipAddress: InetAddress = InetAddress.getByName (s"172.18.1.$idx")

  def stop (): Boolean = {
    val stopNodeSh = new File (Constants.DOCKER_DIR, "stop_node.sh")
    val stopCommand = CommandLine.makeCommand (stopNodeSh.getCanonicalPath, name)
    val success = stopCommand.waitForExit() == 0
    cluster.removeNode (this)
    success
  }
}

class SubstratumNodeCluster (nodeStartupConfigs: NodeStartupConfig*) {

  private val nodes: mutable.HashMap[String, SubstratumNode] = new mutable.HashMap ()
  startNodes (nodeStartupConfigs)

  def runningNodeNames: Set[String] = {
    nodes.keySet.toSet
  }

  def apply(name: String): Option[SubstratumNode] = {
    nodes.get (name)
  }

  def stopAll (): Unit = {
    runningNodeNames.flatMap (name => this (name))
      .foreach (node => node.stop ())
  }

  def removeNode (node: SubstratumNode): Unit = {
    nodes.remove (node.name)
  }

  private def startNodes (nodeStartupConfigs: Seq[NodeStartupConfig]): Unit = {
    val startNodesSh = new File(Constants.DOCKER_DIR, "start_nodes.sh")
    val parameters = nodeStartupConfigs.foldLeft (List (startNodesSh.getCanonicalPath)) {(soFar, config) =>
      config.asCommandLineParameter :: soFar
    }.reverse
    val startCommand = CommandLine.makeCommand(parameters:_*)
    val exitCode = startCommand.waitForExit()
    if (exitCode != 0) {
      throw new IllegalStateException (s"$exitCode: Specified nodes did not start:\n${startCommand.stderrAsString()}")
    }
    nodeStartupConfigs.indices.map {idx => new SubstratumNode (this, nodeStartupConfigs (idx), idx + 1)}
      .foreach {node => nodes (node.name) = node}
  }
}
