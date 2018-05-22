// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
package com.substratum.node.multinode_integration_test.utils

import java.io.{InputStream, OutputStream}
import java.util.concurrent.CountDownLatch

import scala.io.Source
import scala.sys.process.{Process, ProcessIO}

object CommandLine {
  def makeCommand (pieces: String*): Command = {

    val latch = new CountDownLatch(3)
    val stdin: Array[OutputStream] = Array (null)
    val stdout: Array[InputStream] = Array (null)
    val stderr: Array[InputStream] = Array (null)
    val processIO = new ProcessIO (
      s => {stdin (0) = s; latch.countDown ()},
      s => {stdout (0) = s; latch.countDown ()},
      s => {stderr (0) = s; latch.countDown ()}
    )
    val builder = Process (pieces)
    val process = builder.run (processIO)
    latch.await ()
    new Command (process, stdin (0), stdout (0), stderr (0))
  }
}

class Command (process: Process, val stdin: OutputStream, val stdout: InputStream, val stderr: InputStream) {
  def waitForExit (): Int = {
    process.exitValue ()
  }

  def stdoutAsString (): String = {
    streamAsString (stdout)
  }

  def stderrAsString (): String = {
    streamAsString (stderr)
  }

  private def streamAsString (stream: InputStream): String = {
    if (stream.available() == 0) {
      ""
    }
    else {
      Source.fromInputStream(stream).mkString
    }
  }
}
