enablePlugins(JavaAppPackaging)

name := "oauth-headers"
organization := "io.dronekit"
version := "0.1"
scalaVersion := "2.11.7"

libraryDependencies ++= {
  Seq(
    "commons-codec" % "commons-codec" % "1.6",
    "org.scalatest" %% "scalatest" % "2.2.4" % "test")
}
