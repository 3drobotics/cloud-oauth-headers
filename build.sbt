enablePlugins(JavaAppPackaging)

name := "oauth-headers"
organization := "io.dronekit"
version := "0.2"
scalaVersion := "2.11.7"

resolvers += "Artifactory" at "https://dronekit.artifactoryonline.com/dronekit/libs-snapshot-local/"

credentials += Credentials("Artifactory Realm", "dronekit.artifactoryonline.com", "publish", "Km4-PSH-aEM-6Fm")
isSnapshot := true
publishTo := {
  val artifactory = "https://dronekit.artifactoryonline.com/"
  if (isSnapshot.value)
    Some("snapshots" at artifactory + s"dronekit/libs-snapshot-local;build.timestamp=${new java.util.Date().getTime}")
  else
    Some("snapshots" at artifactory + "dronekit/libs-release-local")
}


libraryDependencies ++= {
  Seq(
    "commons-codec" % "commons-codec" % "1.6",
    "org.scalatest" %% "scalatest" % "2.2.4" % "test")
}
