scalaVersion := "3.3.3"

name := "Linux-Networking"

version := "1.0"

Test / envVars := Map(
  "AWS_DEFAULT_REGION" -> "eu-west-1",
  "AWS_REGION" -> "eu-west-1"
)
IntegrationTest / fork := true
IntegrationTest / envVars := Map(
  "AWS_DEFAULT_REGION" -> "eu-west-1",
  "AWS_REGION" -> "eu-west-1"
)
