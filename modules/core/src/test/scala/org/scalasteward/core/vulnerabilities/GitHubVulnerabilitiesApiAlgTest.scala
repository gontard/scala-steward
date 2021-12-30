package org.scalasteward.core.vulnerabilities

import cats.effect.IO
import cats.effect.unsafe.implicits.global
import io.circe.literal._
import munit.FunSuite
import org.http4s.{HttpRoutes, Uri}
import org.http4s.circe._
import org.http4s.client.Client
import org.http4s.dsl.io._
import org.http4s.implicits._
import org.scalasteward.core.data.{ArtifactId, GroupId, Version}
import org.scalasteward.core.mock.MockConfig.config
import org.scalasteward.core.util.HttpJsonClient
import org.scalasteward.core.vulnerabilities.VersionRange.{Between, Since, Until}

class GitHubVulnerabilitiesApiAlgTest extends FunSuite {
  val routes: HttpRoutes[IO] =
    HttpRoutes.of[IO] {
      case req @ POST -> Root / "graphql" =>
        val query = """query {
                      |    securityVulnerabilities(package:"org.apache.logging.log4j:ArtifactId(log4j,None)", ecosystem: MAVEN) {
                      |      nodes {
                      |        advisory {
                      |          identifiers {
                      |            type,
                      |            value
                      |          },
                      |          permalink
                      |        },
                      |        package {
                      |          ecosystem,
                      |          name
                      |        },
                      |        firstPatchedVersion {
                      |          identifier
                      |        },
                      |        vulnerableVersionRange,
                      |        severity
                      |      }
                      |    }
                      |  }""".stripMargin
        req.decodeJson[String].flatMap {
          case `query` => Ok(vulnerabilities)
          case r =>
            println("HERE1")
            println(r)
            NotFound()
        }
      case req =>
        println("HERE2")
        println(req.toString())
        NotFound()
    }

  val vulnerabilities =
    json"""{
      "data": {
        "securityVulnerabilities": {
          "nodes": [
            {
              "advisory": {
                "identifiers": [
                  {
                    "type": "GHSA",
                    "value": "GHSA-vwqq-5vrc-xw9h"
                  },
                  {
                    "type": "CVE",
                    "value": "CVE-2020-9488"
                  }
                ],
                "permalink": "https://github.com/advisories/GHSA-vwqq-5vrc-xw9h"
              },
              "package": {
                "ecosystem": "MAVEN",
                "name": "org.apache.logging.log4j:log4j"
              },
              "firstPatchedVersion": {
                "identifier": "2.13.2"
              },
              "vulnerableVersionRange": "< 2.13.2",
              "severity": "LOW"
            },
            {
              "advisory": {
                "identifiers": [
                  {
                    "type": "GHSA",
                    "value": "GHSA-fxph-q3j8-mv87"
                  },
                  {
                    "type": "CVE",
                    "value": "CVE-2017-5645"
                  }
                ],
                "permalink": "https://github.com/advisories/GHSA-fxph-q3j8-mv87"
              },
              "package": {
                "ecosystem": "MAVEN",
                "name": "org.apache.logging.log4j:log4j"
              },
              "firstPatchedVersion": {
                "identifier": "2.8.2"
              },
              "vulnerableVersionRange": ">= 2.0, < 2.8.2",
              "severity": "CRITICAL"
            }
          ]
        }
      }
    } """

  implicit val client: Client[IO] = Client.fromHttpApp(routes.orNotFound)
  implicit val httpJsonClient: HttpJsonClient[IO] = new HttpJsonClient[IO]
  val gitHubVulnerabilitiesApiAlg =
    new GitHubVulnerabilitiesApiAlg[IO](config.vcsCfg.apiHost, _ => IO.pure)

  test("vulnerabilities") {
    val vulnerabilitiesOut = gitHubVulnerabilitiesApiAlg
      .vulnerabilities(GroupId("org.apache.logging.log4j"), ArtifactId("log4j"))
      .unsafeRunSync()
    assertEquals(vulnerabilitiesOut, SecurityVulnerabilitiesOut(Seq(
      SecurityVulnerability(
        Version("2.13.2"),
        Until(Version("2.13.2"), inclusive = false),
        Uri.unsafeFromString("https://github.com/advisories/GHSA-vwqq-5vrc-xw9h"),
        Severity.Low
      ),
      SecurityVulnerability(
        Version("2.8.2"),
        Between(Since(Version("2.0"), inclusive = true), Until(Version("2.8.2"), inclusive = false)),
        Uri.unsafeFromString("https://github.com/advisories/GHSA-fxph-q3j8-mv87"),
        Severity.Critical
      )
    )))
  }
}
