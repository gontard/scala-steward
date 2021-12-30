package org.scalasteward.core.vulnerabilities

import cats.Applicative
import cats.implicits._
import org.http4s.{Request, Uri}
import org.scalasteward.core.data.{ArtifactId, GroupId, Update, Version}
import org.scalasteward.core.util.HttpJsonClient

class GitHubVulnerabilitiesApiAlg[F[_]](
                                          gitHubApiHost: Uri,
                                          modify: String => Request[F] => F[Request[F]]
                                        )(implicit
                                          client: HttpJsonClient[F],
                                          F: Applicative[F]
                                        ) extends VulnerabilitiesApiAlg[F] {
  private val graphql = gitHubApiHost / "graphql"

  override def vulnerabilities(update: Update): F[List[Vulnerability]] = {
    update.artifactIds.traverse { artifactId =>
      vulnerabilities(update.groupId, artifactId).map { svo => {
        svo.vulnerabilities.filter { v =>
          v.vulnerableVersionRange.contains(Version(update.nextVersion))
        }.map(sv => Vulnerability(sv.id, sv.permalink))
      }}
    }.map(_.toList.flatten.distinct)
  }

  /** https://docs.github.com/en/graphql/reference/queries#securityvulnerabilityconnection */
  private [vulnerabilities] def vulnerabilities(groupId: GroupId, artifactId: ArtifactId): F[SecurityVulnerabilitiesOut] = {
    val pck = s"$groupId:$artifactId"
    val query =
      s"""query {
         |    securityVulnerabilities(package:"$pck", ecosystem: MAVEN) {
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
    client.postWithBody(graphql, query, modify(query))
  }
}
