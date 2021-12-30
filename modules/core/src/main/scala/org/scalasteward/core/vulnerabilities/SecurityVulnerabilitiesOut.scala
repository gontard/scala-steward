package org.scalasteward.core.vulnerabilities

import cats.syntax.all._
import io.circe.{Decoder, DecodingFailure}
import org.http4s.Uri
import org.scalasteward.core.data.Version

case class SecurityVulnerabilitiesOut(vulnerabilities: Seq[SecurityVulnerability])

object SecurityVulnerabilitiesOut {
  implicit val decoder: Decoder[SecurityVulnerabilitiesOut] = Decoder.instance { c =>
    c.downField("data")
      .downField("securityVulnerabilities")
      .downField("nodes")
      .as[List[SecurityVulnerability]]
      .map(SecurityVulnerabilitiesOut(_))
  }
}

case class SecurityVulnerability(
                                  firstPatchedVersion: Version,
                                  vulnerableVersionRange: VersionRange,
                                  permalink: Uri,
                                  severity: Severity
                                ) {
  lazy val id: String = permalink.path.segments.last.toString
}

object SecurityVulnerability {

  implicit val decoder: Decoder[SecurityVulnerability] = Decoder.instance { c =>
    for {
      firstPatchedVersion <- c.downField("firstPatchedVersion").downField("identifier").as[Version]
      permalink <- c.downField("advisory").downField("permalink").as[String].map(Uri.unsafeFromString)
      vulnerableVersionRange <- c.downField("vulnerableVersionRange").as[VersionRange]
      severity <- c.downField("severity").as[Severity]
    }
    yield {
      SecurityVulnerability(firstPatchedVersion, vulnerableVersionRange, permalink, severity)
    }
  }
}

/**
 * https://docs.github.com/en/graphql/reference/enums#securityadvisoryseverity
 */
sealed trait Severity extends Product with Serializable

object Severity {
  case object Critical extends Severity

  case object High extends Severity

  case object Low extends Severity

  case object Moderate extends Severity

  implicit val decoder: Decoder[Severity] = Decoder.instance { c =>
    c.as[String].flatMap {
      case "CRITICAL" => Critical.asRight
      case "HIGH" => High.asRight
      case "LOW" => Low.asRight
      case "MODERATE" => Moderate.asRight
      case _ => DecodingFailure("severity", c.history).asLeft
    }
  }
}

sealed trait VersionRange extends Product with Serializable {
  def contains(other: Version): Boolean
}

object VersionRange {
  /**
   * Denotes a single vulnerable version.
   */
  case class Single(version: Version) extends VersionRange {
    override def contains(other: Version): Boolean = other == version
  }

  /**
   * Denotes a version range with a known minimum.
   */
  case class Since(version: Version, inclusive: Boolean) extends VersionRange {
    override def contains(other: Version): Boolean =
      if (inclusive) version <= other else version < other
  }

  /**
   * Denotes a version range up to and including or excluding the specified version.
   */
  case class Until(version: Version, inclusive: Boolean) extends VersionRange {
    override def contains(other: Version): Boolean =
      if (inclusive) version >= other else version > other
  }

  /**
   * Denotes a version range with a known minimum and maximum version.
   */
  case class Between(since: Since, until: Until) extends VersionRange {
    override def contains(other: Version): Boolean =
      since.contains(other) && until.contains(other)
  }

  // Ex: '= 0.2.0'
  private lazy val singleR = raw"= ([^\s]+)".r
  // Ex: '>= 0.0.1'
  private lazy val sinceR = raw">(=?) ([^\s]+)".r
  // Ex: `<= 1.0.8` or `< 0.1.11`
  private lazy val untilR = raw"<(=?) ([^\s]+)".r
  // Ex: `>= 4.3.0, < 4.3.5`
  private lazy val betweenR = raw">(=?) ([^\s]+), <(=?) ([^\s]+)".r

  def fromString(value: String): Option[VersionRange] = {
    value match {
      case singleR(v) => Some(Single(Version(v)))
      case sinceR(e, v) => Some(Since(Version(v), inclusive = e == "="))
      case untilR(e, v) => Some(Until(Version(v), inclusive = e == "="))
      case betweenR(es, s, eu, u) => Some(
        Between(
          Since(Version(s), inclusive = es == "="),
          Until(Version(u), inclusive = eu == "=")
        )
      )
      case _ => None
    }
  }

  implicit val decoder: Decoder[VersionRange] = Decoder.instance { c =>
    c.as[String].map(fromString).flatMap { maybeRange =>
      maybeRange.toRight(DecodingFailure("versionRange", c.history))
    }
  }
}