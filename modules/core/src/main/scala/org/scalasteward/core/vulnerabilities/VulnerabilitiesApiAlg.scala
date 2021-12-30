package org.scalasteward.core.vulnerabilities

import org.http4s.Uri
import org.scalasteward.core.data.Update

trait VulnerabilitiesApiAlg[F[_]] {
  def vulnerabilities(update: Update): F[List[Vulnerability]]
}

case class Vulnerability(id: String, permalink: Uri)