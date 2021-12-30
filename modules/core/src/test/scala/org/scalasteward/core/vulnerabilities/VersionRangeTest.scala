package org.scalasteward.core.vulnerabilities

import munit.FunSuite
import org.scalasteward.core.data.Version
import org.scalasteward.core.vulnerabilities.VersionRange._

class VersionRangeTest extends FunSuite {

  test("fromString: single") {
    assertEquals(
      VersionRange.fromString("= 0.2.0"),
      Some(Single(Version("0.2.0")))
    )
  }

  test("fromString: since inclusive") {
    assertEquals(
      VersionRange.fromString(">= 0.0.1"),
      Some(Since(Version("0.0.1"), inclusive = true))
    )
  }

  test("fromString: since exclusive") {
    assertEquals(
      VersionRange.fromString("> 2.3.3"),
      Some(Since(Version("2.3.3"), inclusive = false))
    )
  }

  test("fromString: until inclusive") {
    assertEquals(
      VersionRange.fromString("<= 1.0.8"),
      Some(Until(Version("1.0.8"), inclusive = true))
    )
  }

  test("fromString: until exclusive") {
    assertEquals(
      VersionRange.fromString("< 0.1.11"),
      Some(Until(Version("0.1.11"), inclusive = false))
    )
  }

  test("fromString: between since inclusive & until inclusive") {
    assertEquals(
      VersionRange.fromString(">= 2.0, <= 2.8.2"),
      Some(Between(Since(Version("2.0"), inclusive = true), Until(Version("2.8.2"), inclusive = true)))
    )
  }

  test("fromString: between since inclusive & until exclusive") {
    assertEquals(
      VersionRange.fromString(">= 2.0, < 2.8.2"),
      Some(Between(Since(Version("2.0"), inclusive = true), Until(Version("2.8.2"), inclusive = false)))
    )
  }

  test("fromString: between since exclusive & until inclusive") {
    assertEquals(
      VersionRange.fromString("> 2.0, <= 2.8.2"),
      Some(Between(Since(Version("2.0"), inclusive = false), Until(Version("2.8.2"), inclusive = true)))
    )
  }

  test("fromString: between since exclusive & until exclusive") {
    assertEquals(
      VersionRange.fromString("> 2.0, < 2.8.2"),
      Some(Between(Since(Version("2.0"), inclusive = false), Until(Version("2.8.2"), inclusive = false)))
    )
  }

  test("fromString: invalid values") {
    assert(VersionRange.fromString("2.8.2").isEmpty)
    assert(VersionRange.fromString("2.6 <").isEmpty)
    assert(VersionRange.fromString("2.0 < x < 2.8.2").isEmpty)
  }

  test("contains: single") {
    assertVersionRangeContains("= 1.2.1", "1.2.1")
    assertVersionRangeNotContains("= 1.4.1", "1.2.2")
  }

  test("contains: since inclusive") {
    assertVersionRangeContains(">= 1.2.1", "1.2.1")
    assertVersionRangeContains(">= 1.2.1", "1.2.2")
    assertVersionRangeContains(">= 1.2.1", "2.1")
    assertVersionRangeNotContains(">= 1.2.1", "1.2.0")
    assertVersionRangeNotContains(">= 1.2.1", "1.0")
  }

  test("contains: since inclusive") {
    assertVersionRangeContains("> 1.2.1", "1.2.2")
    assertVersionRangeContains("> 1.2.1", "2.1")
    assertVersionRangeNotContains("> 1.2.1", "1.2.1")
    assertVersionRangeNotContains("> 1.2.1", "1.0")
  }

  test("contains: until inclusive") {
    assertVersionRangeContains("<= 1.2.1", "1.2.0")
    assertVersionRangeContains("<= 1.2.1", "1.2.1")
    assertVersionRangeContains("<= 1.2.1", "0.8")
    assertVersionRangeNotContains("<= 1.2.1", "1.2.2")
    assertVersionRangeNotContains("<= 1.2.1", "2.0")
  }

  test("contains: until exclusive") {
    assertVersionRangeContains("< 1.2.1", "1.2.0")
    assertVersionRangeContains("< 1.2.1", "0.8")
    assertVersionRangeNotContains("< 1.2.1", "1.2.1")
    assertVersionRangeNotContains("< 1.2.1", "2.0")
  }

  test("contains: between since inclusive & until inclusive") {
    assertVersionRangeContains(">= 1.2.1, <= 1.7.8", "1.2.1")
    assertVersionRangeContains(">= 1.2.1, <= 1.7.8", "1.7.8")
    assertVersionRangeContains(">= 1.2.1, <= 1.7.8", "1.3.8")
    assertVersionRangeNotContains(">= 1.2.1, <= 1.7.8", "1.2.0")
    assertVersionRangeNotContains(">= 1.2.1, <= 1.7.8", "1.7.9")
  }

  test("contains: between since inclusive & until exclusive") {
    assertVersionRangeContains(">= 1.2.1, < 1.7.8", "1.2.1")
    assertVersionRangeContains(">= 1.2.1, < 1.7.8", "1.7.7")
    assertVersionRangeContains(">= 1.2.1, < 1.7.8", "1.3.8")
    assertVersionRangeNotContains(">= 1.2.1, < 1.7.8", "1.2.0")
    assertVersionRangeNotContains(">= 1.2.1, < 1.7.8", "1.7.8")
  }

  test("contains:  between since exclusive & until inclusive") {
    assertVersionRangeContains("> 1.2.1, <= 1.7.8", "1.2.2")
    assertVersionRangeContains("> 1.2.1, <= 1.7.8", "1.7.8")
    assertVersionRangeContains("> 1.2.1, <= 1.7.8", "1.3.8")
    assertVersionRangeNotContains("> 1.2.1, <= 1.7.8", "1.2.1")
    assertVersionRangeNotContains("> 1.2.1, <= 1.7.8", "1.7.9")
  }

  test("contains:  between since exclusive & until exclusive") {
    assertVersionRangeContains("> 1.2.1, < 1.7.8", "1.2.2")
    assertVersionRangeContains("> 1.2.1, < 1.7.8", "1.7.7")
    assertVersionRangeContains("> 1.2.1, < 1.7.8", "1.3.8")
    assertVersionRangeNotContains("> 1.2.1, < 1.7.8", "1.2.1")
    assertVersionRangeNotContains("> 1.2.1, < 1.7.8", "1.7.8")
  }

  private def assertVersionRangeContains(range: String, version: String): Unit =
    assert(VersionRange.fromString(range).get.contains(Version(version)), s"$range must contain $version")

  private def assertVersionRangeNotContains(range: String, version: String): Unit =
    assert(!VersionRange.fromString(range).get.contains(Version(version)), s"$range must not contain $version")
}
