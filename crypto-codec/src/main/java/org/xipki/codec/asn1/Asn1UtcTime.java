// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * UTC Time
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1UtcTime extends AbstractAsn1Time {

  private static final DateTimeFormatter UTC_TIME =
          DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);

  /**
   * YYMMDDhhmm[ss](Z|(+|-)hhmm), X.680 47.3. DER (X.690 11.8) requires the seconds and 'Z'.
   */
  private static final Pattern PATTERN =
      Pattern.compile("(\\d{2})(\\d{2})(\\d{2})(\\d{2})(\\d{2})(\\d{2})?(Z|[+-]\\d{4})");

  private final Instant time;

  private final String text;

  public static Asn1UtcTime fromEncoded(byte[] encoded) throws CodecException {
    return (Asn1UtcTime) Asn1Util.readAsn1Object(Asn1Tags.UTC_TIME, encoded);
  }

  public Asn1UtcTime(Instant time) {
    this.time = Args.notNull(time, "time").truncatedTo(ChronoUnit.SECONDS);
    this.text = UTC_TIME.format(time);
  }

  public Asn1UtcTime(String utcTime) {
    this(parse(utcTime));
  }

  private static Instant parse(String text) {
    Matcher m = PATTERN.matcher(Args.notNull(text, "utcTime"));
    if (!m.matches()) {
      throw new IllegalArgumentException("invalid UTCTime " + text);
    }

    // RFC 5280 4.1.2.5.1: YY >= 50: 19YY, YY < 50: 20YY
    int yy = Integer.parseInt(m.group(1));
    int year = yy >= 50 ? 1900 + yy : 2000 + yy;
    LocalDateTime dt = LocalDateTime.of(year, Integer.parseInt(m.group(2)),
        Integer.parseInt(m.group(3)), Integer.parseInt(m.group(4)),
        Integer.parseInt(m.group(5)), m.group(6) == null ? 0 : Integer.parseInt(m.group(6)));
    String zone = m.group(7);
    return dt.toInstant("Z".equals(zone) ? ZoneOffset.UTC : ZoneOffset.of(zone));
  }

  @Override
  public PrimitiveType type() {
    return PrimitiveType.UTC_TIME;
  }

  @Override
  public boolean isConstructed() {
    return false;
  }

  @Override
  public int getTagNo() {
    return Asn1Tags.UTC_TIME;
  }

  @Override
  public int getEncodedLength(Asn1Encoding encoding) {
    return text.length();
  }

  @Override
  public Instant getTime() {
    return time;
  }

  @Override
  public String getText() {
    return text;
  }

  @Override
  public int hashCode() {
    return text.hashCode();
  }

  @Override
  protected boolean doEquals(Asn1Primitive obj) {
    if (!(obj instanceof Asn1UtcTime)) {
      return false;
    }

    Asn1UtcTime b = (Asn1UtcTime) obj;
    return text.equals(b.text);
  }

  @Override
  public String toString() {
    return text;
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    return ToStringUtil.appendIndent(buf,indentLevel, text);
  }

}
