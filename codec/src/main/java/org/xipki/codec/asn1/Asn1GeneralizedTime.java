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
 * Generalized Time
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1GeneralizedTime extends AbstractAsn1Time {

  private static final DateTimeFormatter GENERALIZED_TIME =
          DateTimeFormatter.ofPattern("yyyyMMddHHmmss")
                  .withZone(ZoneOffset.UTC);

  /**
   * YYYYMMDDhhmm[ss[(.|,)f+]](Z|(+|-)hh[mm]), X.680 46.3. The local time without 'Z' or
   * time differential is not supported.
   * DER (X.690 11.7) requires the seconds, 'Z', '.' as decimal separator, and no trailing
   * zeros in the fraction.
   */
  private static final Pattern PATTERN = Pattern.compile(
      "(\\d{4})(\\d{2})(\\d{2})(\\d{2})(\\d{2})(?:(\\d{2})(?:[.,](\\d{1,9}))?)?"
          + "(Z|[+-]\\d{2}(?:\\d{2})?)");

  private final Instant time;

  private final String text;

  public static Asn1GeneralizedTime fromEncoded(byte[] encoded) throws CodecException {
    return (Asn1GeneralizedTime) Asn1Util.readAsn1Object(Asn1Tags.GENERALIZED_TIME, encoded);
  }

  /**
   * Constructor. The fraction of seconds is removed, as required in RFC 5280.
   * @param time the time.
   */
  public Asn1GeneralizedTime(Instant time) {
    this(time, true);
  }

  /**
   * Constructor. The fraction of seconds is kept, e.g. for the genTime in TSTInfo
   * (RFC 3161).
   * @param generalizedTime the text.
   */
  public Asn1GeneralizedTime(String generalizedTime) {
    this(parse(generalizedTime), false);
  }

  private Asn1GeneralizedTime(Instant time, boolean truncateToSeconds) {
    Args.notNull(time, "time");
    this.time = truncateToSeconds ? time.truncatedTo(ChronoUnit.SECONDS) : time;
    this.text = format(this.time);
  }

  private static String format(Instant time) {
    String text = GENERALIZED_TIME.format(time);
    int nanos = time.getNano();
    if (nanos == 0) {
      return text + "Z";
    }

    // fraction without trailing zeros
    String fraction = String.format("%09d", nanos);
    int end = fraction.length();
    while (fraction.charAt(end - 1) == '0') {
      end--;
    }
    return text + "." + fraction.substring(0, end) + "Z";
  }

  private static Instant parse(String text) {
    Matcher m = PATTERN.matcher(Args.notBlank(text, "generalizedTime"));
    if (!m.matches()) {
      throw new IllegalArgumentException("invalid or unsupported GeneralizedTime " + text);
    }

    int nanos = 0;
    if (m.group(7) != null) {
      String fraction = (m.group(7) + "000000000").substring(0, 9);
      nanos = Integer.parseInt(fraction);
    }

    LocalDateTime dt = LocalDateTime.of(Integer.parseInt(m.group(1)),
        Integer.parseInt(m.group(2)), Integer.parseInt(m.group(3)),
        Integer.parseInt(m.group(4)), Integer.parseInt(m.group(5)),
        m.group(6) == null ? 0 : Integer.parseInt(m.group(6)), nanos);
    String zone = m.group(8);
    return dt.toInstant("Z".equals(zone) ? ZoneOffset.UTC : ZoneOffset.of(zone));
  }

  @Override
  public PrimitiveType type() {
    return PrimitiveType.GENERALIZED_TIME;
  }

  @Override
  public boolean isConstructed() {
    return false;
  }

  @Override
  public int getTagNo() {
    return Asn1Tags.GENERALIZED_TIME;
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
    if (!(obj instanceof Asn1GeneralizedTime)) {
      return false;
    }

    Asn1GeneralizedTime b = (Asn1GeneralizedTime) obj;
    return text.equals(b.text);
  }

  @Override
  public String toString() {
    StringBuilder buf = new StringBuilder();
    toString(buf, 0);
    return buf.toString();
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    return ToStringUtil.appendIndent(buf,indentLevel, text);
  }

}
