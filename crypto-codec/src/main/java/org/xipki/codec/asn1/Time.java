// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.time.Instant;

/**
 * <pre>
 * Time ::= CHOICE {
 *      utcTime        UTCTime,
 *      generalTime    GeneralizedTime }
 * </pre>
 * @author Lijun Liao (xipki)
 */
public class Time extends Asn1Encodable {

  // 2050-01-01T00:00
  private static final long epochSecondsStart2050 =
      Instant.parse("2050-01-01T00:00:00Z").getEpochSecond();

  // 1950-01-01T00:00
  private static final long epochSecondsStart1950 =
      Instant.parse("1950-01-01T00:00:00Z").getEpochSecond();

  private final Asn1UtcTime utcTime;

  private final Asn1GeneralizedTime generalTime;

  public Time(Asn1UtcTime time) {
    this.utcTime = Args.notNull(time, "time");
    this.generalTime = null;
  }

  public Time(Asn1GeneralizedTime time) {
    this.utcTime = null;
    this.generalTime = Args.notNull(time, "time");
  }

  /**
   * Creates a time object from a given date - if the date is between 1950
   * and 2049 a UTCTime object is generated, otherwise a GeneralizedTime
   * is used.
   *
   * @param time a date object representing the time of interest.
   */
  public Time(Instant time) {
    long epochSeconds = time.getEpochSecond();
    if (epochSeconds < epochSecondsStart2050 && epochSeconds >= epochSecondsStart1950) {
      this.utcTime = new Asn1UtcTime(time);
      this.generalTime = null;
    } else {
      this.utcTime = null;
      this.generalTime = new Asn1GeneralizedTime(time);
    }
  }

  public static Time fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(AbstractAsn1Time.fromEncoded(encoded));
  }

  public static Time fromAsn1(AbstractAsn1Time time) {
    if (time instanceof Asn1UtcTime) {
      return new Time((Asn1UtcTime) time);
    } else { // if (time instanceof Asn1GeneralizedTime) {
      return new Time((Asn1GeneralizedTime)time);
    }
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  public String getTime() {
    return (utcTime != null) ? utcTime.getText() : generalTime.getText();
  }

  public Instant time() {
    return utcTime != null ? Asn1Util.fromAsn1(utcTime) : Asn1Util.fromAsn1(generalTime);
  }

  @Override
  public AbstractAsn1Time toAsn1Primitive() {
    return utcTime != null ? utcTime : generalTime;
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    return toAsn1Primitive().toString(buf, indentLevel);
  }

}
