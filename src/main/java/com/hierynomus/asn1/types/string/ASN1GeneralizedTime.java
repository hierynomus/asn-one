/*
 *    Copyright 2016 Jeroen van Erp <jeroen@hierynomus.com>
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
package com.hierynomus.asn1.types.string;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Locale;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.hierynomus.asn1.ASN1ParseException;
import com.hierynomus.asn1.ASN1Parser;
import com.hierynomus.asn1.encodingrules.ASN1Decoder;
import com.hierynomus.asn1.encodingrules.ASN1Encoder;
import com.hierynomus.asn1.types.ASN1Tag;

import static com.hierynomus.asn1.util.Checks.checkFormat;

/**
 * ASN.1 GeneralizedTime (UNIVERSAL 24, X.680 clause 46), defined as a VisibleString of the form
 * {@code YYYYMMDDhh[mm[ss]]}, optionally followed by a decimal fraction (with {@code .} or {@code ,}) of the last
 * element, and then either nothing (local time), {@code Z} (UTC), or a {@code +hh[mm]}/{@code -hh[mm]} offset.
 * <p>
 * A value created from a {@link Date} is always in the DER form (X.690 11.7): {@code YYYYMMDDhhmmss[.f]Z}, where the
 * fraction is omitted when zero and has no trailing zeros. As with all {@link ASN1CharacterString character
 * strings}, parsing is lenient: malformed content is only reported when calling {@link #getDate()}.
 * <p>
 * Equality is based on the string value, so two encodings of the same instant in a different form are not equal.
 */
public class ASN1GeneralizedTime extends ASN1CharacterString {
    private static final Pattern GENERALIZED_TIME = Pattern.compile(
        "(\\d{4})(\\d{2})(\\d{2})(\\d{2})(?:(\\d{2})(\\d{2})?)?(?:[.,](\\d+))?(Z|([+-])(\\d{2})(\\d{2})?)?");
    private static final TimeZone UTC = TimeZone.getTimeZone("UTC");
    private static final long MILLIS_PER_SECOND = 1000L;
    private static final long MILLIS_PER_MINUTE = 60 * MILLIS_PER_SECOND;
    private static final long MILLIS_PER_HOUR = 60 * MILLIS_PER_MINUTE;

    /**
     * @param date the moment in time, which must lie in the years 1 up to and including 9999
     * @throws IllegalArgumentException if the date cannot be represented as a GeneralizedTime
     */
    public ASN1GeneralizedTime(Date date) {
        this(ASN1Tag.GENERALIZED_TIME, date);
    }

    public ASN1GeneralizedTime(ASN1Tag<?> tag, Date date) {
        super(tag, format(date), StandardCharsets.US_ASCII);
    }

    /**
     * @param value a GeneralizedTime string, e.g. {@code 20250101120000Z}
     * @throws IllegalArgumentException if the value is not a valid GeneralizedTime
     */
    public ASN1GeneralizedTime(String value) {
        this(ASN1Tag.GENERALIZED_TIME, value);
    }

    public ASN1GeneralizedTime(ASN1Tag<?> tag, String value) {
        super(tag, checkValid(value), StandardCharsets.US_ASCII);
    }

    private ASN1GeneralizedTime(ASN1Tag<?> tag, byte[] bytes) {
        // ISO-8859-1 maps every octet to a character, so even non-conforming content survives a round trip.
        super(tag, bytes, StandardCharsets.ISO_8859_1);
    }

    /**
     * A value without {@code Z} or offset denotes local time (X.680 46.3 a); it is interpreted in the JVM's default
     * time zone, as there is no other information to go on.
     *
     * @return the moment in time this GeneralizedTime represents, truncated to milliseconds
     * @throws ASN1ParseException if the value is not a valid GeneralizedTime
     */
    public Date getDate() {
        return parse(getValue());
    }

    private static Date parse(String value) {
        Matcher m = GENERALIZED_TIME.matcher(value);
        checkFormat(m.matches(), "Invalid ASN.1 GeneralizedTime: '%s'", value);
        String zone = m.group(8);
        Calendar calendar = newCalendar(zone == null ? TimeZone.getDefault() : UTC);
        calendar.set(Integer.parseInt(m.group(1)),
            Integer.parseInt(m.group(2)) - 1,
            Integer.parseInt(m.group(3)),
            Integer.parseInt(m.group(4)),
            m.group(5) != null ? Integer.parseInt(m.group(5)) : 0,
            m.group(6) != null ? Integer.parseInt(m.group(6)) : 0);

        long fractionMillis = 0;
        if (m.group(7) != null) {
            // The fraction applies to the last element present (X.680 46.2)
            long unit = m.group(6) != null ? MILLIS_PER_SECOND : m.group(5) != null ? MILLIS_PER_MINUTE : MILLIS_PER_HOUR;
            fractionMillis = new BigDecimal("0." + m.group(7)).multiply(BigDecimal.valueOf(unit)).longValue();
        }

        long offsetMillis = 0;
        if (m.group(9) != null) {
            int offsetHours = Integer.parseInt(m.group(10));
            int offsetMinutes = m.group(11) != null ? Integer.parseInt(m.group(11)) : 0;
            checkFormat(offsetHours <= 23 && offsetMinutes <= 59, "Invalid offset in ASN.1 GeneralizedTime: '%s'", value);
            offsetMillis = (offsetHours * MILLIS_PER_HOUR + offsetMinutes * MILLIS_PER_MINUTE) * ("-".equals(m.group(9)) ? -1 : 1);
        }
        try {
            // With an offset, the fields denote local time at that offset, so subtract it to get to UTC.
            return new Date(calendar.getTimeInMillis() + fractionMillis - offsetMillis);
        } catch (IllegalArgumentException e) {
            throw new ASN1ParseException(e, "Invalid date or time in ASN.1 GeneralizedTime: '%s'", value);
        }
    }

    private static String format(Date date) {
        Calendar calendar = newCalendar(UTC);
        calendar.setTime(date);
        if (calendar.get(Calendar.ERA) != GregorianCalendar.AD || calendar.get(Calendar.YEAR) > 9999) {
            throw new IllegalArgumentException("ASN.1 GeneralizedTime can only represent the years 1-9999: " + date);
        }
        StringBuilder sb = new StringBuilder(String.format(Locale.ROOT, "%04d%02d%02d%02d%02d%02d",
            calendar.get(Calendar.YEAR), calendar.get(Calendar.MONTH) + 1, calendar.get(Calendar.DAY_OF_MONTH),
            calendar.get(Calendar.HOUR_OF_DAY), calendar.get(Calendar.MINUTE), calendar.get(Calendar.SECOND)));
        int millis = calendar.get(Calendar.MILLISECOND);
        if (millis != 0) {
            // DER: no trailing zeros in the fraction, and no fraction at all when it is zero (X.690 11.7.3, 11.7.4)
            String fraction = String.format(Locale.ROOT, "%03d", millis);
            while (fraction.endsWith("0")) {
                fraction = fraction.substring(0, fraction.length() - 1);
            }
            sb.append('.').append(fraction);
        }
        return sb.append('Z').toString();
    }

    /**
     * A non-lenient, proleptic Gregorian calendar, as X.680 times follow ISO 8601.
     */
    private static Calendar newCalendar(TimeZone zone) {
        GregorianCalendar calendar = new GregorianCalendar(zone);
        calendar.setGregorianChange(new Date(Long.MIN_VALUE));
        calendar.setLenient(false);
        calendar.clear();
        return calendar;
    }

    private static String checkValid(String value) {
        try {
            parse(value);
        } catch (ASN1ParseException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
        return value;
    }

    public static class Parser extends ASN1Parser<ASN1GeneralizedTime> {
        public Parser(ASN1Decoder decoder) {
            super(decoder);
        }

        @Override
        public ASN1GeneralizedTime parse(ASN1Tag<ASN1GeneralizedTime> asn1Tag, byte[] value) throws ASN1ParseException {
            byte[] contents = primitiveContents(decoder, asn1Tag, ASN1Tag.GENERALIZED_TIME.getTag(), value);
            return new ASN1GeneralizedTime(asn1Tag.primitive(), contents);
        }
    }

    public static class Serializer extends CharacterStringSerializer<ASN1GeneralizedTime> {
        public Serializer(ASN1Encoder encoder) {
            super(encoder);
        }
    }
}
