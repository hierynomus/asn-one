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

import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
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
 * ASN.1 UTCTime (UNIVERSAL 23, X.680 clause 47), defined as a VisibleString of the form {@code YYMMDDhhmm[ss]}
 * followed by either {@code Z} or a {@code +hhmm}/{@code -hhmm} offset from UTC.
 * <p>
 * Two-digit years are interpreted as in RFC 5280: {@code YY >= 50} is {@code 19YY}, otherwise {@code 20YY}.
 * A value created from a {@link Date} is always in the DER form {@code YYMMDDhhmmssZ} (X.690 11.8). As with all
 * {@link ASN1CharacterString character strings}, parsing is lenient: malformed content is only reported when
 * calling {@link #getDate()}.
 * <p>
 * Equality is based on the string value, so two encodings of the same instant in a different form are not equal.
 */
public class ASN1UTCTime extends ASN1CharacterString {
    private static final Pattern UTC_TIME = Pattern.compile("(\\d{2})(\\d{2})(\\d{2})(\\d{2})(\\d{2})(\\d{2})?(Z|([+-])(\\d{2})(\\d{2}))");
    private static final TimeZone UTC = TimeZone.getTimeZone("UTC");

    /**
     * @param date the moment in time, which must lie in the years 1950 up to and including 2049
     * @throws IllegalArgumentException if the date cannot be represented as a UTCTime
     */
    public ASN1UTCTime(Date date) {
        this(ASN1Tag.UTC_TIME, date);
    }

    public ASN1UTCTime(ASN1Tag<?> tag, Date date) {
        super(tag, format(date), StandardCharsets.US_ASCII);
    }

    /**
     * @param value a UTCTime string, e.g. {@code 250101120000Z}
     * @throws IllegalArgumentException if the value is not a valid UTCTime
     */
    public ASN1UTCTime(String value) {
        this(ASN1Tag.UTC_TIME, value);
    }

    public ASN1UTCTime(ASN1Tag<?> tag, String value) {
        super(tag, checkValid(value), StandardCharsets.US_ASCII);
    }

    private ASN1UTCTime(ASN1Tag<?> tag, byte[] bytes) {
        // ISO-8859-1 maps every octet to a character, so even non-conforming content survives a round trip.
        super(tag, bytes, StandardCharsets.ISO_8859_1);
    }

    /**
     * @return the moment in time this UTCTime represents
     * @throws ASN1ParseException if the value is not a valid UTCTime
     */
    public Date getDate() {
        return parse(getValue());
    }

    private static Date parse(String value) {
        Matcher m = UTC_TIME.matcher(value);
        checkFormat(m.matches(), "Invalid ASN.1 UTCTime: '%s'", value);
        int yy = Integer.parseInt(m.group(1));
        Calendar calendar = new GregorianCalendar(UTC);
        calendar.setLenient(false);
        calendar.clear();
        calendar.set(yy >= 50 ? 1900 + yy : 2000 + yy,
            Integer.parseInt(m.group(2)) - 1,
            Integer.parseInt(m.group(3)),
            Integer.parseInt(m.group(4)),
            Integer.parseInt(m.group(5)),
            m.group(6) != null ? Integer.parseInt(m.group(6)) : 0);
        long offsetMillis = 0;
        if (m.group(8) != null) {
            int offsetHours = Integer.parseInt(m.group(9));
            int offsetMinutes = Integer.parseInt(m.group(10));
            checkFormat(offsetHours <= 23 && offsetMinutes <= 59, "Invalid offset in ASN.1 UTCTime: '%s'", value);
            offsetMillis = (offsetHours * 60L + offsetMinutes) * 60_000L * ("-".equals(m.group(8)) ? -1 : 1);
        }
        try {
            // The fields denote local time at the given offset, so subtract it to get to UTC.
            return new Date(calendar.getTimeInMillis() - offsetMillis);
        } catch (IllegalArgumentException e) {
            throw new ASN1ParseException(e, "Invalid date or time in ASN.1 UTCTime: '%s'", value);
        }
    }

    private static String format(Date date) {
        Calendar calendar = new GregorianCalendar(UTC);
        calendar.setTime(date);
        int year = calendar.get(Calendar.YEAR);
        if (year < 1950 || year > 2049) {
            throw new IllegalArgumentException("ASN.1 UTCTime can only represent the years 1950-2049, not " + year);
        }
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyMMddHHmmss'Z'", Locale.ROOT);
        dateFormat.setTimeZone(UTC);
        return dateFormat.format(date);
    }

    private static String checkValid(String value) {
        try {
            parse(value);
        } catch (ASN1ParseException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
        return value;
    }

    public static class Parser extends ASN1Parser<ASN1UTCTime> {
        public Parser(ASN1Decoder decoder) {
            super(decoder);
        }

        @Override
        public ASN1UTCTime parse(ASN1Tag<ASN1UTCTime> asn1Tag, byte[] value) throws ASN1ParseException {
            byte[] contents = primitiveContents(decoder, asn1Tag, ASN1Tag.UTC_TIME.getTag(), value);
            return new ASN1UTCTime(asn1Tag.primitive(), contents);
        }
    }

    public static class Serializer extends CharacterStringSerializer<ASN1UTCTime> {
        public Serializer(ASN1Encoder encoder) {
            super(encoder);
        }
    }
}
