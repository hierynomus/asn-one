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

import com.hierynomus.asn1.ASN1InputStream;
import com.hierynomus.asn1.ASN1OutputStream;
import com.hierynomus.asn1.ASN1ParseException;
import com.hierynomus.asn1.encodingrules.ber.BERDecoder;
import com.hierynomus.asn1.encodingrules.der.DEREncoder;
import com.hierynomus.asn1.types.ASN1Object;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

import static com.hierynomus.asn1.Bytes.bytes;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ASN1GeneralizedTimeTest {

    @ParameterizedTest(name = "{0} = {1}")
    @CsvSource({
        "20250101000000Z,       2025-01-01T00:00:00Z",
        "20520101000000Z,       2052-01-01T00:00:00Z",       // beyond UTCTime's range, as used in X.509
        "20250101120000.5Z,     2025-01-01T12:00:00.500Z",   // fraction of a second
        "'20250101120000,25Z', 2025-01-01T12:00:00.250Z",   // comma as decimal separator
        "20250101120000.123456Z,2025-01-01T12:00:00.123Z",   // truncated to milliseconds
        "202501011230Z,         2025-01-01T12:30:00Z",       // seconds omitted
        "2025010112Z,           2025-01-01T12:00:00Z",       // minutes and seconds omitted
        "202501011230.5Z,       2025-01-01T12:30:30Z",       // fraction of a minute
        "2025010112.25Z,        2025-01-01T12:15:00Z",       // fraction of an hour
        "20250101120000+0130,   2025-01-01T10:30:00Z",
        "20250101120000-05,     2025-01-01T17:00:00Z",       // offset hours only
        "99991231235959Z,       9999-12-31T23:59:59Z",
        "00010101000000Z,       0001-01-01T00:00:00Z",       // proleptic Gregorian, as in ISO 8601
        "20000229120000Z,       2000-02-29T12:00:00Z",
    })
    void shouldParseGeneralizedTime(String value, String expected) {
        ASN1GeneralizedTime time = new ASN1InputStream(new BERDecoder(), encode(value)).readObject();

        assertEquals(value, time.getValue());
        assertEquals(Date.from(Instant.parse(expected)), time.getDate());
    }

    @Test
    void shouldInterpretLocalTimeInDefaultTimeZone() {
        TimeZone original = TimeZone.getDefault();
        try {
            TimeZone.setDefault(TimeZone.getTimeZone("Europe/Amsterdam"));
            ASN1GeneralizedTime time = new ASN1GeneralizedTime("20250701120000");

            Instant expected = LocalDateTime.parse("2025-07-01T12:00:00").atZone(ZoneId.of("Europe/Amsterdam")).toInstant();
            assertEquals(Date.from(expected), time.getDate());
        } finally {
            TimeZone.setDefault(original);
        }
    }

    @ParameterizedTest(name = "{0} -> {1}")
    @CsvSource({
        "2025-06-30T13:45:07Z,     20250630134507Z",       // no fraction when zero (X.690 11.7.4)
        "2025-06-30T13:45:07.500Z, 20250630134507.5Z",     // no trailing zeros (X.690 11.7.3)
        "2025-06-30T13:45:07.120Z, 20250630134507.12Z",
        "2025-06-30T13:45:07.001Z, 20250630134507.001Z",
        "2052-01-01T00:00:00Z,     20520101000000Z",
    })
    void shouldWriteDateInDerForm(String instant, String expected) throws IOException {
        ASN1GeneralizedTime time = new ASN1GeneralizedTime(Date.from(Instant.parse(instant)));

        assertEquals(expected, time.getValue());
        assertArrayEquals(encode(expected), write(time));
        assertEquals(Date.from(Instant.parse(instant)), time.getDate());
    }

    @Test
    void shouldWriteAsciiDigitsRegardlessOfDefaultLocale() {
        Locale original = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("th-TH-u-nu-thai"));

            assertEquals("20250630134507.5Z", new ASN1GeneralizedTime(Date.from(Instant.parse("2025-06-30T13:45:07.500Z"))).getValue());
            assertEquals("250630134507Z", new ASN1UTCTime(Date.from(Instant.parse("2025-06-30T13:45:07Z"))).getValue());
        } finally {
            Locale.setDefault(original);
        }
    }

    @Test
    void shouldRejectDateOutsideGeneralizedTimeRange() {
        Date tooLate = Date.from(Instant.parse("+10000-01-01T00:00:00Z"));
        Date beforeYearOne = Date.from(Instant.parse("0000-12-31T23:59:59Z"));

        assertThrows(IllegalArgumentException.class, () -> new ASN1GeneralizedTime(tooLate));
        assertThrows(IllegalArgumentException.class, () -> new ASN1GeneralizedTime(beforeYearOne));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "",
        "xyz",
        "250101000000Z",          // two-digit year is UTCTime, not GeneralizedTime
        "20250101",               // hour is mandatory
        "20250101120000.Z",       // empty fraction
        "20251301120000Z",        // month 13
        "20250230120000Z",        // 30 February
        "20250101240000Z",        // hour 24
        "20250101126000Z",        // minute 60
        "20250101120000+2400",    // offset hours out of range
        "20250101120000+0160",    // offset minutes out of range
        "00000101000000Z",        // there is no year 0
    })
    void shouldRejectInvalidGeneralizedTimeWhenConstructing(String value) {
        assertThrows(IllegalArgumentException.class, () -> new ASN1GeneralizedTime(value));
    }

    @Test
    void shouldLenientlyParseInvalidGeneralizedTimeButFailOnGetDate() throws IOException {
        byte[] encoded = encode("20251301120000Z");

        ASN1GeneralizedTime time = new ASN1InputStream(new BERDecoder(), encoded).readObject();

        assertEquals("20251301120000Z", time.getValue());
        assertThrows(ASN1ParseException.class, time::getDate);
        assertArrayEquals(encoded, write(time));
    }

    @Test
    void shouldParseConstructedGeneralizedTime() {
        byte[] encoded = bytes(0x38, 0x13, 0x04, 0x08, '2', '0', '5', '2', '0', '1', '0', '1', 0x04, 0x07, '0', '0', '0', '0', '0', '0', 'Z');

        ASN1GeneralizedTime time = new ASN1InputStream(new BERDecoder(), encoded).readObject();

        assertEquals(new ASN1GeneralizedTime("20520101000000Z"), time);
    }

    private static byte[] encode(String value) {
        byte[] content = value.getBytes(StandardCharsets.US_ASCII);
        byte[] encoded = new byte[content.length + 2];
        encoded[0] = 0x18;
        encoded[1] = (byte) content.length;
        System.arraycopy(content, 0, encoded, 2, content.length);
        return encoded;
    }

    private static byte[] write(ASN1Object<?> object) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new ASN1OutputStream(new DEREncoder(), baos).writeObject(object);
        return baos.toByteArray();
    }
}
