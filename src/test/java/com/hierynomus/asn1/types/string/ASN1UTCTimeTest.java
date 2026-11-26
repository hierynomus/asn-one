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
import java.util.Date;

import static com.hierynomus.asn1.Bytes.bytes;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ASN1UTCTimeTest {

    @ParameterizedTest(name = "{0} = {1}")
    @CsvSource({
        "250101000000Z,     2025-01-01T00:00:00Z",
        "2501010000Z,       2025-01-01T00:00:00Z",   // seconds omitted
        "250101000000+0130, 2024-12-31T22:30:00Z",   // local time is ahead of UTC
        "250101000000-0500, 2025-01-01T05:00:00Z",
        "2501010000-0500,   2025-01-01T05:00:00Z",
        "500101000000Z,     1950-01-01T00:00:00Z",   // RFC 5280: YY >= 50 is 19YY
        "491231235959Z,     2049-12-31T23:59:59Z",   // RFC 5280: YY < 50 is 20YY
        "000229120000Z,     2000-02-29T12:00:00Z",   // leap day
    })
    void shouldParseUTCTime(String value, String expected) {
        byte[] encoded = encode(value);

        ASN1UTCTime utcTime = new ASN1InputStream(new BERDecoder(), encoded).readObject();

        assertEquals(value, utcTime.getValue());
        assertEquals(Date.from(Instant.parse(expected)), utcTime.getDate());
    }

    @Test
    void shouldParseConstructedUTCTime() {
        byte[] encoded = bytes(0x37, 0x11, 0x04, 0x06, '2', '5', '0', '1', '0', '1', 0x04, 0x07, '0', '0', '0', '0', '0', '0', 'Z');

        ASN1UTCTime utcTime = new ASN1InputStream(new BERDecoder(), encoded).readObject();

        assertEquals(new ASN1UTCTime("250101000000Z"), utcTime);
    }

    @Test
    void shouldWriteDateInDerForm() throws IOException {
        ASN1UTCTime utcTime = new ASN1UTCTime(Date.from(Instant.parse("2025-06-30T13:45:07.890Z")));

        // Fractional seconds are not allowed in UTCTime, and DER requires seconds and 'Z' (X.690 11.8)
        assertEquals("250630134507Z", utcTime.getValue());
        assertArrayEquals(encode("250630134507Z"), write(utcTime));
    }

    @ParameterizedTest
    @ValueSource(strings = {"1950-01-01T00:00:00Z", "1999-12-31T23:59:59Z", "2000-01-01T00:00:00Z", "2049-12-31T23:59:59Z"})
    void shouldRoundTripDate(String instant) {
        Date date = Date.from(Instant.parse(instant));

        assertEquals(date, new ASN1UTCTime(date).getDate());
    }

    @ParameterizedTest
    @ValueSource(strings = {"1949-12-31T23:59:59Z", "2050-01-01T00:00:00Z"})
    void shouldRejectDateOutsideUTCTimeRange(String instant) {
        Date date = Date.from(Instant.parse(instant));

        assertThrows(IllegalArgumentException.class, () -> new ASN1UTCTime(date));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "",
        "xyz",
        "250101000000",       // no time zone
        "250101000000.5Z",    // fractional seconds
        "2501010000000Z",     // too many digits
        "251301000000Z",      // month 13
        "250230000000Z",      // 30 February
        "250101240000Z",      // hour 24
        "250101006000Z",      // minute 60
        "250101000000+2400",  // offset hours out of range
        "250101000000+0060",  // offset minutes out of range
    })
    void shouldRejectInvalidUTCTimeWhenConstructing(String value) {
        assertThrows(IllegalArgumentException.class, () -> new ASN1UTCTime(value));
    }

    @Test
    void shouldLenientlyParseInvalidUTCTimeButFailOnGetDate() throws IOException {
        byte[] encoded = encode("251301000000Z");

        ASN1UTCTime utcTime = new ASN1InputStream(new BERDecoder(), encoded).readObject();

        assertEquals("251301000000Z", utcTime.getValue());
        assertThrows(ASN1ParseException.class, utcTime::getDate);
        assertArrayEquals(encoded, write(utcTime));
    }

    @Test
    void shouldIncludeValueInToString() {
        assertEquals("ASN1UTCTime[250101000000Z]", new ASN1UTCTime("250101000000Z").toString());
    }

    private static byte[] encode(String value) {
        byte[] content = value.getBytes(StandardCharsets.US_ASCII);
        byte[] encoded = new byte[content.length + 2];
        encoded[0] = 0x17;
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
