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
package com.hierynomus.asn1.types.primitive;

import com.hierynomus.asn1.ASN1InputStream;
import com.hierynomus.asn1.ASN1OutputStream;
import com.hierynomus.asn1.ASN1ParseException;
import com.hierynomus.asn1.encodingrules.ber.BERDecoder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.stream.Stream;

import static com.hierynomus.asn1.Bytes.bytes;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class ASN1ObjectIdentifierTest {

    static Stream<Arguments> objectIdentifiers() {
        return Stream.of(
            arguments(bytes(0x06, 0x03, 0x55, 0x04, 0x03), "2.5.4.3"),
            arguments(bytes(0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x14), "1.3.6.1.4.1.311.21.20"),
            arguments(bytes(0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02), "1.2.840.113549.1.7.2"),
            arguments(bytes(0x06, 0x03, 0x88, 0x37, 0x03), "2.999.3"),                       // X.690 8.19.5 example
            arguments(bytes(0x06, 0x01, 0x00), "0.0"),
            arguments(bytes(0x06, 0x01, 0x27), "0.39"),
            arguments(bytes(0x06, 0x01, 0x28), "1.0"),
            arguments(bytes(0x06, 0x01, 0x4f), "1.39"),
            arguments(bytes(0x06, 0x01, 0x50), "2.0"),
            arguments(bytes(0x06, 0x01, 0x78), "2.40"),                                      // root arc 2 allows Y >= 40
            arguments(bytes(0x06, 0x01, 0x7f), "2.47"),
            arguments(bytes(0x06, 0x02, 0x81, 0x00), "2.48"),                                // first subidentifier 128
            arguments(bytes(0x06, 0x02, 0x2a, 0x00), "1.2.0"),                               // arc 0
            arguments(bytes(0x06, 0x02, 0x2a, 0x7f), "1.2.127"),                             // largest single-octet arc
            arguments(bytes(0x06, 0x03, 0x2a, 0x81, 0x00), "1.2.128"),                       // smallest two-octet arc
            arguments(bytes(0x06, 0x06, 0x2a, 0x90, 0x80, 0x80, 0x80, 0x05), "1.2.4294967301"), // arc beyond 32 bits
            // UUID based OID (X.667), arc of 128 bits
            arguments(bytes(0x06, 0x14, 0x69, 0x83, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f), "2.25.340282366920938463463374607431768211455"));
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("objectIdentifiers")
    void shouldParseObjectIdentifier(byte[] encoded, String oid) {
        assertEquals(new ASN1ObjectIdentifier(oid), new ASN1InputStream(new BERDecoder(), encoded).readObject());
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("objectIdentifiers")
    void shouldWriteObjectIdentifier(byte[] expected, String oid) throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();

        new ASN1OutputStream(null, stream).writeObject(new ASN1ObjectIdentifier(oid));

        assertArrayEquals(expected, stream.toByteArray());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "",
        "1",               // a single arc
        "1.",
        ".1",
        "1..2",
        "1.2.",
        "-1.2",
        "1.-2",
        "1.a",
        "1.02",            // leading zero, not canonical
        "1 .2",
        "3.1",             // first arc must be 0, 1 or 2
        "0.40",            // second arc must be < 40 under 0 and 1
        "1.40",
    })
    void shouldRejectInvalidObjectIdentifierWhenConstructing(String oid) {
        assertThrows(IllegalArgumentException.class, () -> new ASN1ObjectIdentifier(oid));
    }

    static Stream<Arguments> malformedEncodings() {
        return Stream.of(
            arguments("empty", bytes(0x06, 0x00)),
            arguments("truncated subidentifier", bytes(0x06, 0x02, 0x2a, 0x81)),
            arguments("truncated first subidentifier", bytes(0x06, 0x01, 0x88)),
            arguments("non-minimal subidentifier (X.690 8.19.2)", bytes(0x06, 0x03, 0x2a, 0x80, 0x01)),
            arguments("non-minimal first subidentifier", bytes(0x06, 0x02, 0x80, 0x2a)));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("malformedEncodings")
    void shouldRejectMalformedEncoding(String description, byte[] encoded) {
        ASN1InputStream is = new ASN1InputStream(new BERDecoder(), encoded);

        assertThrows(ASN1ParseException.class, is::readObject);
    }
}
