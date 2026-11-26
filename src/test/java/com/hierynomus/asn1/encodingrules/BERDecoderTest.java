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
package com.hierynomus.asn1.encodingrules;

import com.hierynomus.asn1.ASN1InputStream;
import com.hierynomus.asn1.ASN1OutputStream;
import com.hierynomus.asn1.ASN1ParseException;
import com.hierynomus.asn1.encodingrules.ber.BERDecoder;
import com.hierynomus.asn1.encodingrules.der.DEREncoder;
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.constructed.ASN1TaggedObject;
import com.hierynomus.asn1.types.primitive.ASN1Null;
import com.hierynomus.asn1.types.string.ASN1OctetString;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.stream.Stream;

import static com.hierynomus.asn1.Bytes.bytes;
import static com.hierynomus.asn1.types.ASN1Tag.contextSpecific;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class BERDecoderTest {

    static Stream<Arguments> malformedEncodings() {
        return Stream.of(
            arguments("empty input", bytes()),
            arguments("tag only", bytes(0x04)),
            arguments("long form length cut off", bytes(0x04, 0x82, 0x01)),
            arguments("value shorter than length", bytes(0x04, 0x05, 0x01, 0x02)),
            arguments("length of 5 octets", bytes(0x04, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00)),
            arguments("length beyond Integer.MAX_VALUE", bytes(0x04, 0x84, 0x80, 0x00, 0x00, 0x00)),
            arguments("indefinite length", bytes(0x24, 0x80, 0x04, 0x01, 0x01, 0x00, 0x00)));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("malformedEncodings")
    void shouldRejectMalformedEncoding(String description, byte[] encoded) {
        ASN1InputStream is = new ASN1InputStream(new BERDecoder(), encoded);

        assertThrows(ASN1ParseException.class, is::readObject);
    }

    @Test
    void shouldAcceptZeroLengthInLongForm() {
        // 0x81 0x00 is a valid (non-DER) encoding of length 0, distinct from the indefinite form 0x80
        ASN1OctetString octetString = new ASN1InputStream(new BERDecoder(), bytes(0x04, 0x81, 0x00)).readObject();

        assertEquals(0, octetString.length());
    }

    static Stream<Arguments> highTagNumbers() {
        return Stream.of(
            arguments(31, bytes(0xbf, 0x1f, 0x02, 0x05, 0x00)),
            arguments(127, bytes(0xbf, 0x7f, 0x02, 0x05, 0x00)),
            arguments(128, bytes(0xbf, 0x81, 0x00, 0x02, 0x05, 0x00)),
            arguments(200, bytes(0xbf, 0x81, 0x48, 0x02, 0x05, 0x00)),
            arguments(16384, bytes(0xbf, 0x81, 0x80, 0x00, 0x02, 0x05, 0x00)));
    }

    @ParameterizedTest(name = "[{0}]")
    @MethodSource("highTagNumbers")
    void shouldWriteAndReadHighTagNumbers(int tagNumber, byte[] expected) throws IOException {
        // X.690 8.1.2.4: tag numbers >= 31 use the high tag number form
        ASN1TaggedObject tagged = new ASN1TaggedObject(contextSpecific(tagNumber).constructed(), new ASN1Null());

        assertArrayEquals(expected, write(tagged));
        ASN1TaggedObject read = new ASN1InputStream(new BERDecoder(), expected).readObject();
        assertEquals(tagNumber, read.getTag().getTag());
        assertEquals(new ASN1Null(), read.getObject());
    }

    @Test
    void shouldRejectExplicitTaggedObjectWithTrailingBytes() {
        // [0] { NULL, NULL } is not a valid explicitly tagged object
        ASN1TaggedObject tagged = new ASN1InputStream(new BERDecoder(), bytes(0xa0, 0x04, 0x05, 0x00, 0x05, 0x00)).readObject();

        assertThrows(ASN1ParseException.class, tagged::getObject);
    }

    private static byte[] write(ASN1Object<?> object) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new ASN1OutputStream(new DEREncoder(), baos).writeObject(object);
        return baos.toByteArray();
    }
}
