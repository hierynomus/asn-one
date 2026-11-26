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
import com.hierynomus.asn1.types.ASN1Encoding;
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.ASN1Tag;
import com.hierynomus.asn1.types.constructed.ASN1TaggedObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.stream.Stream;

import static com.hierynomus.asn1.Bytes.bytes;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class ASN1OctetStringTest {

    private static final byte[] CONTENT = bytes(0x01, 0x02, 0x03, 0x04, 0x05);
    private static final byte[] DER = bytes(0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05);

    static Stream<Arguments> encodings() {
        return Stream.of(
            arguments("primitive", DER),
            arguments("constructed (X.690 8.7.3)", bytes(0x24, 0x09, 0x04, 0x03, 0x01, 0x02, 0x03, 0x04, 0x02, 0x04, 0x05)),
            arguments("constructed, nested segments", bytes(0x24, 0x0b, 0x24, 0x05, 0x04, 0x03, 0x01, 0x02, 0x03, 0x04, 0x02, 0x04, 0x05)),
            arguments("constructed, empty segment", bytes(0x24, 0x09, 0x04, 0x00, 0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05)));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("encodings")
    void shouldParseOctetString(String description, byte[] encoded) {
        ASN1OctetString octetString = new ASN1InputStream(new BERDecoder(), encoded).readObject();

        assertArrayEquals(CONTENT, octetString.getValue());
        assertEquals(CONTENT.length, octetString.length());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("encodings")
    void shouldEqualOctetStringConstructedFromValue(String description, byte[] encoded) {
        assertEquals(new ASN1OctetString(CONTENT), new ASN1InputStream(new BERDecoder(), encoded).readObject());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("encodings")
    void shouldReEncodeAsPrimitive(String description, byte[] encoded) throws IOException {
        ASN1OctetString octetString = new ASN1InputStream(new BERDecoder(), encoded).readObject();

        assertEquals(ASN1Encoding.PRIMITIVE, octetString.getTag().getAsn1Encoding());
        assertArrayEquals(DER, write(octetString));
    }

    @Test
    void shouldRejectConstructedOctetStringWithNonOctetStringSegment() {
        // Segment is an INTEGER instead of an OCTET STRING
        ASN1InputStream is = new ASN1InputStream(new BERDecoder(), bytes(0x24, 0x03, 0x02, 0x01, 0x01));

        assertThrows(ASN1ParseException.class, is::readObject);
    }

    @Test
    void shouldRejectExcessivelyNestedSegments() {
        int depth = 40;
        byte[] encoded = bytes(0x04, 0x00);
        for (int i = 0; i < depth; i++) {
            byte[] wrapped = new byte[encoded.length + 2];
            wrapped[0] = 0x24;
            wrapped[1] = (byte) encoded.length;
            System.arraycopy(encoded, 0, wrapped, 2, encoded.length);
            encoded = wrapped;
        }
        ASN1InputStream is = new ASN1InputStream(new BERDecoder(), encoded);

        assertThrows(ASN1ParseException.class, is::readObject);
    }

    @Test
    void shouldParseImplicitlyTaggedConstructedOctetString() {
        // [0] IMPLICIT OCTET STRING in constructed form: the segments keep their UNIVERSAL OCTET STRING tag
        ASN1TaggedObject tagged = new ASN1InputStream(new BERDecoder(), bytes(0xa0, 0x09, 0x04, 0x03, 0x01, 0x02, 0x03, 0x04, 0x02, 0x04, 0x05)).readObject();

        ASN1OctetString octetString = tagged.getObject(ASN1Tag.OCTET_STRING);

        assertArrayEquals(CONTENT, octetString.getValue());
    }

    @Test
    void shouldWriteOctetString() throws IOException {
        assertArrayEquals(DER, write(new ASN1OctetString(CONTENT)));
    }

    private static byte[] write(ASN1Object<?> object) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new ASN1OutputStream(new DEREncoder(), baos).writeObject(object);
        return baos.toByteArray();
    }
}
