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
import com.hierynomus.asn1.encodingrules.ber.BERDecoder;
import com.hierynomus.asn1.encodingrules.der.DEREncoder;
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.ASN1Tag;
import com.hierynomus.asn1.types.constructed.ASN1TaggedObject;
import org.junit.jupiter.api.Test;
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class ASN1IA5StringTest {

    private static final byte[] DER = bytes(0x16, 0x05, 'a', '@', 'b', '.', 'c');

    static Stream<Arguments> encodings() {
        return Stream.of(
            arguments("primitive", DER),
            arguments("constructed, OCTET STRING segments (X.690 8.23.6)", bytes(0x36, 0x09, 0x04, 0x02, 'a', '@', 0x04, 0x03, 'b', '.', 'c')),
            arguments("constructed, IA5String segments (lenient)", bytes(0x36, 0x09, 0x16, 0x02, 'a', '@', 0x16, 0x03, 'b', '.', 'c')));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("encodings")
    void shouldParseIA5String(String description, byte[] encoded) throws IOException {
        ASN1IA5String ia5String = new ASN1InputStream(new BERDecoder(), encoded).readObject();

        assertEquals("a@b.c", ia5String.getValue());
        assertEquals(new ASN1IA5String("a@b.c"), ia5String);
        assertArrayEquals(DER, write(ia5String));
    }

    @Test
    void shouldAcceptAllAsciiCharacters() {
        StringBuilder all = new StringBuilder();
        for (char c = 0; c <= 0x7f; c++) {
            all.append(c);
        }

        assertTrue(ASN1IA5String.isIA5String(all.toString()));
        assertEquals(all.toString(), new ASN1IA5String(all.toString()).getValue());
    }

    @ParameterizedTest
    @ValueSource(strings = {"café", "ÿ", "naïve@example.com", "€"})
    void shouldRejectNonAsciiWhenConstructing(String value) {
        assertFalse(ASN1IA5String.isIA5String(value));
        assertThrows(IllegalArgumentException.class, () -> new ASN1IA5String(value));
    }

    @Test
    void shouldLenientlyParseNonAsciiAndPreserveIt() throws IOException {
        byte[] encoded = bytes(0x16, 0x03, 'a', 0xe9, 'b');

        ASN1IA5String ia5String = new ASN1InputStream(new BERDecoder(), encoded).readObject();

        assertEquals("aéb", ia5String.getValue());
        assertArrayEquals(encoded, write(ia5String));
    }

    @Test
    void shouldParseImplicitlyTaggedIA5String() {
        // X.509 SubjectAltName rfc822Name: [1] IMPLICIT IA5String
        ASN1TaggedObject tagged = new ASN1InputStream(new BERDecoder(), bytes(0x81, 0x05, 'a', '@', 'b', '.', 'c')).readObject();

        assertEquals("a@b.c", tagged.getObject(ASN1Tag.IA5_STRING).getValue());
    }

    private static byte[] write(ASN1Object<?> object) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new ASN1OutputStream(new DEREncoder(), baos).writeObject(object);
        return baos.toByteArray();
    }
}
