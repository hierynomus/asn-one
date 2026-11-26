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

class ASN1PrintableStringTest {

    private static final byte[] DER_US = bytes(0x13, 0x02, 'U', 'S');

    static Stream<Arguments> encodings() {
        return Stream.of(
            arguments("primitive", DER_US),
            arguments("constructed, OCTET STRING segments (X.690 8.23.6)", bytes(0x33, 0x06, 0x04, 0x01, 'U', 0x04, 0x01, 'S')),
            arguments("constructed, PrintableString segments (lenient)", bytes(0x33, 0x06, 0x13, 0x01, 'U', 0x13, 0x01, 'S')));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("encodings")
    void shouldParsePrintableString(String description, byte[] encoded) throws IOException {
        ASN1PrintableString printableString = new ASN1InputStream(new BERDecoder(), encoded).readObject();

        assertEquals("US", printableString.getValue());
        assertEquals(2, printableString.length());
        assertEquals(new ASN1PrintableString("US"), printableString);
        assertArrayEquals(DER_US, write(printableString));
    }

    @Test
    void shouldWritePrintableString() throws IOException {
        assertArrayEquals(DER_US, write(new ASN1PrintableString("US")));
    }

    @Test
    void shouldAcceptAllPermittedCharacters() {
        String all = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?";

        assertTrue(ASN1PrintableString.isPrintableString(all));
        assertEquals(all, new ASN1PrintableString(all).getValue());
    }

    @ParameterizedTest
    @ValueSource(strings = {"user@example.com", "*.example.com", "R&D", "a_b", "café", "tab\there", "semi;colon"})
    void shouldRejectNonPrintableCharactersWhenConstructing(String value) {
        assertFalse(ASN1PrintableString.isPrintableString(value));
        assertThrows(IllegalArgumentException.class, () -> new ASN1PrintableString(value));
    }

    @Test
    void shouldLenientlyParseNonPrintableCharactersAndPreserveThem() throws IOException {
        // '@' and '*' are not permitted, but are common in certificates issued in the wild
        byte[] encoded = bytes(0x13, 0x0b, '*', '@', 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0xe9, '!');

        ASN1PrintableString printableString = new ASN1InputStream(new BERDecoder(), encoded).readObject();

        assertEquals("*@exampleé!", printableString.getValue());
        assertArrayEquals(encoded, write(printableString));
    }

    @Test
    void shouldParseImplicitlyTaggedPrintableString() {
        ASN1TaggedObject tagged = new ASN1InputStream(new BERDecoder(), bytes(0x80, 0x02, 'U', 'S')).readObject();

        assertEquals("US", tagged.getObject(ASN1Tag.PRINTABLE_STRING).getValue());
    }

    @Test
    void shouldIncludeValueInToString() {
        assertEquals("ASN1PrintableString[US]", new ASN1PrintableString("US").toString());
    }

    private static byte[] write(ASN1Object<?> object) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new ASN1OutputStream(new DEREncoder(), baos).writeObject(object);
        return baos.toByteArray();
    }
}
