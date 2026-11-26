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

class ASN1NumericStringTest {

    private static final byte[] DER = bytes(0x12, 0x05, '1', '2', ' ', '3', '4');

    static Stream<Arguments> encodings() {
        return Stream.of(
            arguments("primitive", DER),
            arguments("constructed, OCTET STRING segments (X.690 8.23.6)", bytes(0x32, 0x09, 0x04, 0x02, '1', '2', 0x04, 0x03, ' ', '3', '4')),
            arguments("constructed, NumericString segments (lenient)", bytes(0x32, 0x09, 0x12, 0x02, '1', '2', 0x12, 0x03, ' ', '3', '4')));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("encodings")
    void shouldParseNumericString(String description, byte[] encoded) throws IOException {
        ASN1NumericString numericString = new ASN1InputStream(new BERDecoder(), encoded).readObject();

        assertEquals("12 34", numericString.getValue());
        assertEquals(new ASN1NumericString("12 34"), numericString);
        assertArrayEquals(DER, write(numericString));
    }

    @Test
    void shouldWriteNumericString() throws IOException {
        assertArrayEquals(DER, write(new ASN1NumericString("12 34")));
    }

    @Test
    void shouldAcceptAllPermittedCharacters() {
        assertTrue(ASN1NumericString.isNumericString("0123456789 "));
        assertEquals("0123456789 ", new ASN1NumericString("0123456789 ").getValue());
    }

    @ParameterizedTest
    @ValueSource(strings = {"12a", "-1", "1.5", "+31", "1_000", "١"})  // last one is ARABIC-INDIC DIGIT ONE
    void shouldRejectNonNumericCharactersWhenConstructing(String value) {
        assertFalse(ASN1NumericString.isNumericString(value));
        assertThrows(IllegalArgumentException.class, () -> new ASN1NumericString(value));
    }

    @Test
    void shouldLenientlyParseNonNumericCharactersAndPreserveThem() throws IOException {
        byte[] encoded = bytes(0x12, 0x03, '1', 'A', 0xe9);

        ASN1NumericString numericString = new ASN1InputStream(new BERDecoder(), encoded).readObject();

        assertEquals("1Aé", numericString.getValue());
        assertArrayEquals(encoded, write(numericString));
    }

    @Test
    void shouldIncludeValueInToString() {
        assertEquals("ASN1NumericString[12 34]", new ASN1NumericString("12 34").toString());
    }

    private static byte[] write(ASN1Object<?> object) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new ASN1OutputStream(new DEREncoder(), baos).writeObject(object);
        return baos.toByteArray();
    }
}
