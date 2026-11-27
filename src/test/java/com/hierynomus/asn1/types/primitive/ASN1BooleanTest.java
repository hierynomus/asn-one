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
import com.hierynomus.asn1.encodingrules.ber.BERDecoder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import com.hierynomus.asn1.ASN1ParseException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.stream.Stream;

import static com.hierynomus.asn1.Bytes.bytes;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class ASN1BooleanTest {

    static Stream<Arguments> encodedBooleans() {
        return Stream.of(
            arguments(bytes(0x01, 0x01, 0x00), new ASN1Boolean(false)),
            arguments(bytes(0x01, 0x01, 0x01), new ASN1Boolean(true)),
            arguments(bytes(0x01, 0x01, 0xFF), new ASN1Boolean(true)));
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("encodedBooleans")
    void shouldParseBoolean(byte[] encoded, ASN1Boolean expected) {
        assertEquals(expected, new ASN1InputStream(new BERDecoder(), encoded).readObject());
    }

    static Stream<Arguments> booleansToWrite() {
        return Stream.of(
            arguments(new ASN1Boolean(false), bytes(0x01, 0x01, 0x00)),
            arguments(new ASN1Boolean(true), bytes(0x01, 0x01, 0xFF)));   // DER: TRUE is all ones (X.690 11.1)
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("booleansToWrite")
    void shouldWriteBoolean(ASN1Boolean value, byte[] expected) throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();

        new ASN1OutputStream(null, stream).writeObject(value);

        assertArrayEquals(expected, stream.toByteArray());
    }

    @ParameterizedTest(name = "{0} content octets")
    @ValueSource(ints = {0, 2})
    void shouldRejectBooleanWithWrongLength(int length) {
        byte[] encoded = new byte[2 + length];
        encoded[0] = 0x01;
        encoded[1] = (byte) length;

        ASN1ParseException ex = assertThrows(ASN1ParseException.class, () -> new ASN1InputStream(new BERDecoder(), encoded).readObject());

        assertEquals("ASN.1 BOOLEAN must have exactly one content octet, but has " + length, ex.getMessage());
    }
}
