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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.stream.Stream;

import static com.hierynomus.asn1.Bytes.bytes;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class ASN1UTF8StringTest {

    static Stream<Arguments> values() {
        return Stream.of(
            arguments("", bytes(0x0c, 0x00)),
            arguments("hello", bytes(0x0c, 0x05, 'h', 'e', 'l', 'l', 'o')),
            arguments("café", bytes(0x0c, 0x05, 'c', 'a', 'f', 0xc3, 0xa9)),                  // 2-byte sequence
            arguments("€", bytes(0x0c, 0x03, 0xe2, 0x82, 0xac)),                               // 3-byte sequence
            arguments("😀", bytes(0x0c, 0x04, 0xf0, 0x9f, 0x98, 0x80)));                   // 4-byte, outside the BMP
    }

    @ParameterizedTest(name = "\"{0}\"")
    @MethodSource("values")
    void shouldParseUTF8String(String value, byte[] encoded) {
        ASN1UTF8String utf8String = new ASN1InputStream(new BERDecoder(), encoded).readObject();

        assertEquals(value, utf8String.getValue());
        assertEquals(new ASN1UTF8String(value), utf8String);
    }

    @ParameterizedTest(name = "\"{0}\"")
    @MethodSource("values")
    void shouldWriteUTF8String(String value, byte[] encoded) throws IOException {
        assertArrayEquals(encoded, write(new ASN1UTF8String(value)));
    }

    @Test
    void shouldCountCodePointsAsLength() {
        // 'a', 'é' (2 bytes) and U+1F600 (4 bytes, a surrogate pair in Java)
        assertEquals(3, new ASN1UTF8String("aé😀").length());
    }

    @Test
    void shouldParseConstructedUTF8StringSplitInsideMultiByteSequence() throws IOException {
        // X.690 8.23.6: segments are OCTET STRINGs, and may split a UTF-8 sequence
        byte[] encoded = bytes(0x2c, 0x09, 0x04, 0x03, 'c', 'a', 'f', 0x04, 0x02, 0xc3, 0xa9);

        ASN1UTF8String utf8String = new ASN1InputStream(new BERDecoder(), encoded).readObject();

        assertEquals("café", utf8String.getValue());
        assertArrayEquals(bytes(0x0c, 0x05, 'c', 'a', 'f', 0xc3, 0xa9), write(utf8String));
    }

    @Test
    void shouldLenientlyParseInvalidUTF8AndPreserveIt() throws IOException {
        // 0xff never occurs in UTF-8; 0xc3 without a continuation byte is truncated
        byte[] encoded = bytes(0x0c, 0x04, 'o', 'k', 0xff, 0xc3);

        ASN1UTF8String utf8String = new ASN1InputStream(new BERDecoder(), encoded).readObject();

        assertEquals("ok��", utf8String.getValue());
        assertArrayEquals(encoded, write(utf8String));
    }

    @Test
    void shouldRejectUnpairedSurrogateWhenConstructing() {
        assertThrows(IllegalArgumentException.class, () -> new ASN1UTF8String("broken\ud83d"));
    }

    @Test
    void shouldParseImplicitlyTaggedUTF8String() {
        ASN1TaggedObject tagged = new ASN1InputStream(new BERDecoder(), bytes(0x81, 0x02, 0xc3, 0xa9)).readObject();

        assertEquals("é", tagged.getObject(ASN1Tag.UTF8_STRING).getValue());
    }

    @Test
    void shouldIncludeValueInToString() {
        assertEquals("ASN1UTF8String[café]", new ASN1UTF8String("café").toString());
    }

    private static byte[] write(ASN1Object<?> object) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new ASN1OutputStream(new DEREncoder(), baos).writeObject(object);
        return baos.toByteArray();
    }
}
