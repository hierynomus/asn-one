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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.stream.Stream;

import static com.hierynomus.asn1.Bytes.bytes;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class ASN1ObjectIdentifierTest {

    static Stream<Arguments> objectIdentifiers() {
        return Stream.of(
            arguments(bytes(0x06, 0x03, 0x55, 0x04, 0x03), "2.5.4.3"),
            arguments(bytes(0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x14), "1.3.6.1.4.1.311.21.20"),
            arguments(bytes(0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02), "1.2.840.113549.1.7.2"));
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
}
