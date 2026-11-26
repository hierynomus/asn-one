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
package com.hierynomus.asn1;

import com.hierynomus.asn1.encodingrules.ber.BERDecoder;
import com.hierynomus.asn1.encodingrules.der.DEREncoder;
import com.hierynomus.asn1.types.string.ASN1OctetString;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class ASN1OutputStreamTest {

    @ParameterizedTest(name = "length {0} -> {1}")
    @CsvSource({
        "0,     00",
        "1,     01",
        "127,   7f",       // largest short form (X.690 8.1.3.4), mandatory in DER (X.690 10.1)
        "128,   8180",     // smallest long form
        "255,   81ff",
        "256,   820100",
        "65535, 82ffff",
        "65536, 83010000",
    })
    void shouldWriteLengthInMinimalForm(int length, String expectedLengthOctets) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        new ASN1OutputStream(new DEREncoder(), baos).writeObject(new ASN1OctetString(new byte[length]));

        byte[] encoded = baos.toByteArray();
        byte[] lengthOctets = Arrays.copyOfRange(encoded, 1, 1 + expectedLengthOctets.length() / 2);
        assertEquals(expectedLengthOctets, hex(lengthOctets));
        assertEquals(1 + lengthOctets.length + length, encoded.length);
        ASN1OctetString read = new ASN1InputStream(new BERDecoder(), encoded).readObject();
        assertArrayEquals(new byte[length], read.getValue());
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
}
