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
import com.hierynomus.asn1.types.ASN1Encoding;
import com.hierynomus.asn1.types.ASN1Object;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.BitSet;
import java.util.function.Function;
import java.util.stream.Stream;

import static com.hierynomus.asn1.Bytes.bytes;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class ASN1BitStringTest {

    private static final int[] BITS_22 = {1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1};
    private static final int[] BITS_18 = {0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1};

    private static final Function<int[], ASN1BitString> FROM_BOOLEANS = new Function<int[], ASN1BitString>() {
        public ASN1BitString apply(int[] bits) {
            return new ASN1BitString(toBooleans(bits));
        }

        public String toString() {
            return "boolean[]";
        }
    };

    private static final Function<int[], ASN1BitString> FROM_BITSET = new Function<int[], ASN1BitString>() {
        public ASN1BitString apply(int[] bits) {
            return new ASN1BitString(toBitSet(bits));
        }

        public String toString() {
            return "BitSet";
        }
    };

    static Stream<Arguments> encodedBitStrings() {
        return Stream.of(
            arguments(bytes(0x03, 0x04, 0x02, 0xF0, 0xF0, 0xF4), BITS_22),
            arguments(bytes(0x03, 0x04, 0x06, 0x6E, 0x5D, 0xC0), BITS_18));
    }

    @ParameterizedTest
    @MethodSource("encodedBitStrings")
    void shouldParseBitString(byte[] encoded, int[] bits) {
        ASN1Object<?> object = new ASN1InputStream(new BERDecoder(), encoded).readObject();

        ASN1BitString bs = assertInstanceOf(ASN1BitString.class, object);
        assertEquals(bits.length, bs.length());
        assertArrayEquals(toBooleans(bits), bs.getValue());
    }

    @ParameterizedTest
    @MethodSource("encodedBitStrings")
    void shouldDeserializeAndReconstructFromReturnedValue(byte[] encoded, int[] bits) {
        ASN1BitString bs = assertInstanceOf(ASN1BitString.class, new ASN1InputStream(new BERDecoder(), encoded).readObject());
        assertArrayEquals(Arrays.copyOfRange(encoded, 3, encoded.length), bs.getValueBytes());

        ASN1BitString reconstructed = new ASN1BitString(bs.getValue());

        assertEquals(bits.length, reconstructed.length());
        assertArrayEquals(bs.getValueBytes(), reconstructed.getValueBytes());
        assertArrayEquals(bs.getValue(), reconstructed.getValue());
    }

    static Stream<Arguments> bitValues() {
        return Stream.of(
            arguments(BITS_22, FROM_BITSET),
            arguments(BITS_18, FROM_BITSET),
            arguments(BITS_22, FROM_BOOLEANS),
            arguments(BITS_18, FROM_BOOLEANS));
    }

    @ParameterizedTest(name = "from {1} with {0} bits")
    @MethodSource("bitValues")
    void shouldConstructBitString(int[] bits, Function<int[], ASN1BitString> factory) {
        ASN1BitString bitString = factory.apply(bits);

        for (int i = 0; i < bits.length; i++) {
            assertEquals(bits[i] == 1, bitString.isSet(i), "bit " + i);
        }
    }

    static Stream<Arguments> bitStringsToWrite() {
        return Stream.of(
            arguments(BITS_22, FROM_BOOLEANS, bytes(0x03, 0x04, 0x02, 0xF0, 0xF0, 0xF4)),
            arguments(BITS_18, FROM_BOOLEANS, bytes(0x03, 0x04, 0x06, 0x6e, 0x5d, 0xc0)),
            // A BitSet carries no length information, so no unused bits are encoded.
            arguments(BITS_22, FROM_BITSET, bytes(0x03, 0x04, 0x00, 0xF0, 0xF0, 0xF4)),
            arguments(BITS_18, FROM_BITSET, bytes(0x03, 0x04, 0x00, 0x6e, 0x5d, 0xc0)));
    }

    @ParameterizedTest(name = "from {1} with {0} bits")
    @MethodSource("bitStringsToWrite")
    void shouldSerializeBitString(int[] bits, Function<int[], ASN1BitString> factory, byte[] expected) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        new ASN1OutputStream(new DEREncoder(), baos).writeObject(factory.apply(bits));

        assertArrayEquals(expected, baos.toByteArray());
    }

    @Test
    void shouldRetainConstructedEncoding() {
        ASN1InputStream is = new ASN1InputStream(new BERDecoder(), bytes(0x23, 0x09, 0x03, 0x03, 0x0, 0xF0, 0xF0, 0x03, 0x02, 0x02, 0xF4));

        ASN1Object<?> object = is.readObject();

        assertEquals(ASN1Encoding.CONSTRUCTED, object.getTag().getAsn1Encoding());
        assertEquals(22, ((ASN1BitString) object).length());
    }

    private static boolean[] toBooleans(int[] bits) {
        boolean[] result = new boolean[bits.length];
        for (int i = 0; i < bits.length; i++) {
            result[i] = bits[i] == 1;
        }
        return result;
    }

    private static BitSet toBitSet(int[] bits) {
        BitSet bitSet = new BitSet();
        for (int i = 0; i < bits.length; i++) {
            bitSet.set(i, bits[i] == 1);
        }
        return bitSet;
    }
}
