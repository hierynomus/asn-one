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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
    void shouldParseConstructedBitStringAndReEncodeAsPrimitive() throws IOException {
        ASN1InputStream is = new ASN1InputStream(new BERDecoder(), bytes(0x23, 0x09, 0x03, 0x03, 0x0, 0xF0, 0xF0, 0x03, 0x02, 0x02, 0xF4));

        ASN1BitString bitString = assertInstanceOf(ASN1BitString.class, is.readObject());

        assertEquals(22, bitString.length());
        assertArrayEquals(toBooleans(BITS_22), bitString.getValue());
        // DER only allows the primitive form (X.690 10.2)
        assertEquals(ASN1Encoding.PRIMITIVE, bitString.getTag().getAsn1Encoding());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new ASN1OutputStream(new DEREncoder(), baos).writeObject(bitString);
        assertArrayEquals(bytes(0x03, 0x04, 0x02, 0xF0, 0xF0, 0xF4), baos.toByteArray());
    }

    @Test
    void shouldRejectConstructedBitStringWithNonBitStringSegment() {
        ASN1InputStream is = new ASN1InputStream(new BERDecoder(), bytes(0x23, 0x04, 0x04, 0x02, 0x00, 0xF0));

        assertThrows(ASN1ParseException.class, is::readObject);
    }

    static Stream<Arguments> octetAlignedBitStrings() {
        boolean[] eight = {true, true, true, true, true, true, true, true};
        boolean[] sixteen = {true, false, false, false, false, false, false, false, false, false, false, false, false, false, false, true};
        BitSet eightSet = new BitSet();
        eightSet.set(0, 8);
        return Stream.of(
            // X.690 8.6.2.2: the number of unused bits is 0-7, so a multiple of 8 bits has none
            arguments("boolean[0]", new ASN1BitString(new boolean[0]), bytes(0x03, 0x01, 0x00)),
            arguments("boolean[8]", new ASN1BitString(eight), bytes(0x03, 0x02, 0x00, 0xff)),
            arguments("boolean[16]", new ASN1BitString(sixteen), bytes(0x03, 0x03, 0x00, 0x80, 0x01)),
            arguments("empty BitSet", new ASN1BitString(new BitSet()), bytes(0x03, 0x01, 0x00)),
            arguments("BitSet of 8 bits", new ASN1BitString(eightSet), bytes(0x03, 0x02, 0x00, 0xff)));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("octetAlignedBitStrings")
    void shouldWriteOctetAlignedBitStringWithoutUnusedBits(String description, ASN1BitString bitString, byte[] expected) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        new ASN1OutputStream(new DEREncoder(), baos).writeObject(bitString);

        assertArrayEquals(expected, baos.toByteArray());
        ASN1BitString read = new ASN1InputStream(new BERDecoder(), expected).readObject();
        assertEquals(bitString.length(), read.length());
    }

    static Stream<Arguments> malformedBitStrings() {
        return Stream.of(
            arguments("no initial octet (X.690 8.6.2)", bytes(0x03, 0x00)),
            arguments("8 unused bits (X.690 8.6.2.2)", bytes(0x03, 0x02, 0x08, 0xff)),
            arguments("255 unused bits", bytes(0x03, 0x02, 0xff, 0xff)),
            arguments("unused bits without data (X.690 8.6.2.3)", bytes(0x03, 0x01, 0x03)),
            arguments("constructed, segment without initial octet", bytes(0x23, 0x02, 0x03, 0x00)),
            arguments("constructed, unused bits in a segment that is not the last (X.690 8.6.4)",
                bytes(0x23, 0x08, 0x03, 0x02, 0x04, 0xf0, 0x03, 0x02, 0x00, 0xff)));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("malformedBitStrings")
    void shouldRejectMalformedBitString(String description, byte[] encoded) {
        ASN1InputStream is = new ASN1InputStream(new BERDecoder(), encoded);

        ASN1ParseException ex = assertThrows(ASN1ParseException.class, is::readObject);

        assertTrue(rootMessage(ex).contains("BIT STRING"), rootMessage(ex));
    }

    @Test
    void shouldParseEmptyBitString() {
        ASN1BitString bitString = new ASN1InputStream(new BERDecoder(), bytes(0x03, 0x01, 0x00)).readObject();

        assertEquals(0, bitString.length());
    }

    private static String rootMessage(Throwable t) {
        StringBuilder sb = new StringBuilder();
        for (Throwable c = t; c != null; c = c.getCause()) {
            sb.append(c.getMessage()).append(" / ");
        }
        return sb.toString();
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

    @Test
    void shouldNotBeAffectedByChangesToTheGivenBits() {
        boolean[] bits = {true, false, true};
        ASN1BitString bitString = new ASN1BitString(bits);

        bits[1] = true;

        assertArrayEquals(new boolean[]{true, false, true}, bitString.getValue());
    }

    @Test
    void shouldNotBeAffectedByChangesToTheGivenBytes() {
        byte[] value = bytes(0xa0);
        ASN1BitString bitString = new ASN1BitString(value, 5);

        value[0] = (byte) 0xe0;

        assertArrayEquals(bytes(0xa0), bitString.getValueBytes());
    }
}
