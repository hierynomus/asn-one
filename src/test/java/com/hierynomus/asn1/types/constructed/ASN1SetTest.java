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
package com.hierynomus.asn1.types.constructed;

import com.hierynomus.asn1.ASN1InputStream;
import com.hierynomus.asn1.ASN1OutputStream;
import com.hierynomus.asn1.encodingrules.ber.BERDecoder;
import com.hierynomus.asn1.encodingrules.der.DEREncoder;
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.primitive.ASN1Boolean;
import com.hierynomus.asn1.types.primitive.ASN1Integer;
import com.hierynomus.asn1.types.primitive.ASN1Null;
import com.hierynomus.asn1.types.string.ASN1OctetString;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import static com.hierynomus.asn1.Bytes.bytes;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

class ASN1SetTest {

    private static ASN1Set setOf(long... values) {
        List<ASN1Object> objects = new ArrayList<>();
        for (long value : values) {
            objects.add(new ASN1Integer(value));
        }
        return new ASN1Set(objects);
    }

    @Test
    void shouldKeepDuplicatesWhenParsing() {
        // SET OF INTEGER { 1, 1, 2 } - SET OF is a multiset (X.680 clause 28)
        ASN1Set set = new ASN1InputStream(new BERDecoder(), bytes(0x31, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02)).readObject();

        assertEquals(3, set.size());
        assertEquals(Arrays.<ASN1Object>asList(new ASN1Integer(1), new ASN1Integer(1), new ASN1Integer(2)), set.getValue());
    }

    @Test
    void shouldKeepIdenticalOctetStringsWhenParsing() {
        ASN1Set set = new ASN1InputStream(new BERDecoder(), bytes(0x31, 0x06, 0x04, 0x01, 0x00, 0x04, 0x01, 0x00)).readObject();

        assertEquals(2, set.size());
    }

    @Test
    void shouldKeepDuplicatesWhenConstructing() {
        assertEquals(3, setOf(1, 1, 2).size());
    }

    @Test
    void shouldKeepReceivedOrderWhenParsing() {
        // BER allows any order (X.690 8.12)
        ASN1Set set = new ASN1InputStream(new BERDecoder(), bytes(0x31, 0x09, 0x02, 0x01, 0x03, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02)).readObject();

        assertEquals(Arrays.<ASN1Object>asList(new ASN1Integer(3), new ASN1Integer(1), new ASN1Integer(2)), set.getValue());
    }

    @Test
    void shouldCompareAsMultiset() {
        assertEquals(setOf(1, 2, 2), setOf(2, 1, 2));
        assertEquals(setOf(1, 2, 2).hashCode(), setOf(2, 1, 2).hashCode());
        assertEquals(setOf(), setOf());
        assertNotEquals(setOf(1, 2, 2), setOf(1, 2));
        assertNotEquals(setOf(1, 2, 2), setOf(1, 1, 2));
        assertNotEquals(setOf(1, 2), setOf(1, 3));
    }

    @Test
    void shouldEqualParsedSetInDifferentOrder() {
        ASN1Set parsed = new ASN1InputStream(new BERDecoder(), bytes(0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01)).readObject();

        assertEquals(setOf(1, 2), parsed);
    }

    @Test
    void shouldSortElementsByEncodingWhenConstructed() throws IOException {
        // DER: SET OF elements in ascending order of their encodings (X.690 11.6)
        assertArrayEquals(bytes(0x31, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03), write(setOf(3, 1, 2)));
    }

    @Test
    void shouldSortDuplicatesTogether() throws IOException {
        assertArrayEquals(bytes(0x31, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x02), write(setOf(2, 1, 2)));
    }

    @Test
    void shouldSortByFullEncodingNotJustValue() throws IOException {
        // -1 (02 01 ff) sorts after 1 (02 01 01), and 128 (02 02 00 80) sorts after both on its length octet
        assertArrayEquals(bytes(0x31, 0x0a, 0x02, 0x01, 0x01, 0x02, 0x01, 0xff, 0x02, 0x02, 0x00, 0x80), write(setOf(128, -1, 1)));
    }

    @Test
    void shouldSortElementsOfDifferentTypes() throws IOException {
        // e.g. SET OF CHOICE: BOOLEAN (01) < INTEGER (02) < OCTET STRING (04) < NULL (05)
        ASN1Set set = new ASN1Set(Arrays.<ASN1Object>asList(new ASN1Null(), new ASN1OctetString(new byte[]{0x01}), new ASN1Integer(7), new ASN1Boolean(false)));

        assertArrayEquals(bytes(0x31, 0x0b, 0x01, 0x01, 0x00, 0x02, 0x01, 0x07, 0x04, 0x01, 0x01, 0x05, 0x00), write(set));
    }

    @Test
    void shouldReEncodeParsedSetWithOriginalContents() throws IOException {
        // Not in DER order; re-encoding must not reorder, or signatures over it would break
        byte[] encoded = bytes(0x31, 0x09, 0x02, 0x01, 0x03, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02);

        ASN1Set set = new ASN1InputStream(new BERDecoder(), encoded).readObject();

        assertArrayEquals(encoded, write(set));
    }

    @Test
    void shouldWriteEmptySet() throws IOException {
        assertArrayEquals(bytes(0x31, 0x00), write(setOf()));
    }

    @Test
    void shouldAcceptAnyCollection() {
        assertEquals(setOf(1, 2), new ASN1Set(new HashSet<ASN1Object>(Arrays.<ASN1Object>asList(new ASN1Integer(2), new ASN1Integer(1)))));
    }

    @Test
    void shouldParseLargeSetInLinearTime() {
        // Used to be quadratic: every element collided in a HashSet, as ASN1Object.hashCode() is the tag number
        int n = 50000;
        ByteArrayOutputStream contents = new ByteArrayOutputStream();
        for (int i = 0; i < n; i++) {
            contents.write(0x02);
            contents.write(0x03);
            contents.write(0x00);
            contents.write((i >> 8) & 0xff);
            contents.write(i & 0xff);
        }
        byte[] c = contents.toByteArray();
        byte[] encoded = new byte[c.length + 5];
        encoded[0] = 0x31;
        encoded[1] = (byte) 0x83;
        encoded[2] = (byte) (c.length >> 16);
        encoded[3] = (byte) (c.length >> 8);
        encoded[4] = (byte) c.length;
        System.arraycopy(c, 0, encoded, 5, c.length);

        ASN1Set set = assertTimeoutPreemptively(Duration.ofSeconds(5), () -> new ASN1InputStream(new BERDecoder(), encoded).readObject());

        assertEquals(n, set.size());
    }

    @Test
    void shouldNotMutateInternalListThroughValue() {
        ASN1Set set = setOf(1, 2);

        set.getValue().clear();

        assertEquals(2, set.size());
    }

    @Test
    void shouldNotMutateInternalListThroughIterator() {
        ASN1Set set = setOf(1, 2);
        Iterator<ASN1Object> iterator = set.iterator();

        iterator.next();
        iterator.remove();

        assertEquals(2, set.size());
    }

    @Test
    void shouldNotBeAffectedByChangesToSourceCollection() throws IOException {
        List<ASN1Object> source = new ArrayList<>(Collections.<ASN1Object>singletonList(new ASN1Integer(1)));
        ASN1Set set = new ASN1Set(source);

        source.add(new ASN1Integer(2));

        assertEquals(1, set.size());
        assertArrayEquals(bytes(0x31, 0x03, 0x02, 0x01, 0x01), write(set));
    }

    private static byte[] write(ASN1Object<?> object) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new ASN1OutputStream(new DEREncoder(), baos).writeObject(object);
        return baos.toByteArray();
    }
}
