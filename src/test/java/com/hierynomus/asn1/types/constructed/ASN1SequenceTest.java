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

import com.hierynomus.asn1.ASN1OutputStream;
import com.hierynomus.asn1.encodingrules.der.DEREncoder;
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.primitive.ASN1Integer;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import static com.hierynomus.asn1.Bytes.bytes;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ASN1SequenceTest {

    private static byte[] write(ASN1Object<?> object) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new ASN1OutputStream(new DEREncoder(), baos).writeObject(object);
        return baos.toByteArray();
    }

    @Test
    void shouldNotBeAffectedByChangesToTheGivenList() throws IOException {
        List<ASN1Integer> elements = new ArrayList<>(Arrays.asList(new ASN1Integer(1), new ASN1Integer(2)));
        ASN1Sequence sequence = new ASN1Sequence(elements);
        byte[] before = write(sequence);

        elements.add(new ASN1Integer(3));

        assertEquals(2, sequence.size());
        assertArrayEquals(bytes(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02), before);
        assertArrayEquals(before, write(sequence));
    }

    @Test
    void shouldNotBeModifiableThroughItsIterator() {
        Iterator<ASN1Object> iterator = new ASN1Sequence(Arrays.asList(new ASN1Integer(1))).iterator();
        iterator.next();

        assertThrows(UnsupportedOperationException.class, iterator::remove);
    }

    @Test
    void shouldNotBeAffectedByChangesToItsValue() {
        ASN1Sequence sequence = new ASN1Sequence(Arrays.asList(new ASN1Integer(1)));

        sequence.getValue().add(new ASN1Integer(2));

        assertEquals(1, sequence.size());
    }

    @Test
    void shouldRejectNullElements() {
        assertThrows(NullPointerException.class, () -> new ASN1Sequence(Arrays.asList(new ASN1Integer(1), null)));
    }

    @Test
    void equalSequencesShouldHaveEqualHashCodes() {
        assertEquals(new ASN1Sequence(Arrays.asList(new ASN1Integer(1), new ASN1Integer(2))).hashCode(),
            new ASN1Sequence(Arrays.asList(new ASN1Integer(1), new ASN1Integer(2))).hashCode());
    }
}
