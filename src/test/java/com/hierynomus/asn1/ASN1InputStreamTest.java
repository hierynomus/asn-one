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
import com.hierynomus.asn1.types.ASN1Tag;
import com.hierynomus.asn1.types.ASN1Object;
import org.junit.jupiter.api.Test;

import java.util.Iterator;
import java.util.NoSuchElementException;

import static com.hierynomus.asn1.Bytes.bytes;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASN1InputStreamTest {

    @Test
    void doesNotSupportIndefiniteLengthEncoding() {
        ASN1InputStream is = new ASN1InputStream(new BERDecoder(), bytes(0x23, 0x80, 0x03, 0x02, 0xF0, 0xF0, 0x03, 0x02, 0x02, 0xF4, 0x0, 0x0));

        ASN1ParseException ex = assertThrows(ASN1ParseException.class, is::readObject);
        assertEquals("The indefinite length form is not (yet) supported!", ex.getMessage());
    }

    @Test
    void supportsLargestValueInShortLengthForm() {
        byte[] encoded = new byte[2 + 127];
        encoded[0] = 0x02;
        encoded[1] = 0x7f;
        for (int i = 1; i <= 127; i++) {
            encoded[i + 1] = (byte) i;
        }
        ASN1InputStream is = new ASN1InputStream(new BERDecoder(), encoded);

        assertEquals(ASN1Tag.INTEGER, is.readTag());
        assertEquals(127, is.readLength());
    }

    @Test
    void shouldKeepCauseOfErrorInsideSequence() {
        // SEQUENCE { INTEGER with the constructed bit set }
        ASN1InputStream is = new ASN1InputStream(new BERDecoder(), bytes(0x30, 0x03, 0x22, 0x01, 0x03));

        ASN1ParseException ex = assertThrows(ASN1ParseException.class, is::readObject);

        StringBuilder messages = new StringBuilder();
        for (Throwable t = ex; t != null; t = t.getCause()) {
            messages.append(t.getMessage()).append('\n');
        }
        assertTrue(messages.toString().contains("does not support encoding as CONSTRUCTED"), messages.toString());
    }

    @Test
    void iteratorShouldThrowNoSuchElementWhenExhausted() {
        Iterator<ASN1Object> iterator = new ASN1InputStream(new BERDecoder(), bytes(0x05, 0x00)).iterator();

        iterator.next();

        assertFalse(iterator.hasNext());
        assertThrows(NoSuchElementException.class, iterator::next);
    }
}
