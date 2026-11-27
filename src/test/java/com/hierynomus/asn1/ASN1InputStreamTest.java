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
import com.hierynomus.asn1.types.constructed.ASN1Sequence;
import com.hierynomus.asn1.types.constructed.ASN1TaggedObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Iterator;
import java.util.NoSuchElementException;

import static com.hierynomus.asn1.Bytes.bytes;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
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
    void shouldReportUnknownTagInsideSequence() {
        // SEQUENCE { [UNIVERSAL 14] } - the unknown tag used to be hidden behind a NoSuchElementException
        ASN1InputStream is = new ASN1InputStream(new BERDecoder(), bytes(0x30, 0x02, 0x0e, 0x00));

        ASN1ParseException ex = assertThrows(ASN1ParseException.class, is::readObject);

        assertEquals("Unknown ASN.1 tag 'UNIVERSAL:14' found", ex.getMessage());
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

    /**
     * {@code levels} nested encodings of the given constructed identifier, around a NULL (which is one more level).
     */
    private static byte[] nested(int identifier, int levels) {
        byte[] inner = bytes(0x05, 0x00);
        for (int i = 0; i < levels; i++) {
            int l = inner.length;
            byte[] lengthOctets = l < 128 ? bytes(l) : l < 256 ? bytes(0x81, l) : bytes(0x82, l >> 8, l);
            byte[] wrapped = new byte[1 + lengthOctets.length + l];
            wrapped[0] = (byte) identifier;
            System.arraycopy(lengthOctets, 0, wrapped, 1, lengthOctets.length);
            System.arraycopy(inner, 0, wrapped, 1 + lengthOctets.length, l);
            inner = wrapped;
        }
        return inner;
    }

    @Test
    void shouldParseNestingUpToTheLimit() {
        ASN1Object<?> object = new ASN1InputStream(new BERDecoder(), nested(0x30, ASN1InputStream.MAX_NESTING_DEPTH - 1)).readObject();

        assertInstanceOf(ASN1Sequence.class, object);
    }

    @ParameterizedTest(name = "identifier {0}")
    @ValueSource(ints = {0x30, 0x31})   // SEQUENCE, SET
    void shouldRejectNestingBeyondTheLimit(int identifier) {
        ASN1InputStream is = new ASN1InputStream(new BERDecoder(), nested(identifier, ASN1InputStream.MAX_NESTING_DEPTH));

        assertThrows(ASN1ParseException.class, is::readObject);
    }

    @Test
    void shouldUnwrapDeepChainOfTaggedObjectsOneLevelAtATime() {
        // Tagged objects are parsed lazily, one level per getObject() call, so a deep chain does not recurse
        ASN1Object<?> object = new ASN1InputStream(new BERDecoder(), nested(0xa0, 3000)).readObject();
        int levels = 0;
        while (object instanceof ASN1TaggedObject) {
            object = ((ASN1TaggedObject) object).getObject();
            levels++;
        }

        assertEquals(3000, levels);
    }

    @Test
    void shouldRejectDeepNestingWithoutStackOverflow() {
        // ~9 KB of input; used to cause a StackOverflowError
        ASN1InputStream is = new ASN1InputStream(new BERDecoder(), nested(0x30, 3000));

        ASN1ParseException ex = assertThrows(ASN1ParseException.class, is::readObject);

        assertTrue(ex.getMessage().contains("nested deeper than"), ex.getMessage());
    }

    @Test
    void shouldResetNestingDepthAfterFailure() {
        assertThrows(ASN1ParseException.class, () -> new ASN1InputStream(new BERDecoder(), nested(0x30, 3000)).readObject());

        // A following parse on the same thread starts at depth 0 again
        assertInstanceOf(ASN1Sequence.class, new ASN1InputStream(new BERDecoder(), nested(0x30, ASN1InputStream.MAX_NESTING_DEPTH - 1)).readObject());
    }
}
