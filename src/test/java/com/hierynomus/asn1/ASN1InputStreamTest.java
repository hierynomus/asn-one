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
import org.junit.jupiter.api.Test;

import static com.hierynomus.asn1.Bytes.bytes;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
}
