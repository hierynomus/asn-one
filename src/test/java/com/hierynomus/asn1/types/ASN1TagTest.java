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
package com.hierynomus.asn1.types;

import com.hierynomus.asn1.types.string.ASN1BitString;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class ASN1TagTest {

    @Test
    void derivedTagShouldEqualOriginalWithSameEncoding() {
        ASN1Tag<?> derived = ASN1Tag.OCTET_STRING.constructed().primitive();

        assertEquals(ASN1Tag.OCTET_STRING, derived);
        assertEquals(ASN1Tag.OCTET_STRING.hashCode(), derived.hashCode());
    }

    @Test
    void tagsShouldDifferOnEncoding() {
        assertNotEquals(ASN1Tag.OCTET_STRING, ASN1Tag.OCTET_STRING.constructed());
    }

    @Test
    void objectsWithArrayValuesShouldBeEqualByContent() {
        assertEquals(new ASN1BitString(new boolean[]{true, false, true}), new ASN1BitString(new boolean[]{true, false, true}));
        assertNotEquals(new ASN1BitString(new boolean[]{true, false, true}), new ASN1BitString(new boolean[]{true, true, true}));
    }
}
