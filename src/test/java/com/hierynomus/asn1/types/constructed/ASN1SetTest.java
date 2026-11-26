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

import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.primitive.ASN1Boolean;
import com.hierynomus.asn1.types.primitive.ASN1Integer;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ASN1SetTest {

    private static ASN1Set newSet() {
        return new ASN1Set(new HashSet<ASN1Object>(Arrays.<ASN1Object>asList(new ASN1Boolean(true), new ASN1Integer(1))));
    }

    @Test
    void shouldNotMutateInternalSet() {
        ASN1Set set = newSet();

        set.getValue().clear();

        assertEquals(2, set.getValue().size());
    }

    @Test
    void shouldNotMutateInternalSetThroughIterator() {
        ASN1Set set = newSet();
        Iterator<ASN1Object> iterator = set.iterator();

        iterator.next();
        iterator.remove();

        assertEquals(2, set.getValue().size());
    }
}
