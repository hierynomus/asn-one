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
import com.hierynomus.asn1.ASN1ParseException;
import com.hierynomus.asn1.ASN1Parser;
import com.hierynomus.asn1.types.ASN1Constructed;
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.ASN1Tag;

import java.io.IOException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

public class ASN1Set extends ASN1Object implements ASN1Constructed {
    private final Set<ASN1Object> objects;
    private byte[] bytes;

    private ASN1Set(Set<ASN1Object> objects, byte[] bytes) {
        super(ASN1Tag.SET);
        this.objects = objects;
        this.bytes = bytes;
    }

    public ASN1Set(Set<ASN1Object> objects) {
        super(ASN1Tag.SET);
        this.objects = new HashSet<>(objects);
    }

    @Override
    public Object getValue() {
        return new HashSet<>(objects);
    }

    public Iterator<ASN1Object> iterator() {
        return new HashSet<>(objects).iterator();
    }

    public static class Parser implements ASN1Parser<ASN1Set> {
        @Override
        public ASN1Set parse(byte[] value) throws ASN1ParseException {
            HashSet<ASN1Object> asn1Objects = new HashSet<>();
            try (ASN1InputStream stream = new ASN1InputStream(value)) {
                for (ASN1Object asn1Object : stream) {
                    asn1Objects.add(asn1Object);
                }
            } catch (IOException e) {
                throw new ASN1ParseException(e, "Could not parse ASN.1 SET contents.");
            }

            return new ASN1Set(asn1Objects, value);
        }
    }
}
