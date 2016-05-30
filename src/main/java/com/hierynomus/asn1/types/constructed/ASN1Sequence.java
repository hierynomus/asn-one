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
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class ASN1Sequence extends ASN1Object<List<ASN1Object>> implements ASN1Constructed {
    private final List<ASN1Object> objects;
    private byte[] bytes;

    private ASN1Sequence(List<ASN1Object> objects, byte[] bytes) {
        super(ASN1Tag.SEQUENCE);
        this.objects = objects;
        this.bytes = bytes;
    }

    public ASN1Sequence(List<ASN1Object> objects) {
        super(ASN1Tag.SEQUENCE);
        this.objects = objects;
    }

    @Override
    public List<ASN1Object> getValue() {
        return new ArrayList<>(objects);
    }

    @Override
    public Iterator<ASN1Object> iterator() {
        return new ArrayList<>(objects).iterator();
    }

    public int size() {
        return objects.size();
    }

    public ASN1Object get(int i) {
        return objects.get(i);
    }

    public static class Parser implements ASN1Parser<ASN1Sequence> {

        @Override
        public ASN1Sequence parse(byte[] value) throws ASN1ParseException {
            List<ASN1Object> list = new ArrayList<>();
            try (ASN1InputStream stream = new ASN1InputStream(value)) {
                for (ASN1Object asn1Object : stream) {
                    list.add(asn1Object);
                }
            } catch (IOException e) {
                throw new ASN1ParseException(e, "Unable to parse the ASN.1 SEQUENCE contents.");
            }
            return new ASN1Sequence(list, value);
        }
    }
}
