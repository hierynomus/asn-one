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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import com.hierynomus.asn1.*;
import com.hierynomus.asn1.encodingrules.ASN1Decoder;
import com.hierynomus.asn1.encodingrules.ASN1Encoder;
import com.hierynomus.asn1.types.ASN1Constructed;
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.ASN1Tag;

/**
 * ASN.1 SET and SET OF (UNIVERSAL 17).
 * <p>
 * A SET OF value is an unordered collection that may contain duplicates (X.680 clause 28), so the elements are kept
 * as a list: a parsed SET keeps its elements, including duplicates, in the order they were received.
 * {@link #equals(Object)} ignores the order of the elements, but not how often each occurs.
 * <p>
 * Encoding:
 * <ul>
 * <li>A parsed SET is re-encoded with its original contents, so signatures over a received SET (e.g. CMS signed
 * attributes) remain valid, even if the sender did not order the elements canonically.</li>
 * <li>A SET constructed in code is encoded when it is created, with its elements sorted by their encodings, as DER requires for
 * SET OF (X.690 11.6). As this library has no schema, it cannot distinguish a SET from a SET OF; for a SET DER
 * orders by tag instead (X.690 10.3), which only differs when components of the same tag class have a different
 * primitive/constructed form.</li>
 * </ul>
 */
public class ASN1Set extends ASN1Object<List<ASN1Object>> implements ASN1Constructed {
    private final List<ASN1Object> objects;
    private final byte[] bytes;

    private ASN1Set(List<ASN1Object> objects, byte[] bytes) {
        super(ASN1Tag.SET);
        this.objects = objects;
        this.bytes = bytes;
    }

    /**
     * @param objects the elements of the SET, duplicates are kept
     */
    public ASN1Set(Collection<? extends ASN1Object> objects) {
        super(ASN1Tag.SET);
        this.objects = DerContents.copyElements(objects, "SET");
        this.bytes = DerContents.encodeElements(this.objects, true);
    }

    /**
     * @return a copy of the elements, in the order they were received or added
     */
    @Override
    public List<ASN1Object> getValue() {
        return new ArrayList<>(objects);
    }

    public Iterator<ASN1Object> iterator() {
        return objects.iterator();
    }

    public int size() {
        return objects.size();
    }

    /**
     * Two SETs are equal if they contain the same elements the same number of times, in any order.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ASN1Set)) return false;
        ASN1Set that = (ASN1Set) o;
        if (!tag.equals(that.tag) || objects.size() != that.objects.size()) return false;
        List<ASN1Object> remaining = new ArrayList<>(that.objects);
        for (ASN1Object object : objects) {
            if (!remaining.remove(object)) {
                return false;
            }
        }
        return true;
    }

    @Override
    public int hashCode() {
        // Consistent with equals: independent of the order of the elements
        int hash = 0;
        for (ASN1Object object : objects) {
            hash += object.hashCode();
        }
        return 31 * tag.hashCode() + hash;
    }

    public static class Parser extends ASN1Parser<ASN1Set> {
        public Parser(ASN1Decoder decoder) {
            super(decoder);
        }

        @Override
        public ASN1Set parse(ASN1Tag<ASN1Set> asn1Tag, byte[] value) throws ASN1ParseException {
            List<ASN1Object> asn1Objects = new ArrayList<>();
            try (ASN1InputStream stream = new ASN1InputStream(decoder, value)) {
                for (ASN1Object asn1Object : stream) {
                    asn1Objects.add(asn1Object);
                }
            } catch (IOException e) {
                throw new ASN1ParseException(e, "Could not parse ASN.1 SET contents.");
            }

            return new ASN1Set(Collections.unmodifiableList(asn1Objects), value);
        }
    }

    public static class Serializer extends ASN1Serializer<ASN1Set> {
        public Serializer(final ASN1Encoder encoder) {
            super(encoder);
        }

        @Override
        public int serializedLength(final ASN1Set asn1Object) {
            return asn1Object.bytes.length;
        }

        @Override
        public void serialize(final ASN1Set asn1Object, final ASN1OutputStream stream) throws IOException {
            stream.write(asn1Object.bytes);
        }
    }
}
