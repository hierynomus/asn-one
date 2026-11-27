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
 * ASN.1 SEQUENCE and SEQUENCE OF (UNIVERSAL 16).
 * <p>
 * A SEQUENCE is immutable. A parsed SEQUENCE is re-encoded with its original contents, one constructed in code is
 * encoded in DER when it is created.
 */
public class ASN1Sequence extends ASN1Object<List<ASN1Object>> implements ASN1Constructed {
    private final List<ASN1Object> objects;
    private final byte[] bytes;

    private ASN1Sequence(List<ASN1Object> objects, byte[] bytes) {
        super(ASN1Tag.SEQUENCE);
        this.objects = objects;
        this.bytes = bytes;
    }

    /**
     * Creates a SEQUENCE of the given objects. The list is copied, so later changes to it do not affect this SEQUENCE.
     *
     * @param objects the elements of the SEQUENCE.
     */
    public ASN1Sequence(List<? extends ASN1Object> objects) {
        super(ASN1Tag.SEQUENCE);
        this.objects = DerContents.copyElements(objects, "SEQUENCE");
        this.bytes = DerContents.encodeElements(this.objects, false);
    }

    @Override
    public List<ASN1Object> getValue() {
        return new ArrayList<>(objects);
    }

    @Override
    public Iterator<ASN1Object> iterator() {
        return objects.iterator();
    }

    public int size() {
        return objects.size();
    }

    public ASN1Object get(int i) {
        return objects.get(i);
    }

    @Override
    public int hashCode() {
        // Consistent with equals, which compares the elements in order
        return 31 * tag.hashCode() + objects.hashCode();
    }

    public static class Parser extends ASN1Parser<ASN1Sequence> {

        public Parser(ASN1Decoder decoder) {
            super(decoder);
        }

        @Override
        public ASN1Sequence parse(ASN1Tag<ASN1Sequence> asn1Tag, byte[] value) throws ASN1ParseException {
            List<ASN1Object> list = new ArrayList<>();
            try (ASN1InputStream stream = new ASN1InputStream(decoder, value)) {
                for (ASN1Object asn1Object : stream) {
                    list.add(asn1Object);
                }
            } catch (IOException e) {
                throw new ASN1ParseException(e, "Unable to parse the ASN.1 SEQUENCE contents.");
            }
            return new ASN1Sequence(Collections.unmodifiableList(list), value);
        }
    }

    public static class Serializer extends ASN1Serializer<ASN1Sequence> {
        public Serializer(final ASN1Encoder encoder) {
            super(encoder);
        }

        @Override
        public int serializedLength(final ASN1Sequence asn1Object) {
            return asn1Object.bytes.length;
        }

        @Override
        public void serialize(final ASN1Sequence asn1Object, final ASN1OutputStream stream) throws IOException {
            stream.write(asn1Object.bytes);
        }
    }

}
