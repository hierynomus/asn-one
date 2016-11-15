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

import com.hierynomus.asn1.*;
import com.hierynomus.asn1.types.ASN1Constructed;
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.ASN1Tag;

import java.io.ByteArrayInputStream;
import java.util.Iterator;

public class ASN1TaggedObject extends ASN1Object<ASN1Object> implements ASN1Constructed {
    private byte[] bytes;

    protected ASN1TaggedObject(ASN1Tag tag, byte[] bytes) {
        super(tag);
        this.bytes = bytes;
    }

    @Override
    public ASN1Object getValue() {
        return getObject();
    }

    /**
     * Returns the identifying tag number of this ASN.1 Tagged Object.
     * @return the tag number.
     */
    public int getTagNo() {
        return tag.getTag();
    }

    @Override
    public Iterator<ASN1Object> iterator() {
        return getObject(ASN1Tag.SEQUENCE).iterator();
    }

    public static class Parser implements ASN1Parser<ASN1TaggedObject> {
        private ASN1Tag tag;

        public Parser(ASN1Tag tag) {
            this.tag = tag;
        }

        @Override
        public ASN1TaggedObject parse(byte[] value) {
            return new ASN1TaggedObject(tag, value);
        }
    }

    public static class Serializer implements ASN1Serializer<ASN1TaggedObject> {
        private final ASN1Tag tag;

        public Serializer(final ASN1Tag asn1Tag) {
            this.tag = asn1Tag;
        }

        @Override
        public int serializedLength(final ASN1TaggedObject asn1Object) {
            return 0;
        }

        @Override
        public void serialize(final ASN1TaggedObject asn1Object, final ASN1OutputStream stream) {

        }
    }

    public ASN1Object getObject() {
        try {
            return new ASN1InputStream(new ByteArrayInputStream(bytes)).readObject();
        } catch (ASN1ParseException e) {
            throw new ASN1ParseException(e, "Unable to parse the explicit Tagged Object with %s, it might be implicit", tag);
        }
    }

    public <T extends ASN1Object> T getObject(ASN1Tag<T> tag) {
        return tag.newParser().parse(bytes);
    }
}
