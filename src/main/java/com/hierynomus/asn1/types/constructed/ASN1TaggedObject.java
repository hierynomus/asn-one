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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Iterator;
import com.hierynomus.asn1.*;
import com.hierynomus.asn1.encodingrules.ASN1Decoder;
import com.hierynomus.asn1.encodingrules.ASN1Encoder;
import com.hierynomus.asn1.types.ASN1Constructed;
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.ASN1Tag;

public class ASN1TaggedObject extends ASN1Object<ASN1Object> implements ASN1Constructed {
    private final ASN1Object object;
    private byte[] bytes;
    private ASN1Decoder decoder;
    private boolean explicit = true;

    public ASN1TaggedObject(ASN1Tag tag, ASN1Object object, boolean explicit) {
        // If this is an explicitly tagged object, it should be constructed form
        // Else we take the form of the implictly tagged object.
        super(explicit ? tag.constructed() : tag.asEncoded(object.getTag().getAsn1Encoding()));
        this.object = object;
        this.explicit = explicit;
        this.bytes = null;
    }

    public ASN1TaggedObject(ASN1Tag tag, ASN1Object object) {
        this(tag, object, true);
    }

    private ASN1TaggedObject(ASN1Tag tag, byte[] bytes, ASN1Decoder decoder) {
        super(tag);
        this.bytes = bytes;
        this.decoder = decoder;
        object = null;
    }

    public boolean isExplicit() {
        return explicit;
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

    public static class Parser extends ASN1Parser<ASN1TaggedObject> {

        public Parser(ASN1Decoder decoder) {
            super(decoder);
        }

        @Override
        public ASN1TaggedObject parse(ASN1Tag<ASN1TaggedObject> asn1Tag, byte[] value) {
            return new ASN1TaggedObject(asn1Tag, value, decoder);
        }
    }

    public static class Serializer extends ASN1Serializer<ASN1TaggedObject> {

        public Serializer(final ASN1Encoder encoder) {
            super(encoder);
        }

        @Override
        public int serializedLength(final ASN1TaggedObject asn1Object) throws IOException {
            if (asn1Object.bytes == null) {
                calculateBytes(asn1Object);
            }
            return asn1Object.bytes.length;
        }

        private void calculateBytes(final ASN1TaggedObject asn1Object) throws IOException {
            ASN1Object object = asn1Object.object;
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ASN1OutputStream asn1OutputStream = new ASN1OutputStream(encoder, baos);
            if (asn1Object.explicit) {
                asn1OutputStream.writeObject(object);
            } else {
                object.getTag().newSerializer(encoder).serialize(object, asn1OutputStream);
            }
            asn1Object.bytes = baos.toByteArray();
        }

        @Override
        public void serialize(final ASN1TaggedObject asn1Object, final ASN1OutputStream stream) throws IOException {
            if (asn1Object.bytes == null) {
                calculateBytes(asn1Object);
            }
            stream.write(asn1Object.bytes);
        }
    }

    public ASN1Object getObject() {
        if (object != null) {
            return object;
        }
        try {
            return new ASN1InputStream(decoder, bytes).readObject();
        } catch (ASN1ParseException e) {
            throw new ASN1ParseException(e, "Unable to parse the explicit Tagged Object with %s, it might be implicit", tag);
        }
    }

    public <T extends ASN1Object> T getObject(ASN1Tag<T> tag) {
        if (object != null && object.getTag().equals(tag)) {
            return (T) object;
        } else  if (object == null && bytes != null) {
            return tag.newParser(decoder).parse(tag, bytes);
        }
        throw new ASN1ParseException("Unable to parse the implicit Tagged Object with %s, it is explicit", tag);
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder();
        b.append(this.getClass().getSimpleName());
        b.append("[").append(tag);
        if (object != null) {
            b.append(",").append(object);
        } else {
            b.append(",<unknown>");
        }
        b.append("]");
        return b.toString();
    }
}
