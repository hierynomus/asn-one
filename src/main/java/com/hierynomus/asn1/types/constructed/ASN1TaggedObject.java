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
import java.util.Arrays;
import java.util.Iterator;
import com.hierynomus.asn1.*;
import com.hierynomus.asn1.encodingrules.ASN1Decoder;
import com.hierynomus.asn1.encodingrules.ASN1Encoder;
import com.hierynomus.asn1.types.ASN1Constructed;
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.ASN1Tag;

import static com.hierynomus.asn1.util.Checks.checkFormat;

/**
 * An object with a tag of the APPLICATION, CONTEXT-SPECIFIC or PRIVATE class, which is either explicitly tagged (the
 * contents are the complete encoding of the underlying object) or implicitly tagged (the contents are those of the
 * underlying object).
 * <p>
 * A tagged object is immutable. A parsed one keeps its original contents and decodes them on request, as only the
 * schema tells how; one constructed in code is encoded in DER when it is created.
 */
public class ASN1TaggedObject extends ASN1Object<ASN1Object> implements ASN1Constructed {
    private final ASN1Object object;
    private final byte[] bytes;
    private final ASN1Decoder decoder;
    private final boolean explicit;
    private final int hashCode;

    public ASN1TaggedObject(ASN1Tag tag, ASN1Object object, boolean explicit) {
        // If this is an explicitly tagged object, it should be constructed form
        // Else we take the form of the implictly tagged object.
        super(explicit ? tag.constructed() : tag.asEncoded(object.getTag().getAsn1Encoding()));
        this.object = object;
        this.explicit = explicit;
        this.decoder = null;
        this.bytes = explicit ? DerContents.encode(object) : DerContents.encodeContents(object);
        this.hashCode = hash(this.tag, this.bytes);
    }

    public ASN1TaggedObject(ASN1Tag tag, ASN1Object object) {
        this(tag, object, true);
    }

    private ASN1TaggedObject(ASN1Tag tag, byte[] bytes, ASN1Decoder decoder) {
        super(tag);
        this.bytes = bytes;
        this.decoder = decoder;
        // An explicit tag always uses the constructed form (X.690 8.14.2), so a primitive one is implicit. A
        // constructed one can be either: an explicit tag, or an implicit tag on a constructed type such as a SEQUENCE.
        this.explicit = tag.isConstructed();
        this.object = null;
        this.hashCode = hash(this.tag, bytes);
    }

    private static int hash(ASN1Tag<?> tag, byte[] bytes) {
        return 31 * tag.hashCode() + Arrays.hashCode(bytes);
    }

    /**
     * Whether this is an explicitly tagged object.
     * <p>
     * For a parsed object, the encoding alone does not always tell: a primitive tagged object is always implicit, but a
     * constructed one can be either explicitly tagged, or an implicit tag on a constructed type such as a SEQUENCE. In
     * that case this returns {@code true}, and only the schema determines whether to use {@link #getObject()} or
     * {@link #getObject(ASN1Tag)}.
     *
     * @return {@code false} if this object is implicitly tagged, {@code true} if it is (or, when parsed, may be)
     * explicitly tagged.
     */
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
        public int serializedLength(final ASN1TaggedObject asn1Object) {
            return asn1Object.bytes.length;
        }

        @Override
        public void serialize(final ASN1TaggedObject asn1Object, final ASN1OutputStream stream) throws IOException {
            stream.write(asn1Object.bytes);
        }
    }

    public ASN1Object getObject() {
        if (object != null) {
            return object;
        }
        // An explicit tag always uses the constructed form (X.690 8.14.2)
        checkFormat(tag.isConstructed(), "Unable to parse the primitive Tagged Object with %s as explicit, it is implicit", tag);
        try (ASN1InputStream inputStream = new ASN1InputStream(decoder, bytes)) {
            ASN1Object read = inputStream.readObject();
            // An explicitly tagged object contains exactly one complete encoding (X.690 8.14.3)
            int left = inputStream.available();
            checkFormat(left == 0, "%s bytes left after the explicitly tagged object", left);
            return read;
        } catch (ASN1ParseException e) {
            throw new ASN1ParseException(e, "Unable to parse the explicit Tagged Object with %s, it might be implicit", tag);
        } catch (IOException e) {
            throw new ASN1ParseException(e, "Could not parse the inputstream");
        }
    }

    public <T extends ASN1Object> T getObject(ASN1Tag<T> tag) {
        if (object != null && object.getTag().equals(tag)) {
            return (T) object;
        } else  if (object == null && bytes != null) {
            // For an implicitly tagged object, the encoding (primitive/constructed) of the outer tag is that of the
            // underlying type, so the parser needs to know about it (e.g. [0] IMPLICIT OCTET STRING, constructed).
            ASN1Tag<T> encodedTag = tag.getSupportedEncodings().contains(this.tag.getAsn1Encoding()) ? tag.asEncoded(this.tag.getAsn1Encoding()) : tag;
            return encodedTag.newParser(decoder).parse(encodedTag, bytes);
        }
        throw new ASN1ParseException("Unable to parse the implicit Tagged Object with %s, it is explicit", tag);
    }

    /**
     * Two tagged objects are equal if they have the same tag and the same encoded contents.
     * <p>
     * Without the schema, that is the only consistent notion of equality: for instance, {@code [1] EXPLICIT INTEGER}
     * and {@code [1] IMPLICIT SEQUENCE OF INTEGER} can encode to exactly the same octets. A parsed object that was
     * not DER encoded is therefore not equal to the same value constructed in code.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof ASN1TaggedObject)) {
            return false;
        }
        ASN1TaggedObject that = (ASN1TaggedObject) o;
        return hashCode == that.hashCode && tag.equals(that.tag) && Arrays.equals(bytes, that.bytes);
    }

    @Override
    public int hashCode() {
        return hashCode;
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
