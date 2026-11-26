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
package com.hierynomus.asn1.types.string;

import java.io.IOException;
import java.nio.charset.Charset;

import com.hierynomus.asn1.ASN1OutputStream;
import com.hierynomus.asn1.ASN1Serializer;
import com.hierynomus.asn1.encodingrules.ASN1Decoder;
import com.hierynomus.asn1.encodingrules.ASN1Encoder;
import com.hierynomus.asn1.types.ASN1Tag;

/**
 * Base class for the ASN.1 restricted character string types (X.680 clause 41) and the types defined in terms of
 * them, such as UTCTime. The value is kept as the encoded octets, and exposed as a {@link String} decoded with the
 * character set of the type.
 * <p>
 * Reading is lenient: parsed content is not validated against the permitted characters of the type, so values
 * written by non-conforming encoders can still be read, and are re-encoded byte for byte. Constructing a value from
 * a {@link String} is strict and rejects characters the type does not permit.
 */
public abstract class ASN1CharacterString extends ASN1String<String> {
    private final String value;

    /**
     * Wrap encoded contents as they were read, without validation.
     */
    protected ASN1CharacterString(ASN1Tag<?> tag, byte[] bytes, Charset charset) {
        super(tag, bytes);
        this.value = new String(bytes, charset);
    }

    /**
     * Create a value from an already validated {@link String}.
     */
    protected ASN1CharacterString(ASN1Tag<?> tag, String value, Charset charset) {
        super(tag, value.getBytes(charset));
        this.value = value;
    }

    @Override
    public String getValue() {
        return value;
    }

    @Override
    protected String valueString() {
        return value;
    }

    /**
     * @return the number of characters (Unicode code points) in this string.
     */
    @Override
    public int length() {
        return value.codePointCount(0, value.length());
    }

    /**
     * Returns the contents octets of the primitive form, joining the segments if the value was encoded in the
     * constructed form (X.690 8.23.6).
     */
    protected static byte[] primitiveContents(ASN1Decoder decoder, ASN1Tag<?> asn1Tag, int universalTag, byte[] value) {
        return asn1Tag.isConstructed() ? joinSegments(decoder, universalTag, value) : value;
    }

    /**
     * Serializes a character string in the primitive form, as required by DER (X.690 10.2).
     */
    public static class CharacterStringSerializer<T extends ASN1CharacterString> extends ASN1Serializer<T> {
        public CharacterStringSerializer(ASN1Encoder encoder) {
            super(encoder);
        }

        @Override
        public int serializedLength(T asn1Object) {
            return asn1Object.valueBytes.length;
        }

        @Override
        public void serialize(T asn1Object, ASN1OutputStream stream) throws IOException {
            stream.write(asn1Object.valueBytes);
        }
    }
}
