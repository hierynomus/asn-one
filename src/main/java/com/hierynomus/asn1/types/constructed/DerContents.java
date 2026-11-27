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
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import com.hierynomus.asn1.ASN1OutputStream;
import com.hierynomus.asn1.encodingrules.ASN1Encoder;
import com.hierynomus.asn1.encodingrules.der.DEREncoder;
import com.hierynomus.asn1.types.ASN1Object;

/**
 * Encodes the contents of constructed objects when they are created, so that they are immutable and their equality
 * and hash code can be based on their encoding. Objects constructed in code are encoded in DER.
 */
final class DerContents {
    private static final ASN1Encoder ENCODER = new DEREncoder();

    /**
     * X.690 11.6: ascending order, comparing as octet strings with the shorter one padded with trailing 0-octets.
     */
    static final Comparator<byte[]> DER_ORDER = new Comparator<byte[]>() {
        @Override
        public int compare(byte[] a, byte[] b) {
            for (int i = 0; i < Math.max(a.length, b.length); i++) {
                int x = i < a.length ? a[i] & 0xff : 0;
                int y = i < b.length ? b[i] & 0xff : 0;
                if (x != y) {
                    return x - y;
                }
            }
            return 0;
        }
    };

    private DerContents() {
    }

    /**
     * @return an unmodifiable copy of the elements, which must not be {@code null}.
     */
    static List<ASN1Object> copyElements(Collection<? extends ASN1Object> elements, String type) {
        List<ASN1Object> copy = new ArrayList<>(elements.size());
        for (ASN1Object element : elements) {
            if (element == null) {
                throw new NullPointerException("An ASN.1 " + type + " cannot contain null elements");
            }
            copy.add(element);
        }
        return Collections.unmodifiableList(copy);
    }

    /**
     * @return the complete encoding (identifier, length and contents) of the object.
     */
    static byte[] encode(ASN1Object object) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            new ASN1OutputStream(ENCODER, out).writeObject(object);
        } catch (IOException e) {
            // Cannot happen when writing to a ByteArrayOutputStream
            throw new UncheckedIOException(e);
        }
        return out.toByteArray();
    }

    /**
     * @return only the contents octets of the encoding of the object, as used for an implicitly tagged object.
     */
    @SuppressWarnings("unchecked")
    static byte[] encodeContents(ASN1Object object) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            object.getTag().newSerializer(ENCODER).serialize(object, new ASN1OutputStream(ENCODER, out));
        } catch (IOException e) {
            // Cannot happen when writing to a ByteArrayOutputStream
            throw new UncheckedIOException(e);
        }
        return out.toByteArray();
    }

    /**
     * @return the concatenated encodings of the elements, in the given order, or sorted if {@code sort} is set.
     */
    static byte[] encodeElements(List<ASN1Object> elements, boolean sort) {
        List<byte[]> encodings = new ArrayList<>(elements.size());
        for (ASN1Object element : elements) {
            encodings.add(encode(element));
        }
        if (sort) {
            Collections.sort(encodings, DER_ORDER);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] encoding : encodings) {
            out.write(encoding, 0, encoding.length);
        }
        return out.toByteArray();
    }
}
