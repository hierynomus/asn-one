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
package com.hierynomus.asn1.types;

import java.io.IOException;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Locale;

import com.hierynomus.asn1.ASN1InputStream;
import com.hierynomus.asn1.ASN1OutputStream;
import com.hierynomus.asn1.ASN1ParseException;
import com.hierynomus.asn1.ASN1Parser;
import com.hierynomus.asn1.ASN1Serializer;
import com.hierynomus.asn1.encodingrules.ASN1Decoder;
import com.hierynomus.asn1.encodingrules.ASN1Encoder;

/**
 * An object with a UNIVERSAL tag that this library has no specific type for, e.g. a BMPString (30) or a REAL (9).
 * <p>
 * Rather than failing on the whole structure, such an object is kept with its tag and raw contents octets, so the
 * rest of the structure can still be read, and the object is re-encoded exactly as it was read. For a constructed
 * encoding, the contents are the nested encodings, which are checked to be well-formed when parsing, and can be read
 * with an {@link ASN1InputStream}.
 */
public class ASN1UnknownObject extends ASN1Object<byte[]> {
    private final byte[] contents;

    /**
     * @param tag the tag of the object
     * @param contents the contents octets of the encoding
     */
    public ASN1UnknownObject(ASN1Tag<?> tag, byte[] contents) {
        super(tag);
        this.contents = Arrays.copyOf(contents, contents.length);
    }

    /**
     * @return a copy of the contents octets, as read
     */
    @Override
    public byte[] getValue() {
        return Arrays.copyOf(contents, contents.length);
    }

    @Override
    protected String valueString() {
        StringBuilder sb = new StringBuilder();
        for (byte b : contents) {
            sb.append(String.format(Locale.ROOT, "%02x", b & 0xff));
        }
        return sb.toString();
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + tag + "," + valueString() + "]";
    }

    /**
     * Creates the tag used for a UNIVERSAL tag number without a specific type.
     */
    static ASN1Tag<ASN1UnknownObject> universalTag(int tagNumber) {
        return new ASN1Tag<ASN1UnknownObject>(ASN1TagClass.UNIVERSAL, tagNumber, EnumSet.of(ASN1Encoding.PRIMITIVE, ASN1Encoding.CONSTRUCTED)) {
            @Override
            public ASN1Parser<ASN1UnknownObject> newParser(ASN1Decoder decoder) {
                return new Parser(decoder);
            }

            @Override
            public ASN1Serializer<ASN1UnknownObject> newSerializer(ASN1Encoder encoder) {
                return new Serializer(encoder);
            }
        };
    }

    public static class Parser extends ASN1Parser<ASN1UnknownObject> {
        public Parser(ASN1Decoder decoder) {
            super(decoder);
        }

        @Override
        public ASN1UnknownObject parse(ASN1Tag<ASN1UnknownObject> asn1Tag, byte[] value) throws ASN1ParseException {
            if (asn1Tag.isConstructed()) {
                checkNestedEncodings(asn1Tag, value);
            }
            return new ASN1UnknownObject(asn1Tag, value);
        }

        /**
         * The contents of a constructed encoding are complete encodings themselves (X.690 8.1.2.5). Without a known
         * type this is the only thing that can be checked, but it does reject input that is not BER/DER at all.
         */
        private void checkNestedEncodings(ASN1Tag<ASN1UnknownObject> asn1Tag, byte[] value) {
            try (ASN1InputStream stream = new ASN1InputStream(decoder, value)) {
                while (stream.available() > 0) {
                    stream.readObject();
                }
            } catch (ASN1ParseException e) {
                throw new ASN1ParseException(e, "Contents of constructed %s are not valid nested encodings", asn1Tag);
            } catch (IOException e) {
                throw new ASN1ParseException(e, "Unable to read contents of constructed %s", asn1Tag);
            }
        }
    }

    public static class Serializer extends ASN1Serializer<ASN1UnknownObject> {
        public Serializer(ASN1Encoder encoder) {
            super(encoder);
        }

        @Override
        public int serializedLength(ASN1UnknownObject asn1Object) {
            return asn1Object.contents.length;
        }

        @Override
        public void serialize(ASN1UnknownObject asn1Object, ASN1OutputStream stream) throws IOException {
            stream.write(asn1Object.contents);
        }
    }
}
