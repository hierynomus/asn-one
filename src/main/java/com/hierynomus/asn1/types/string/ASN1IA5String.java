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

import java.nio.charset.StandardCharsets;

import com.hierynomus.asn1.ASN1ParseException;
import com.hierynomus.asn1.ASN1Parser;
import com.hierynomus.asn1.encodingrules.ASN1Decoder;
import com.hierynomus.asn1.encodingrules.ASN1Encoder;
import com.hierynomus.asn1.types.ASN1Tag;

/**
 * ASN.1 IA5String (UNIVERSAL 22, X.680 clause 41), the 128 characters of International Alphabet No. 5, i.e. ASCII
 * including the control characters. Used for e.g. e-mail addresses, DNS names and URIs in X.509 certificates.
 * <p>
 * As with all {@link ASN1CharacterString character strings}, this is enforced when constructing a value, but not
 * when parsing.
 */
public class ASN1IA5String extends ASN1CharacterString {

    public ASN1IA5String(String value) {
        this(ASN1Tag.IA5_STRING, value);
    }

    /**
     * @param tag the tag to use, e.g. an implicit tag
     * @param value the string value
     * @throws IllegalArgumentException if the value contains a character outside of IA5 (ASCII)
     */
    public ASN1IA5String(ASN1Tag<?> tag, String value) {
        super(tag, checkIA5(value), StandardCharsets.US_ASCII);
    }

    private ASN1IA5String(ASN1Tag<?> tag, byte[] bytes) {
        // ISO-8859-1 maps every octet to a character, so even non-conforming content survives a round trip.
        super(tag, bytes, StandardCharsets.ISO_8859_1);
    }

    /**
     * @return whether every character of {@code value} is permitted in an IA5String.
     */
    public static boolean isIA5String(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) > 0x7f) {
                return false;
            }
        }
        return true;
    }

    private static String checkIA5(String value) {
        if (!isIA5String(value)) {
            throw new IllegalArgumentException("Value contains characters not permitted in an ASN.1 IA5String: " + value);
        }
        return value;
    }

    public static class Parser extends ASN1Parser<ASN1IA5String> {
        public Parser(ASN1Decoder decoder) {
            super(decoder);
        }

        @Override
        public ASN1IA5String parse(ASN1Tag<ASN1IA5String> asn1Tag, byte[] value) throws ASN1ParseException {
            byte[] contents = primitiveContents(decoder, asn1Tag, ASN1Tag.IA5_STRING.getTag(), value);
            return new ASN1IA5String(asn1Tag.primitive(), contents);
        }
    }

    public static class Serializer extends CharacterStringSerializer<ASN1IA5String> {
        public Serializer(ASN1Encoder encoder) {
            super(encoder);
        }
    }
}
