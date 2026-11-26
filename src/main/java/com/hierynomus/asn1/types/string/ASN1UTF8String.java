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
 * ASN.1 UTF8String (UNIVERSAL 12, X.680 clause 41), any sequence of Unicode characters, encoded as UTF-8.
 * <p>
 * As with all {@link ASN1CharacterString character strings}, parsing is lenient: invalid UTF-8 is decoded with
 * replacement characters in {@link #getValue()}, while the original octets are kept and re-encoded unchanged.
 */
public class ASN1UTF8String extends ASN1CharacterString {

    public ASN1UTF8String(String value) {
        this(ASN1Tag.UTF8_STRING, value);
    }

    /**
     * @param tag the tag to use, e.g. an implicit tag
     * @param value the string value
     * @throws IllegalArgumentException if the value cannot be encoded as UTF-8, i.e. contains unpaired surrogates
     */
    public ASN1UTF8String(ASN1Tag<?> tag, String value) {
        super(tag, checkEncodable(value), StandardCharsets.UTF_8);
    }

    private ASN1UTF8String(ASN1Tag<?> tag, byte[] bytes) {
        super(tag, bytes, StandardCharsets.UTF_8);
    }

    private static String checkEncodable(String value) {
        if (!StandardCharsets.UTF_8.newEncoder().canEncode(value)) {
            throw new IllegalArgumentException("Value contains unpaired surrogate characters and cannot be encoded as an ASN.1 UTF8String");
        }
        return value;
    }

    public static class Parser extends ASN1Parser<ASN1UTF8String> {
        public Parser(ASN1Decoder decoder) {
            super(decoder);
        }

        @Override
        public ASN1UTF8String parse(ASN1Tag<ASN1UTF8String> asn1Tag, byte[] value) throws ASN1ParseException {
            byte[] contents = primitiveContents(decoder, asn1Tag, ASN1Tag.UTF8_STRING.getTag(), value);
            return new ASN1UTF8String(asn1Tag.primitive(), contents);
        }
    }

    public static class Serializer extends CharacterStringSerializer<ASN1UTF8String> {
        public Serializer(ASN1Encoder encoder) {
            super(encoder);
        }
    }
}
