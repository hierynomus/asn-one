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
 * ASN.1 PrintableString (UNIVERSAL 19, X.680 clause 41).
 * <p>
 * Permitted characters are {@code A-Z a-z 0-9}, space and {@code ' ( ) + , - . / : = ?}. As with all
 * {@link ASN1CharacterString character strings}, this is enforced when constructing a value, but not when parsing.
 */
public class ASN1PrintableString extends ASN1CharacterString {

    public ASN1PrintableString(String value) {
        this(ASN1Tag.PRINTABLE_STRING, value);
    }

    /**
     * @param tag the tag to use, e.g. an implicit tag
     * @param value the string value
     * @throws IllegalArgumentException if the value contains a character not permitted in a PrintableString
     */
    public ASN1PrintableString(ASN1Tag<?> tag, String value) {
        super(tag, checkPrintable(value), StandardCharsets.US_ASCII);
    }

    private ASN1PrintableString(ASN1Tag<?> tag, byte[] bytes) {
        // ISO-8859-1 maps every octet to a character, so even non-conforming content survives a round trip.
        super(tag, bytes, StandardCharsets.ISO_8859_1);
    }

    /**
     * @return whether every character of {@code value} is permitted in a PrintableString.
     */
    public static boolean isPrintableString(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (!isPrintableCharacter(value.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    private static boolean isPrintableCharacter(char c) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
            return true;
        }
        switch (c) {
            case ' ':
            case '\'':
            case '(':
            case ')':
            case '+':
            case ',':
            case '-':
            case '.':
            case '/':
            case ':':
            case '=':
            case '?':
                return true;
            default:
                return false;
        }
    }

    private static String checkPrintable(String value) {
        if (!isPrintableString(value)) {
            throw new IllegalArgumentException("Value contains characters not permitted in an ASN.1 PrintableString: " + value);
        }
        return value;
    }

    public static class Parser extends ASN1Parser<ASN1PrintableString> {
        public Parser(ASN1Decoder decoder) {
            super(decoder);
        }

        @Override
        public ASN1PrintableString parse(ASN1Tag<ASN1PrintableString> asn1Tag, byte[] value) throws ASN1ParseException {
            byte[] contents = primitiveContents(decoder, asn1Tag, ASN1Tag.PRINTABLE_STRING.getTag(), value);
            return new ASN1PrintableString(asn1Tag.primitive(), contents);
        }
    }

    public static class Serializer extends CharacterStringSerializer<ASN1PrintableString> {
        public Serializer(ASN1Encoder encoder) {
            super(encoder);
        }
    }
}
