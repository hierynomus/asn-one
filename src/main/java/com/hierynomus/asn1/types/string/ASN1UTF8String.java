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

import com.hierynomus.asn1.ASN1OutputStream;
import com.hierynomus.asn1.ASN1ParseException;
import com.hierynomus.asn1.ASN1Parser;
import com.hierynomus.asn1.ASN1Serializer;
import com.hierynomus.asn1.encodingrules.ASN1Decoder;
import com.hierynomus.asn1.encodingrules.ASN1Encoder;
import com.hierynomus.asn1.types.ASN1Tag;

import java.io.IOException;
import java.util.Arrays;

public class ASN1UTF8String extends ASN1String<byte[]> {
    public ASN1UTF8String(byte[] bytes) {
        super(ASN1Tag.UTF8_STRING, bytes);
    }

    public ASN1UTF8String(ASN1Tag<?> tag, byte[] bytes) {
        super(tag, bytes);
    }

    @Override
    public byte[] getValue() {
        return Arrays.copyOf(valueBytes, valueBytes.length);
    }

    @Override
    protected String valueString() {
        return Arrays.toString(valueBytes);
    }

    @Override
    public int length() {
        return valueBytes.length;
    }

    public static class Parser extends ASN1Parser<ASN1UTF8String> {

        public Parser(ASN1Decoder decoder) {
            super(decoder);
        }

        @Override
        public ASN1UTF8String parse(ASN1Tag<ASN1UTF8String> asn1Tag, byte[] value) throws ASN1ParseException {
            return new ASN1UTF8String(asn1Tag, value);
        }
    }

    public static class Serializer extends ASN1Serializer<ASN1UTF8String> {

        public Serializer(final ASN1Encoder encoder) {
            super(encoder);
        }

        @Override
        public int serializedLength(final ASN1UTF8String asn1Object) throws IOException {
            return asn1Object.valueBytes.length;
        }

        @Override
        public void serialize(final ASN1UTF8String asn1Object, final ASN1OutputStream stream) throws IOException {
            stream.write(asn1Object.valueBytes);
        }
    }
}
