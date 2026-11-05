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
import java.util.Arrays;

import com.hierynomus.asn1.ASN1OutputStream;
import com.hierynomus.asn1.ASN1ParseException;
import com.hierynomus.asn1.ASN1Parser;
import com.hierynomus.asn1.ASN1Serializer;
import com.hierynomus.asn1.encodingrules.ASN1Decoder;
import com.hierynomus.asn1.encodingrules.ASN1Encoder;
import com.hierynomus.asn1.types.ASN1Tag;

public final class ASN1UTCTime extends ASN1String<byte[]> {
    public ASN1UTCTime(byte[] bytes) {
        super(ASN1Tag.UTC_TIME, bytes);
    }

    public ASN1UTCTime(ASN1Tag<ASN1UTCTime> tag, byte[] bytes) {
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

    @Override
    public String toString() {
        String str = new String(valueBytes);
        return this.getClass().getSimpleName() + " [" + str + "]";
    }

    public static class Parser extends ASN1Parser<ASN1UTCTime> {
        public Parser(ASN1Decoder decoder) {
            super(decoder);
        }

        @Override
        public ASN1UTCTime parse(ASN1Tag<ASN1UTCTime> asn1Tag, byte[] value) throws ASN1ParseException {
            return new ASN1UTCTime(asn1Tag, value);
        }
    }

    public static class Serializer extends ASN1Serializer<ASN1UTCTime> {
        public Serializer(final ASN1Encoder encoder) {
            super(encoder);
        }

        @Override
        public int serializedLength(final ASN1UTCTime asn1Object) throws IOException {
            return asn1Object.valueBytes.length;
        }

        @Override
        public void serialize(final ASN1UTCTime asn1Object, final ASN1OutputStream stream) throws IOException {
            stream.write(asn1Object.valueBytes);
        }
    }

}