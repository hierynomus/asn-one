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
package com.hierynomus.asn1.types.primitive;

import java.math.BigInteger;
import com.hierynomus.asn1.ASN1OutputStream;
import com.hierynomus.asn1.ASN1ParseException;
import com.hierynomus.asn1.ASN1Parser;
import com.hierynomus.asn1.encodingrules.ASN1Decoder;
import com.hierynomus.asn1.ASN1Serializer;
import com.hierynomus.asn1.encodingrules.ASN1Encoder;
import com.hierynomus.asn1.types.ASN1Tag;

public class ASN1Enumerated extends ASN1PrimitiveValue<BigInteger> {
    private final BigInteger value;

    private ASN1Enumerated(ASN1Tag tag, BigInteger value, byte[] valueBytes) {
        super(tag, valueBytes);
        this.value = value;
    }

    @Override
    public BigInteger getValue() {
        return value;
    }

    public static class Parser extends ASN1Parser<ASN1Enumerated> {
        public Parser(ASN1Decoder decoder) {
            super(decoder);
        }

        @Override
        public ASN1Enumerated parse(ASN1Tag<ASN1Enumerated> asn1Tag, byte[] value) throws ASN1ParseException {
            ASN1Integer parse = new ASN1Integer.Parser(decoder).parse(ASN1Tag.INTEGER, value);
            BigInteger value1 = (BigInteger) parse.getValue();
            return new ASN1Enumerated(ASN1Tag.ENUMERATED, value1, value);
        }
    }

    public static class Serializer extends ASN1Serializer<ASN1Enumerated> {
        public Serializer(final ASN1Encoder encoder) {
            super(encoder);
        }

        @Override
        public int serializedLength(final ASN1Enumerated asn1Object) {
            return 0;
        }

        @Override
        public void serialize(final ASN1Enumerated asn1Object, final ASN1OutputStream stream) {

        }
    }

}
