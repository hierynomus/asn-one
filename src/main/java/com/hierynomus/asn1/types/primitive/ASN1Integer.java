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

import com.hierynomus.asn1.ASN1Parser;
import com.hierynomus.asn1.encodingrules.ASN1Decoder;
import com.hierynomus.asn1.types.ASN1Tag;

import java.math.BigInteger;

public class ASN1Integer extends ASN1PrimitiveValue<BigInteger> {
    private BigInteger value;

    public ASN1Integer(long value) {
        this(BigInteger.valueOf(value));
    }

    public ASN1Integer(BigInteger value) {
        super(ASN1Tag.INTEGER);
        this.value = value;
    }

    public ASN1Integer(byte[] valueBytes, BigInteger value) {
        super(ASN1Tag.INTEGER, valueBytes);
        this.value = value;
    }

    @Override
    public BigInteger getValue() {
        return value;
    }

    @Override
    protected int valueHash() {
        return value.hashCode();
    }

    public static class Parser extends ASN1Parser<ASN1Integer> {
        public Parser(ASN1Decoder decoder) {
            super(decoder);
        }

        @Override
        public ASN1Integer parse(ASN1Tag<ASN1Integer> asn1Tag, byte[] value) {
            return new ASN1Integer(value, new BigInteger(value));
        }
    }
}
