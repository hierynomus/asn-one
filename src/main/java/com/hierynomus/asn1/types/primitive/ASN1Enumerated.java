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

import com.hierynomus.asn1.ASN1ParseException;
import com.hierynomus.asn1.ASN1Parser;
import com.hierynomus.asn1.types.ASN1Tag;

import java.math.BigInteger;

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

    public static class Parser implements ASN1Parser<ASN1Enumerated> {
        @Override
        public ASN1Enumerated parse(byte[] value) throws ASN1ParseException {
            ASN1Integer parse = new ASN1Integer.Parser().parse(value);
            BigInteger value1 = (BigInteger) parse.getValue();
            return new ASN1Enumerated(ASN1Tag.ENUMERATED, value1, value);
        }
    }
}
