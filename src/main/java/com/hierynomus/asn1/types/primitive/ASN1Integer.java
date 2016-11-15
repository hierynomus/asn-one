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

import java.io.IOException;
import java.math.BigInteger;
import com.hierynomus.asn1.ASN1OutputStream;
import com.hierynomus.asn1.ASN1Parser;
import com.hierynomus.asn1.ASN1Serializer;
import com.hierynomus.asn1.types.ASN1Tag;

public class ASN1Integer extends ASN1PrimitiveValue<BigInteger> {
    private BigInteger value;

    public ASN1Integer(long value) {
        this(BigInteger.valueOf(value));
    }

    public ASN1Integer(BigInteger value) {
        super(ASN1Tag.INTEGER);
        this.value = value;
        this.valueBytes = value.toByteArray();
    }

    private ASN1Integer(byte[] valueBytes, BigInteger value) {
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

    public static class Parser implements ASN1Parser<ASN1Integer> {
        @Override
        public ASN1Integer parse(byte[] value) {
            return new ASN1Integer(value, new BigInteger(value));
        }
    }

    public static class Serializer implements ASN1Serializer<ASN1Integer> {
        @Override
        public int serializedLength(final ASN1Integer asn1Object) {
            return asn1Object.valueBytes.length;
        }

        @Override
        public void serialize(final ASN1Integer asn1Object, final ASN1OutputStream stream) throws IOException {
            stream.write(asn1Object.valueBytes);
        }
    }

}
