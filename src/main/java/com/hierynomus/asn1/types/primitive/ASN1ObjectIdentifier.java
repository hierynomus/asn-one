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
import com.hierynomus.asn1.types.ASN1Tag;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;

import static com.hierynomus.asn1.util.Checks.checkArgument;

public class ASN1ObjectIdentifier extends ASN1PrimitiveValue {

    private String oid;

    public ASN1ObjectIdentifier(String oid) {
        super(ASN1Tag.OBJECT_IDENTIFIER);
        this.oid = oid;
    }

    private ASN1ObjectIdentifier(byte[] valueBytes, String oid) {
        super(ASN1Tag.OBJECT_IDENTIFIER, valueBytes);
        this.oid = oid;
    }

    @Override
    public Object getValue() {
        return oid;
    }

    @Override
    protected int valueHash() {
        return oid.hashCode();
    }

    public static class Parser implements ASN1Parser<ASN1ObjectIdentifier> {
        @Override
        public ASN1ObjectIdentifier parse(byte[] value) {
            checkArgument(value.length > 0, "An ASN.1 OBJECT IDENTIFIER should have at least a one byte value");
            ByteArrayInputStream is = new ByteArrayInputStream(value);
            StringBuilder b = new StringBuilder();
            int firstTwo = is.read();
            b.append(firstTwo / 40);
            b.append('.').append(firstTwo % 40);
            while (is.available() > 0) {
                int x = is.read();
                if (x < 127) {
                    b.append('.').append(x);
                } else {
                    BigInteger v = BigInteger.valueOf(x & 0x7f);
                    do {
                        x = is.read();
                        v = v.shiftLeft(7).add(BigInteger.valueOf(x & 0x7f));
                    } while (x > 127);
                    b.append('.').append(v);
                }
            }
            return new ASN1ObjectIdentifier(value, b.toString());
        }
    }
}
