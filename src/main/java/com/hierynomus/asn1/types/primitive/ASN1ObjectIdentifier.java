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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.StringTokenizer;
import com.hierynomus.asn1.ASN1OutputStream;
import com.hierynomus.asn1.ASN1Parser;
import com.hierynomus.asn1.ASN1Serializer;
import com.hierynomus.asn1.ASN1Decoder;
import com.hierynomus.asn1.ASN1Encoder;
import com.hierynomus.asn1.types.ASN1Tag;

import static com.hierynomus.asn1.util.Checks.checkArgument;

public class ASN1ObjectIdentifier extends ASN1PrimitiveValue<String> {

    private String oid;

    public ASN1ObjectIdentifier(String oid) {
        super(ASN1Tag.OBJECT_IDENTIFIER);
        this.oid = oid;
    }

    public ASN1ObjectIdentifier(byte[] valueBytes, String oid) {
        super(ASN1Tag.OBJECT_IDENTIFIER, valueBytes);
        this.oid = oid;
    }

    @Override
    public String getValue() {
        return oid;
    }

    @Override
    protected int valueHash() {
        return oid.hashCode();
    }

    public static class Serializer extends ASN1Serializer<ASN1ObjectIdentifier> {
        public Serializer(final ASN1Encoder encoder) {
            super(encoder);
        }

        @Override
        public int serializedLength(final ASN1ObjectIdentifier asn1Object) {
            if (asn1Object.valueBytes == null) {
                calculateBytes(asn1Object);
            }
            return asn1Object.valueBytes.length;
        }

        private void calculateBytes(final ASN1ObjectIdentifier asn1Object) {
            String oid = asn1Object.oid;
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            StringTokenizer tokenizer = new StringTokenizer(oid, ".");
            int first = Integer.parseInt(tokenizer.nextToken());
            int second = Integer.parseInt(tokenizer.nextToken());
            baos.write(first * 40 + second);
            while (tokenizer.hasMoreTokens()) {
                BigInteger token = new BigInteger(tokenizer.nextToken());
                if (token.intValue() > 0 && token.intValue() < 127) {
                    baos.write(token.intValue());
                } else {
                    int neededBytes = token.bitLength() / 7 + ((token.bitLength() % 7 > 0) ? 1 : 0);
                    for (int i = neededBytes - 1; i >= 0; i--) {
                        byte b = token.shiftRight(i * 7).byteValue();
                        b &= 0x7f;
                        if (i > 0) {
                            b |= 0x80;
                        }
                        baos.write(b);
                    }
                }
            }
            asn1Object.valueBytes = baos.toByteArray();
        }

        @Override
        public void serialize(final ASN1ObjectIdentifier asn1Object, final ASN1OutputStream stream) throws IOException {
            if (asn1Object.valueBytes == null) {
                calculateBytes(asn1Object);
            }
            stream.write(asn1Object.valueBytes);
        }
    }

}
