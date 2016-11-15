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
import com.hierynomus.asn1.ASN1OutputStream;
import com.hierynomus.asn1.ASN1Parser;
import com.hierynomus.asn1.ASN1Serializer;
import com.hierynomus.asn1.types.ASN1Tag;
import com.hierynomus.asn1.util.Checks;

public class ASN1Null extends ASN1PrimitiveValue<Void> {

    private static final byte[] NULL_BYTES = new byte[0];

    public ASN1Null() {
        super(ASN1Tag.NULL, NULL_BYTES);
    }

    @Override
    public Void getValue() {
        return null;
    }

    @Override
    protected int valueHash() {
        return 0;
    }

    public static class Parser implements ASN1Parser<ASN1Null> {
        @Override
        public ASN1Null parse(byte[] value) {
            Checks.checkState(value.length == 0, "ASN.1 NULL can not have a value");
            return new ASN1Null();
        }
    }

    public static class Serializer implements ASN1Serializer<ASN1Null> {
        @Override
        public int serializedLength(final ASN1Null asn1Object) {
            return 0;
        }

        @Override
        public void serialize(final ASN1Null asn1Object, final ASN1OutputStream stream) throws IOException {
            // No-op, no data
        }
    }

}
