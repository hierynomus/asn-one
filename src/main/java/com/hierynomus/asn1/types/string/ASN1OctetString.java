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

import com.hierynomus.asn1.ASN1ParseException;
import com.hierynomus.asn1.ASN1Parser;
import com.hierynomus.asn1.encodingrules.ASN1Decoder;
import com.hierynomus.asn1.types.ASN1Tag;

import java.util.Arrays;

public class ASN1OctetString extends ASN1String<byte[]> {
    public ASN1OctetString(ASN1Tag<?> tag, byte[] bytes) {
        super(tag, bytes);
    }

    @Override
    public byte[] getValue() {
        return Arrays.copyOf(valueBytes, valueBytes.length);
    }

    @Override
    public int length() {
        return valueBytes.length;
    }

    public static class Parser extends ASN1Parser<ASN1OctetString> {

        public Parser(ASN1Decoder decoder) {
            super(decoder);
        }

        @Override
        public ASN1OctetString parse(ASN1Tag<ASN1OctetString> asn1Tag, byte[] value) throws ASN1ParseException {
            return new ASN1OctetString(asn1Tag, value);
        }
    }
}
