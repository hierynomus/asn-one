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

import com.hierynomus.asn1.ASN1InputStream;
import com.hierynomus.asn1.ASN1ParseException;
import com.hierynomus.asn1.ASN1Parser;
import com.hierynomus.asn1.encodingrules.ASN1Decoder;
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.ASN1Tag;
import com.hierynomus.asn1.types.constructed.ASN1Sequence;
import com.hierynomus.asn1.util.Checks;

import java.io.IOException;
import java.util.Arrays;
import java.util.BitSet;

public class ASN1BitString extends ASN1String<BitSet> {

    private int unusedBits;

    private ASN1BitString(ASN1Tag<ASN1BitString> tag, byte[] bytes, int unusedBits) {
        super(tag, bytes);
        this.unusedBits = unusedBits;
    }

    public ASN1BitString(BitSet bitSet) {
        super(ASN1Tag.BIT_STRING, bitSet.toByteArray());
    }

    @Override
    public BitSet getValue() {
        return BitSet.valueOf(valueBytes);
    }

    /**
     * Check whether bit 'x' is set in the ASN.1 BIT_STRING
     * @param x The bit to check
     * @return <code>true</code> if bit 'x' is set, <code>false</code> otherwise.
     */
    public boolean isSet(int x) {
        int toCheck = x / 8;
        byte theByte = valueBytes[toCheck];
        int index = x % 8;
        int mask = 1 << (7 - index);
        int masked = theByte & mask;
        return masked != 0;
    }

    @Override
    public int length() {
        return (valueBytes.length * 8) - unusedBits;
    }

    public static class Parser extends ASN1Parser<ASN1BitString> {

        public Parser(ASN1Decoder decoder) {
            super(decoder);
        }

        @Override
        public ASN1BitString parse(ASN1Tag<ASN1BitString> asn1Tag, byte[] value) {
            if (asn1Tag.isConstructed()) {
                ASN1InputStream stream = new ASN1InputStream(decoder, value);
                try {
                    while(stream.available() > 0) {
                        ASN1Tag subTag = stream.readTag();
                        Checks.checkState(subTag.getTag() == asn1Tag.getTag(), "Expected an ASN.1 BIT STRING as Constructed object, got: %s", subTag);
                        int i = stream.readLength();
                        byte[] subValue = stream.readValue(i);
                    }
                    return null;
                } catch (IOException e) {
                    throw new ASN1ParseException(e, "Unable to parse Constructed ASN.1 BIT STRING");
                }
            } else {
                byte unusedBits = value[0];
                byte[] bits = Arrays.copyOfRange(value, 1, value.length);
                return new ASN1BitString(asn1Tag, bits, unusedBits);
            }
        }
    }
}
