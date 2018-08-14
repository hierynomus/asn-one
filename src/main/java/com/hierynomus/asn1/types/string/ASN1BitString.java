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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.BitSet;
import com.hierynomus.asn1.*;
import com.hierynomus.asn1.encodingrules.ASN1Decoder;
import com.hierynomus.asn1.encodingrules.ASN1Encoder;
import com.hierynomus.asn1.types.ASN1Tag;
import com.hierynomus.asn1.util.Checks;

public class ASN1BitString extends ASN1String<boolean[]> {

    private int unusedBits;
    private boolean[] bits;

    private ASN1BitString(ASN1Tag<ASN1BitString> tag, byte[] bytes, int unusedBits) {
        super(tag, bytes);
        this.unusedBits = unusedBits;
        this.bits = constructBits();
    }

    public ASN1BitString(byte[] bytes, int unusedBits) {
        this(ASN1Tag.BIT_STRING, bytes, unusedBits);
    }

    public ASN1BitString(boolean[] bits) {
        super(ASN1Tag.BIT_STRING, constructBytes(bits));
        this.bits = bits;
        this.unusedBits = 8 - (bits.length % 8);
    }

    /**
     * Constructor for ASN.1 BIT STRING.
     *
     * The passed in BitSet will be treated as having no unused bits.
     * @param bitSet
     */
    public ASN1BitString(BitSet bitSet) {
        this(ASN1Tag.BIT_STRING, constructBytes(bitSet), 0);
    }

    private static byte[] constructBytes(boolean[] bits) {
        byte[] bytes = new byte[bits.length / 8 + (bits.length % 8 > 0 ? 1 : 0)];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = 0;
            for (int j = 0; j < 8; j++) {
                boolean v = i * 8 + j < bits.length && bits[i * 8 + j];
                bytes[i] += ((v ? 1 : 0) << (8 - j - 1));
            }
        }
        return bytes;
    }

    private static byte[] constructBytes(BitSet bitSet) {
        byte[] bytes = new byte[bitSet.length() / 8 + 1];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = 0;
            for (int j = 0; j < 8; j++) {
                bytes[i] += ((bitSet.get(i * 8 + j) ? 1 : 0) << (8 - j - 1));
            }
        }
        return bytes;
    }

    private boolean[] constructBits() {
        boolean[] bits = new boolean[length()];
        for (int i = 0; i < bits.length; i++) {
            bits[i] = isSet(i);

        }
        return bits;
    }

    @Override
    public boolean[] getValue() {
        return Arrays.copyOf(this.bits, this.bits.length);
    }

    @Override
    protected String valueString() {
        return Arrays.toString(bits);
    }

    /**
     * Check whether bit 'x' is set in the ASN.1 BIT_STRING
     *
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
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    int unusedBits = 0;
                    while (stream.available() > 0) {
                        ASN1Tag subTag = stream.readTag();
                        Checks.checkState(subTag.getTag() == asn1Tag.getTag(), "Expected an ASN.1 BIT STRING as Constructed object, got: %s", subTag);
                        int i = stream.readLength();
                        byte[] subValue = stream.readValue(i);
                        baos.write(subValue, 1, subValue.length - 1);
                        if (stream.available() <= 0) {
                            // Last ASN.1 BitString
                            unusedBits = subValue[0];
                        }
                    }
                    return new ASN1BitString(asn1Tag, baos.toByteArray(), unusedBits);
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

    public static class Serializer extends ASN1Serializer<ASN1BitString> {
        public Serializer(final ASN1Encoder encoder) {
            super(encoder);
        }

        @Override
        public int serializedLength(final ASN1BitString asn1Object) {
            return asn1Object.valueBytes.length + 1;
        }

        @Override
        public void serialize(final ASN1BitString asn1Object, final ASN1OutputStream stream) throws IOException {
            stream.write(asn1Object.unusedBits);
            stream.write(asn1Object.valueBytes);
        }
    }

}
