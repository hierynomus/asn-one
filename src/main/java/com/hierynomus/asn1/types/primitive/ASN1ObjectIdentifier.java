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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import com.hierynomus.asn1.ASN1OutputStream;
import com.hierynomus.asn1.ASN1ParseException;
import com.hierynomus.asn1.ASN1Parser;
import com.hierynomus.asn1.ASN1Serializer;
import com.hierynomus.asn1.encodingrules.ASN1Decoder;
import com.hierynomus.asn1.encodingrules.ASN1Encoder;
import com.hierynomus.asn1.types.ASN1Tag;

/**
 * ASN.1 OBJECT IDENTIFIER (UNIVERSAL 6), in dotted notation, e.g. {@code 1.2.840.113549}.
 * <p>
 * Encoded as in X.690 8.19: the first two arcs X.Y are combined into a single subidentifier {@code 40 * X + Y}, and
 * every subidentifier is encoded in base 128, most significant group first, with bit 8 set on all but the last octet.
 * Arcs can be arbitrarily large (e.g. UUID based {@code 2.25.*} identifiers).
 */
public class ASN1ObjectIdentifier extends ASN1PrimitiveValue<String> {
    // Canonical dotted notation: at least two arcs, no empty arcs, signs or leading zeros
    private static final Pattern DOTTED = Pattern.compile("(0|[1-9][0-9]*)(\\.(0|[1-9][0-9]*))+");
    private static final BigInteger FORTY = BigInteger.valueOf(40);
    private static final BigInteger EIGHTY = BigInteger.valueOf(80);

    private final String oid;

    /**
     * @param oid the object identifier in dotted notation
     * @throws IllegalArgumentException if the value is not a valid object identifier (X.680 32.3, X.690 8.19.4):
     * at least two arcs, the first being 0, 1 or 2, and the second being below 40 if the first is 0 or 1
     */
    public ASN1ObjectIdentifier(String oid) {
        super(ASN1Tag.OBJECT_IDENTIFIER);
        this.oid = checkValid(oid);
    }

    private ASN1ObjectIdentifier(byte[] valueBytes, String oid) {
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

    private static String checkValid(String oid) {
        if (oid == null || !DOTTED.matcher(oid).matches()) {
            throw new IllegalArgumentException("Not a valid ASN.1 OBJECT IDENTIFIER: '" + oid + "'");
        }
        String[] arcs = oid.split("\\.", 3);
        BigInteger first = new BigInteger(arcs[0]);
        BigInteger second = new BigInteger(arcs[1]);
        if (first.compareTo(BigInteger.valueOf(2)) > 0) {
            throw new IllegalArgumentException("The first arc of an ASN.1 OBJECT IDENTIFIER must be 0, 1 or 2: '" + oid + "'");
        }
        if (first.compareTo(BigInteger.valueOf(2)) < 0 && second.compareTo(FORTY) >= 0) {
            throw new IllegalArgumentException("The second arc of an ASN.1 OBJECT IDENTIFIER must be below 40 under 0 and 1: '" + oid + "'");
        }
        return oid;
    }

    public static class Parser extends ASN1Parser<ASN1ObjectIdentifier> {
        public Parser(ASN1Decoder decoder) {
            super(decoder);
        }

        @Override
        public ASN1ObjectIdentifier parse(ASN1Tag<ASN1ObjectIdentifier> asn1Tag, byte[] value) {
            if (value.length == 0) {
                throw new ASN1ParseException("An ASN.1 OBJECT IDENTIFIER should have at least a one byte value");
            }
            List<BigInteger> subidentifiers = new ArrayList<>();
            int i = 0;
            while (i < value.length) {
                if ((value[i] & 0xff) == 0x80) {
                    // X.690 8.19.2: a subidentifier shall be encoded in the fewest possible octets
                    throw new ASN1ParseException("Non-minimal subidentifier encoding in ASN.1 OBJECT IDENTIFIER at offset %s", i);
                }
                BigInteger subidentifier = BigInteger.ZERO;
                int b;
                do {
                    if (i >= value.length) {
                        throw new ASN1ParseException("Truncated subidentifier in ASN.1 OBJECT IDENTIFIER");
                    }
                    b = value[i++] & 0xff;
                    subidentifier = subidentifier.shiftLeft(7).or(BigInteger.valueOf(b & 0x7f));
                } while ((b & 0x80) != 0);
                subidentifiers.add(subidentifier);
            }

            // X.690 8.19.4: the first subidentifier combines the first two arcs as 40 * X + Y, where Y < 40 if X < 2
            StringBuilder b = new StringBuilder();
            BigInteger first = subidentifiers.get(0);
            if (first.compareTo(FORTY) < 0) {
                b.append("0.").append(first);
            } else if (first.compareTo(EIGHTY) < 0) {
                b.append("1.").append(first.subtract(FORTY));
            } else {
                b.append("2.").append(first.subtract(EIGHTY));
            }
            for (int j = 1; j < subidentifiers.size(); j++) {
                b.append('.').append(subidentifiers.get(j));
            }
            return new ASN1ObjectIdentifier(value, b.toString());
        }
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
            String[] arcs = asn1Object.oid.split("\\.");
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            writeSubidentifier(baos, new BigInteger(arcs[0]).multiply(FORTY).add(new BigInteger(arcs[1])));
            for (int i = 2; i < arcs.length; i++) {
                writeSubidentifier(baos, new BigInteger(arcs[i]));
            }
            asn1Object.valueBytes = baos.toByteArray();
        }

        /**
         * Base 128, most significant group first, bit 8 set on all but the last octet (X.690 8.19.2).
         */
        private static void writeSubidentifier(ByteArrayOutputStream baos, BigInteger subidentifier) {
            int groups = Math.max(1, (subidentifier.bitLength() + 6) / 7);
            for (int i = groups - 1; i >= 0; i--) {
                int group = subidentifier.shiftRight(i * 7).intValue() & 0x7f;
                baos.write(i > 0 ? group | 0x80 : group);
            }
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
