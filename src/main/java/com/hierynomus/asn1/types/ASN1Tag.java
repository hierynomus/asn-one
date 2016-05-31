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
package com.hierynomus.asn1.types;

import com.hierynomus.asn1.ASN1ParseException;
import com.hierynomus.asn1.ASN1Parser;
import com.hierynomus.asn1.encodingrules.ASN1Decoder;
import com.hierynomus.asn1.types.constructed.ASN1Sequence;
import com.hierynomus.asn1.types.constructed.ASN1Set;
import com.hierynomus.asn1.types.constructed.ASN1TaggedObject;
import com.hierynomus.asn1.types.primitive.*;
import com.hierynomus.asn1.types.string.ASN1BitString;
import com.hierynomus.asn1.types.string.ASN1OctetString;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static com.hierynomus.asn1.types.ASN1Tag.ASN1TagClass.Universal;
import static java.lang.String.format;
import static java.util.EnumSet.of;

public abstract class ASN1Tag<T extends ASN1Object> {
    public enum ASN1TagClass {
        Universal(0),
        Application(0x40),
        ContextSpecific(0x80),
        Private(0xc0);

        private int value;

        ASN1TagClass(int value) {
            this.value = value;
        }

        public static ASN1TagClass parseClass(byte tagByte) {
            int classValue = (tagByte & 0xc0);
            for (ASN1TagClass asn1TagClass : values()) {
                if (asn1TagClass.value == classValue) {
                    return asn1TagClass;
                }
            }
            throw new IllegalStateException("Could not parse ASN.1 Tag Class (should be impossible)");
        }
    }

    public enum ASN1Encoding {
        Primitive(0x0),
        Constructed(0x20);

        private int value;

        ASN1Encoding(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }

        public static ASN1Encoding parseEncoding(byte tagByte) {
            if ((tagByte & 0x20) == 0) {
                return Primitive;
            } else {
                return Constructed;
            }
        }
    }

    private static Map<Integer, ASN1Tag<?>> tags = new HashMap<>();

    public static final ASN1Tag<ASN1Boolean> BOOLEAN = new ASN1Tag<ASN1Boolean>(Universal, 0x01, ASN1Encoding.Primitive) {
        @Override
        public ASN1Parser<ASN1Boolean> newParser(ASN1Decoder decoder) {
            return new ASN1Boolean.Parser(decoder);
        }
    };
    public static final ASN1Tag<ASN1Integer> INTEGER = new ASN1Tag<ASN1Integer>(Universal, 0x02, ASN1Encoding.Primitive) {
        @Override
        public ASN1Parser<ASN1Integer> newParser(ASN1Decoder decoder) {
            return new ASN1Integer.Parser(decoder);
        }
    };
    public static final ASN1Tag<ASN1BitString> BIT_STRING = new ASN1Tag<ASN1BitString>(Universal, 0x03, ASN1Encoding.Primitive, of(ASN1Encoding.Primitive, ASN1Encoding.Constructed)) {
        @Override
        public ASN1Parser<ASN1BitString> newParser(ASN1Decoder decoder) {
            return new ASN1BitString.Parser(decoder);
        }
    };
    public static final ASN1Tag<?> OCTET_STRING = new ASN1Tag(Universal, 0x04, of(ASN1Encoding.Primitive, ASN1Encoding.Constructed)) {
        @Override
        public ASN1Parser<?> newParser(ASN1Decoder decoder) {
            return new ASN1OctetString.Parser(decoder);
        }
    };
    public static final ASN1Tag<ASN1Null> NULL = new ASN1Tag<ASN1Null>(Universal, 0x05, ASN1Encoding.Primitive) {
        @Override
        public ASN1Parser<ASN1Null> newParser(ASN1Decoder decoder) {
            return new ASN1Null.Parser(decoder);
        }
    };
    public static final ASN1Tag<ASN1ObjectIdentifier> OBJECT_IDENTIFIER = new ASN1Tag<ASN1ObjectIdentifier>(Universal, 0x06, ASN1Encoding.Primitive) {
        @Override
        public ASN1Parser<ASN1ObjectIdentifier> newParser(ASN1Decoder decoder) {
            return new ASN1ObjectIdentifier.Parser(decoder);
        }
    };
    public static final ASN1Tag<ASN1Enumerated> ENUMERATED = new ASN1Tag<ASN1Enumerated>(Universal, 0x0A, ASN1Encoding.Primitive) {
        @Override
        public ASN1Parser<ASN1Enumerated> newParser(ASN1Decoder decoder) {
            return new ASN1Enumerated.Parser(decoder);
        }
    };
    public static final ASN1Tag<ASN1Set> SET = new ASN1Tag<ASN1Set>(Universal, 0x11, ASN1Encoding.Constructed) {
        @Override
        public ASN1Parser<ASN1Set> newParser(ASN1Decoder decoder) {
            return new ASN1Set.Parser(decoder);
        }
    };
    public static final ASN1Tag<ASN1Sequence> SEQUENCE = new ASN1Tag<ASN1Sequence>(Universal, 0x10, ASN1Encoding.Constructed) {
        @Override
        public ASN1Parser<ASN1Sequence> newParser(ASN1Decoder decoder) {
            return new ASN1Sequence.Parser(decoder);
        }
    };

    private final ASN1TagClass asn1TagClass;
    private final int tag;
    private final EnumSet<ASN1Encoding> supportedEncodings;
    private final ASN1Encoding asn1Encoding;

    public ASN1Tag(ASN1TagClass asn1TagClass, int tag, EnumSet<ASN1Encoding> supportedEncodings) {
        this(asn1TagClass, tag, supportedEncodings.contains(ASN1Encoding.Primitive) ? ASN1Encoding.Primitive : ASN1Encoding.Constructed, supportedEncodings);
    }

    public ASN1Tag(ASN1TagClass asn1TagClass, int tag, ASN1Encoding asn1Encoding) {
        this(asn1TagClass,tag, asn1Encoding, of(asn1Encoding));
    }

    private ASN1Tag(ASN1TagClass asn1TagClass, int tag, ASN1Encoding asn1Encoding, EnumSet<ASN1Encoding> supportedEncodings) {
        this.asn1TagClass = asn1TagClass;
        this.tag = tag;
        this.supportedEncodings = supportedEncodings;
        this.asn1Encoding = asn1Encoding;
        tags.put(tag, this);
    }

    public ASN1Tag<T> asEncoded(final ASN1Encoding asn1Encoding) {
        if (!supportedEncodings.contains(asn1Encoding)) {
            throw new IllegalArgumentException(format("The ASN.1 tag %s does not support encoding as %s", this, asn1Encoding));
        }
        return new ASN1Tag<T>(this.asn1TagClass, this.tag, asn1Encoding, this.supportedEncodings) {
            @Override
            public ASN1Parser<T> newParser(ASN1Decoder decoder) {
                return ASN1Tag.this.newParser(decoder);
            }
        };
    }

    public static ASN1Tag forTag(ASN1TagClass asn1TagClass, int tag) {
        switch (asn1TagClass) {
            case Universal:
                for (ASN1Tag asn1Tag : tags.values()) {
                    if (asn1Tag.tag == tag && asn1TagClass == asn1Tag.asn1TagClass) {
                        return asn1Tag;
                    }
                }
                break;
            case Application:
            case ContextSpecific:
            case Private:
                return new ASN1Tag(asn1TagClass, tag, of(ASN1Encoding.Primitive, ASN1Encoding.Constructed)) {
                    @Override
                    public ASN1Parser<?> newParser(ASN1Decoder decoder) {
                        return new ASN1TaggedObject.Parser(decoder, this);
                    }
                };
        }
        throw new ASN1ParseException(format("Unknown ASN.1 tag '%s:%s' found", asn1TagClass, tag));
    }

    public int getTag() {
        return tag;
    }

    public ASN1TagClass getAsn1TagClass() {
        return asn1TagClass;
    }

    public EnumSet<ASN1Encoding> getSupportedEncodings() {
        return EnumSet.copyOf(supportedEncodings);
    }

    public ASN1Encoding getAsn1Encoding() {
        return asn1Encoding;
    }

    public boolean isConstructed() {
        return asn1Encoding == ASN1Encoding.Constructed;
    }

    public abstract ASN1Parser<T> newParser(ASN1Decoder decoder);

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ASN1Tag asn1Tag = (ASN1Tag) o;
        return getTag() == asn1Tag.getTag() &&
            asn1TagClass == asn1Tag.asn1TagClass &&
            asn1Encoding == asn1Tag.asn1Encoding;
    }

    @Override
    public int hashCode() {
        return Objects.hash(asn1TagClass, getTag(), asn1Encoding);
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("ASN1Tag[");
        sb.append(asn1TagClass);
        sb.append(",").append(asn1Encoding);
        sb.append(",").append(tag);
        sb.append(']');
        return sb.toString();
    }
}
