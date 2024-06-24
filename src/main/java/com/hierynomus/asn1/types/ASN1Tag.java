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
import com.hierynomus.asn1.ASN1Serializer;
import com.hierynomus.asn1.encodingrules.ASN1Decoder;
import com.hierynomus.asn1.encodingrules.ASN1Encoder;
import com.hierynomus.asn1.types.constructed.ASN1Sequence;
import com.hierynomus.asn1.types.constructed.ASN1Set;
import com.hierynomus.asn1.types.constructed.ASN1TaggedObject;
import com.hierynomus.asn1.types.primitive.*;
import com.hierynomus.asn1.types.string.*;

import java.util.*;

import static com.hierynomus.asn1.types.ASN1TagClass.UNIVERSAL;
import static java.lang.String.format;
import static java.util.EnumSet.of;

public abstract class ASN1Tag<T extends ASN1Object> {
    private static Map<Integer, ASN1Tag<?>> tags = new HashMap<>();

    public static final ASN1Tag<ASN1Boolean> BOOLEAN = new ASN1Tag<ASN1Boolean>(UNIVERSAL, 0x01, ASN1Encoding.PRIMITIVE) {
        @Override
        public ASN1Parser<ASN1Boolean> newParser(ASN1Decoder decoder) {
            return new ASN1Boolean.Parser(decoder);
        }

        @Override
        public ASN1Serializer<ASN1Boolean> newSerializer(ASN1Encoder encoder) {
            return new ASN1Boolean.Serializer(encoder);
        }
    };
    public static final ASN1Tag<ASN1Integer> INTEGER = new ASN1Tag<ASN1Integer>(UNIVERSAL, 0x02, ASN1Encoding.PRIMITIVE) {
        @Override
        public ASN1Parser<ASN1Integer> newParser(ASN1Decoder decoder) {
            return new ASN1Integer.Parser(decoder);
        }

        @Override
        public ASN1Serializer<ASN1Integer> newSerializer(ASN1Encoder encoder) {
            return new ASN1Integer.Serializer(encoder);
        }
    };
    public static final ASN1Tag<ASN1BitString> BIT_STRING = new ASN1Tag<ASN1BitString>(UNIVERSAL, 0x03, ASN1Encoding.PRIMITIVE, of(ASN1Encoding.PRIMITIVE, ASN1Encoding.CONSTRUCTED)) {
        @Override
        public ASN1Parser<ASN1BitString> newParser(ASN1Decoder decoder) {
            return new ASN1BitString.Parser(decoder);
        }

        @Override
        public ASN1Serializer<ASN1BitString> newSerializer(ASN1Encoder encoder) {
            return new ASN1BitString.Serializer(encoder);
        }
    };
    public static final ASN1Tag<?> OCTET_STRING = new ASN1Tag(UNIVERSAL, 0x04, of(ASN1Encoding.PRIMITIVE, ASN1Encoding.CONSTRUCTED)) {
        @Override
        public ASN1Parser<?> newParser(ASN1Decoder decoder) {
            return new ASN1OctetString.Parser(decoder);
        }
        @Override
        public ASN1Serializer newSerializer(ASN1Encoder encoder) {
            return new ASN1OctetString.Serializer(encoder);
        }
    };
    public static final ASN1Tag<?> UTF8_STRING = new ASN1Tag(UNIVERSAL, 0x0C, of(ASN1Encoding.PRIMITIVE, ASN1Encoding.CONSTRUCTED)) {
        @Override
        public ASN1Parser<?> newParser(ASN1Decoder decoder) {
            return new ASN1UTF8String.Parser(decoder);
        }
        @Override
        public ASN1Serializer newSerializer(ASN1Encoder encoder) {
            return new ASN1UTF8String.Serializer(encoder);
        }
    };
    public static final ASN1Tag<?> PRINTABLE_STRING = new ASN1Tag(UNIVERSAL, 0x13, of(ASN1Encoding.PRIMITIVE, ASN1Encoding.CONSTRUCTED)) {
        @Override
        public ASN1Parser<?> newParser(ASN1Decoder decoder) {
            return new ASN1PrintableString.Parser(decoder);
        }
        @Override
        public ASN1Serializer newSerializer(ASN1Encoder encoder) {
            return new ASN1PrintableString.Serializer(encoder);
        }
    };
    public static final ASN1Tag<?> NUMERIC_STRING = new ASN1Tag(UNIVERSAL, 0x12, of(ASN1Encoding.PRIMITIVE, ASN1Encoding.CONSTRUCTED)) {
        @Override
        public ASN1Parser<?> newParser(ASN1Decoder decoder) {
            return new ASN1NumericString.Parser(decoder);
        }
        @Override
        public ASN1Serializer newSerializer(ASN1Encoder encoder) {
            return new ASN1NumericString.Serializer(encoder);
        }
    };
    public static final ASN1Tag<ASN1Null> NULL = new ASN1Tag<ASN1Null>(UNIVERSAL, 0x05, ASN1Encoding.PRIMITIVE) {
        @Override
        public ASN1Parser<ASN1Null> newParser(ASN1Decoder decoder) {
            return new ASN1Null.Parser(decoder);
        }

        @Override
        public ASN1Serializer<ASN1Null> newSerializer(ASN1Encoder encoder) {
            return new ASN1Null.Serializer(encoder);
        }
    };
    public static final ASN1Tag<ASN1ObjectIdentifier> OBJECT_IDENTIFIER = new ASN1Tag<ASN1ObjectIdentifier>(UNIVERSAL, 0x06, ASN1Encoding.PRIMITIVE) {
        @Override
        public ASN1Parser<ASN1ObjectIdentifier> newParser(ASN1Decoder decoder) {
            return new ASN1ObjectIdentifier.Parser(decoder);
        }

        @Override
        public ASN1Serializer<ASN1ObjectIdentifier> newSerializer(ASN1Encoder encoder) {
            return new ASN1ObjectIdentifier.Serializer(encoder);
        }
    };
    public static final ASN1Tag<ASN1Enumerated> ENUMERATED = new ASN1Tag<ASN1Enumerated>(UNIVERSAL, 0x0A, ASN1Encoding.PRIMITIVE) {
        @Override
        public ASN1Parser<ASN1Enumerated> newParser(ASN1Decoder decoder) {
            return new ASN1Enumerated.Parser(decoder);
        }

        @Override
        public ASN1Serializer<ASN1Enumerated> newSerializer(ASN1Encoder encoder) {
            return new ASN1Enumerated.Serializer(encoder);
        }
    };
    public static final ASN1Tag<ASN1Set> SET = new ASN1Tag<ASN1Set>(UNIVERSAL, 0x11, ASN1Encoding.CONSTRUCTED) {
        @Override
        public ASN1Parser<ASN1Set> newParser(ASN1Decoder decoder) {
            return new ASN1Set.Parser(decoder);
        }

        @Override
        public ASN1Serializer<ASN1Set> newSerializer(ASN1Encoder encoder) {
            return new ASN1Set.Serializer(encoder);
        }
    };
    public static final ASN1Tag<ASN1Sequence> SEQUENCE = new ASN1Tag<ASN1Sequence>(UNIVERSAL, 0x10, ASN1Encoding.CONSTRUCTED) {
        @Override
        public ASN1Parser<ASN1Sequence> newParser(ASN1Decoder decoder) {
            return new ASN1Sequence.Parser(decoder);
        }

        @Override
        public ASN1Serializer<ASN1Sequence> newSerializer(ASN1Encoder encoder) {
            return new ASN1Sequence.Serializer(encoder);
        }    };

    static {
        tags.put(BOOLEAN.getTag(), BOOLEAN);
        tags.put(INTEGER.getTag(), INTEGER);
        tags.put(BIT_STRING.getTag(), BIT_STRING);
        tags.put(OCTET_STRING.getTag(), OCTET_STRING);
        tags.put(UTF8_STRING.getTag(), UTF8_STRING);
        tags.put(PRINTABLE_STRING.getTag(), PRINTABLE_STRING);
        tags.put(NUMERIC_STRING.getTag(), NUMERIC_STRING);
        tags.put(NULL.getTag(), NULL);
        tags.put(OBJECT_IDENTIFIER.getTag(), OBJECT_IDENTIFIER);
        tags.put(ENUMERATED.getTag(), ENUMERATED);
        tags.put(SET.getTag(), SET);
        tags.put(SEQUENCE.getTag(), SEQUENCE);
    }

    private final ASN1TagClass asn1TagClass;
    private final int tag;
    private final Set<ASN1Encoding> supportedEncodings;
    private final ASN1Encoding asn1Encoding;

    public ASN1Tag(ASN1TagClass asn1TagClass, int tag, Set<ASN1Encoding> supportedEncodings) {
        this(asn1TagClass, tag, supportedEncodings.contains(ASN1Encoding.PRIMITIVE) ? ASN1Encoding.PRIMITIVE : ASN1Encoding.CONSTRUCTED, supportedEncodings);
    }

    public ASN1Tag(ASN1TagClass asn1TagClass, int tag, ASN1Encoding asn1Encoding) {
        this(asn1TagClass,tag, asn1Encoding, of(asn1Encoding));
    }

    private ASN1Tag(ASN1TagClass asn1TagClass, int tag, ASN1Encoding asn1Encoding, Set<ASN1Encoding> supportedEncodings) {
        this.asn1TagClass = asn1TagClass;
        this.tag = tag;
        this.supportedEncodings = supportedEncodings;
        this.asn1Encoding = asn1Encoding;
    }

    public ASN1Tag<T> constructed() {
        return asEncoded(ASN1Encoding.CONSTRUCTED);
    }

    public ASN1Tag<T> primitive() {
        return asEncoded(ASN1Encoding.PRIMITIVE);
    }

    public ASN1Tag<T> asEncoded(final ASN1Encoding asn1Encoding) {
        if (this.asn1Encoding == asn1Encoding) {
            return this;
        }
        if (!supportedEncodings.contains(asn1Encoding)) {
            throw new IllegalArgumentException(format("The ASN.1 tag %s does not support encoding as %s", this, asn1Encoding));
        }
        return new ASN1Tag<T>(this.asn1TagClass, this.tag, asn1Encoding, this.supportedEncodings) {
            @Override
            public ASN1Parser<T> newParser(ASN1Decoder decoder) {
                return ASN1Tag.this.newParser(decoder);
            }

            @Override
            public ASN1Serializer<T> newSerializer(ASN1Encoder encoder) {
                return ASN1Tag.this.newSerializer(encoder);
            }
        };
    }

    public static ASN1Tag application(int tag) {
        return forTag(ASN1TagClass.APPLICATION, tag);
    }

    public static ASN1Tag contextSpecific(int tag) {
        return forTag(ASN1TagClass.CONTEXT_SPECIFIC, tag);
    }

    public static ASN1Tag forTag(ASN1TagClass asn1TagClass, int tag) {
        switch (asn1TagClass) {
            case UNIVERSAL:
                for (ASN1Tag asn1Tag : tags.values()) {
                    if (asn1Tag.tag == tag && asn1TagClass == asn1Tag.asn1TagClass) {
                        return asn1Tag;
                    }
                }
                break;
            case APPLICATION:
            case CONTEXT_SPECIFIC:
            case PRIVATE:
                return new ASN1Tag(asn1TagClass, tag, of(ASN1Encoding.PRIMITIVE, ASN1Encoding.CONSTRUCTED)) {
                    @Override
                    public ASN1Parser<?> newParser(ASN1Decoder decoder) {
                        return new ASN1TaggedObject.Parser(decoder);
                    }

                    @Override
                    public ASN1Serializer newSerializer(ASN1Encoder encoder) {
                        return new ASN1TaggedObject.Serializer(encoder);
                    }
                };
            default:
                break;
        }
        throw new ASN1ParseException(format("Unknown ASN.1 tag '%s:%s' found (%s)", asn1TagClass, tag, ASN1Tag.tags));
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
        return asn1Encoding == ASN1Encoding.CONSTRUCTED;
    }

    public abstract ASN1Parser<T> newParser(ASN1Decoder decoder);

    public abstract ASN1Serializer<T> newSerializer(ASN1Encoder encoder);

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
