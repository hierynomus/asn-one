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
import com.hierynomus.asn1.types.constructed.ASN1Sequence;
import com.hierynomus.asn1.types.constructed.ASN1Set;
import com.hierynomus.asn1.types.constructed.ASN1TaggedObject;
import com.hierynomus.asn1.types.primitive.*;
import com.hierynomus.asn1.types.string.ASN1BitString;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static com.hierynomus.asn1.types.ASN1TagClass.Universal;
import static java.lang.String.format;
import static java.util.EnumSet.of;

public abstract class ASN1Tag<T extends ASN1Object> {
    private static Map<Integer, ASN1Tag<?>> tags = new HashMap<>();

    public static final ASN1Tag<ASN1Boolean> BOOLEAN = new ASN1Tag<ASN1Boolean>(Universal, 0x01, ASN1Encoding.Primitive) {
        @Override
        public ASN1Parser<ASN1Boolean> newParser() {
            return new ASN1Boolean.Parser();
        }

        @Override
        public ASN1Serializer<ASN1Boolean> newSerializer() {
            return new ASN1Boolean.Serializer();
        }
    };
    public static final ASN1Tag<ASN1Integer> INTEGER = new ASN1Tag<ASN1Integer>(Universal, 0x02, ASN1Encoding.Primitive) {
        @Override
        public ASN1Parser<ASN1Integer> newParser() {
            return new ASN1Integer.Parser();
        }

        @Override
        public ASN1Serializer<ASN1Integer> newSerializer() {
            return new ASN1Integer.Serializer();
        }
    };
    public static final ASN1Tag<ASN1BitString> BIT_STRING = new ASN1Tag<ASN1BitString>(Universal, 0x03, ASN1Encoding.Primitive) {
        @Override
        public ASN1Parser<ASN1BitString> newParser() {
            return new ASN1BitString.Parser();
        }

        @Override
        public ASN1Serializer<ASN1BitString> newSerializer() {
            return new ASN1BitString.Serializer();
        }
    };
    public static final ASN1Tag<?> OCTET_STRING = new ASN1Tag(Universal, 0x04, of(ASN1Encoding.Primitive, ASN1Encoding.Constructed)) {
        @Override
        public ASN1Parser<?> newParser() {
            return null; // TODO
        }

        @Override
        public ASN1Serializer newSerializer() {
            return null; // TODO
        }
    };
    public static final ASN1Tag<ASN1Null> NULL = new ASN1Tag<ASN1Null>(Universal, 0x05, ASN1Encoding.Primitive) {
        @Override
        public ASN1Parser<ASN1Null> newParser() {
            return new ASN1Null.Parser();
        }

        @Override
        public ASN1Serializer<ASN1Null> newSerializer() {
            return new ASN1Null.Serializer();
        }
    };
    public static final ASN1Tag<ASN1ObjectIdentifier> OBJECT_IDENTIFIER = new ASN1Tag<ASN1ObjectIdentifier>(Universal, 0x06, ASN1Encoding.Primitive) {
        @Override
        public ASN1Parser<ASN1ObjectIdentifier> newParser() {
            return new ASN1ObjectIdentifier.Parser();
        }

        @Override
        public ASN1Serializer<ASN1ObjectIdentifier> newSerializer() {
            return new ASN1ObjectIdentifier.Serializer();
        }
    };
    public static final ASN1Tag<ASN1Enumerated> ENUMERATED = new ASN1Tag<ASN1Enumerated>(Universal, 0x0A, ASN1Encoding.Primitive) {
        @Override
        public ASN1Parser<ASN1Enumerated> newParser() {
            return new ASN1Enumerated.Parser();
        }

        @Override
        public ASN1Serializer<ASN1Enumerated> newSerializer() {
            return new ASN1Enumerated.Serializer();
        }
    };
    public static final ASN1Tag<ASN1Set> SET = new ASN1Tag<ASN1Set>(Universal, 0x11, ASN1Encoding.Constructed) {
        @Override
        public ASN1Parser<ASN1Set> newParser() {
            return new ASN1Set.Parser();
        }

        @Override
        public ASN1Serializer<ASN1Set> newSerializer() {
            return new ASN1Set.Serializer();
        }
    };
    public static final ASN1Tag<ASN1Sequence> SEQUENCE = new ASN1Tag<ASN1Sequence>(Universal, 0x10, ASN1Encoding.Constructed) {
        @Override
        public ASN1Parser<ASN1Sequence> newParser() {
            return new ASN1Sequence.Parser();
        }

        @Override
        public ASN1Serializer<ASN1Sequence> newSerializer() {
            return new ASN1Sequence.Serializer();
        }    };

    static {
        tags.put(BOOLEAN.getTag(), BOOLEAN);
        tags.put(INTEGER.getTag(), INTEGER);
        tags.put(BIT_STRING.getTag(), BIT_STRING);
        tags.put(OCTET_STRING.getTag(), OCTET_STRING);
        tags.put(NULL.getTag(), NULL);
        tags.put(OBJECT_IDENTIFIER.getTag(), OBJECT_IDENTIFIER);
        tags.put(ENUMERATED.getTag(), ENUMERATED);
        tags.put(SET.getTag(), SET);
        tags.put(SEQUENCE.getTag(), SEQUENCE);
    }

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
    }

    public ASN1Tag asEncoded(ASN1Encoding asn1Encoding) {
        if (!supportedEncodings.contains(asn1Encoding)) {
            throw new IllegalArgumentException(format("The ASN.1 tag %s does not support encoding as %s", this, asn1Encoding));
        }
        return new ASN1Tag(this.asn1TagClass, this.tag, asn1Encoding, this.supportedEncodings) {
            @Override
            public ASN1Parser newParser() {
                return ASN1Tag.this.newParser();
            }

            @Override
            public ASN1Serializer newSerializer() {
                return ASN1Tag.this.newSerializer();
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
                    public ASN1Parser<?> newParser() {
                        return new ASN1TaggedObject.Parser(this);
                    }

                    @Override
                    public ASN1Serializer newSerializer() {
                        return new ASN1TaggedObject.Serializer(this);
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

    public abstract ASN1Parser<T> newParser();

    public abstract ASN1Serializer<T> newSerializer();

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
