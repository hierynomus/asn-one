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
package com.hierynomus.asn1.types.constructed;

import com.hierynomus.asn1.ASN1InputStream;
import com.hierynomus.asn1.ASN1ParseException;
import com.hierynomus.asn1.ASN1Parser;
import com.hierynomus.asn1.encodingrules.ASN1Decoder;
import com.hierynomus.asn1.types.ASN1Constructed;
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.ASN1Tag;

import java.util.Iterator;

public class ASN1TaggedObject extends ASN1Object<ASN1Object> implements ASN1Constructed {
    private byte[] bytes;
    private ASN1Decoder decoder;

    protected ASN1TaggedObject(ASN1Tag tag, byte[] bytes, ASN1Decoder decoder) {
        super(tag);
        this.bytes = bytes;
        this.decoder = decoder;
    }

    @Override
    public ASN1Object getValue() {
        return getObject();
    }

    /**
     * Returns the identifying tag number of this ASN.1 Tagged Object.
     * @return the tag number.
     */
    public int getTagNo() {
        return tag.getTag();
    }

    @Override
    public Iterator<ASN1Object> iterator() {
        return getObject(ASN1Tag.SEQUENCE).iterator();
    }

    public static class Parser extends ASN1Parser<ASN1TaggedObject> {
        private ASN1Tag tag;

        public Parser(ASN1Decoder decoder, ASN1Tag tag) {
            super(decoder);
            this.tag = tag;
        }

        public Parser(ASN1Decoder decoder) {
            super(decoder);
        }

        @Override
        public ASN1TaggedObject parse(ASN1Tag<ASN1TaggedObject> asn1Tag, byte[] value) {
            return new ASN1TaggedObject(tag, value, decoder);
        }
    }

    public ASN1Object getObject() {
        try {
            return new ASN1InputStream(decoder, bytes).readObject();
        } catch (ASN1ParseException e) {
            throw new ASN1ParseException(e, "Unable to parse the explicit Tagged Object with %s, it might be implicit", tag);
        }
    }

    public <T extends ASN1Object> T getObject(ASN1Tag<T> tag) {
        return tag.newParser(decoder).parse(tag, bytes);
    }
}
