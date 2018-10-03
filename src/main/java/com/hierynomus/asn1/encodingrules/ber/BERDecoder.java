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
package com.hierynomus.asn1.encodingrules.ber;

import com.hierynomus.asn1.ASN1ParseException;
import com.hierynomus.asn1.encodingrules.ASN1Decoder;
import com.hierynomus.asn1.types.ASN1Encoding;
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.ASN1Tag;
import com.hierynomus.asn1.types.ASN1TagClass;

import java.io.IOException;
import java.io.InputStream;

public class BERDecoder implements ASN1Decoder {

    @Override
    public ASN1Tag<? extends ASN1Object> readTag(InputStream is) {
        try {
            int tagByte = is.read();
            ASN1TagClass asn1TagClass = ASN1TagClass.parseClass((byte) tagByte);
            ASN1Encoding asn1Encoding = ASN1Encoding.parseEncoding((byte) tagByte);
            int tag = tagByte & 0x1f;
            if (tag <= 0x1e) {
                return ASN1Tag.forTag(asn1TagClass, tag).asEncoded(asn1Encoding);
            } else {
                int iTag = 0;
                int read = is.read();
                do {
                    iTag <<= 7;
                    iTag |= (read & 0x7f);
                    read = is.read();
                } while ((read & 0x80) > 0);
                return ASN1Tag.forTag(asn1TagClass, iTag).asEncoded(asn1Encoding);
            }
        } catch (IOException ioe) {
            throw new ASN1ParseException("Unable to parse ASN.1 tag", ioe);
        }
    }

    @Override
    public int readLength(InputStream is) {
        try {
            int firstByte = is.read();
            if (firstByte < 0x7f) {
                return firstByte;
            }
            int nrBytes = firstByte & 0x7f;
            int longLength = 0;
            for (int i = 0; i < nrBytes; i++) {
                longLength = longLength << 8;
                longLength += is.read();
            }

            if (longLength == 0) {
                throw new ASN1ParseException("The indefinite length form is not (yet) supported!");
            }

            return longLength;
        } catch (IOException ioe) {
            throw new ASN1ParseException("Unable to read the length of the ASN.1 object.", ioe);
        }
    }

    @Override
    public byte[] readValue(int length, InputStream is) {
        try {
            byte[] value = new byte[length];
            int count = 0;
            int read = 0;
            while (count < length && ((read = is.read(value, count, length - count)) != -1)) {
                count += read;
            }
            return value;
        } catch (IOException ioe) {
            throw new ASN1ParseException("Unable to read the value of the ASN.1 object", ioe);
        }
    }
}
