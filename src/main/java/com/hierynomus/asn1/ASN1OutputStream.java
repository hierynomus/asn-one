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
package com.hierynomus.asn1;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import com.hierynomus.asn1.encodingrules.ASN1Encoder;
import com.hierynomus.asn1.types.ASN1Object;
import com.hierynomus.asn1.types.ASN1Tag;

public class ASN1OutputStream extends FilterOutputStream {

    private final ASN1Encoder encoder;

    /**
     * Creates an output stream filter built on top of the specified
     * underlying output stream.
     *
     * @param out the underlying output stream to be assigned to
     *            the field <tt>this.out</tt> for later use, or
     *            <code>null</code> if this instance is to be
     *            created without an underlying stream.
     */
    public ASN1OutputStream(final ASN1Encoder encoder, final OutputStream out) {
        super(out);
        this.encoder = encoder;
    }

    public void writeObject(ASN1Object asn1Object) throws IOException {
        ASN1Tag tag = asn1Object.getTag();
        writeTag(tag);
        ASN1Serializer asn1Serializer = asn1Object.getTag().newSerializer(encoder);
        writeLength(asn1Serializer.serializedLength(asn1Object));

        //noinspection unchecked
        asn1Serializer.serialize(asn1Object, this);
    }

    private void writeLength(final int length) throws IOException {
        if (length < 0x7f) {
            write(length);
        } else {
            int nrBytes = lengthBytes(length);
            write(0x80 | nrBytes);
            for (; nrBytes > 0; nrBytes --) {
                write(length >> ((nrBytes - 1) * 8));
            }
        }
    }

    private int lengthBytes(final int length) {
        int l = length;
        int nrBytes = 1;
        while (l > 255) {
            nrBytes++;
            l >>= 8;
        }
        return nrBytes;
    }

    private void writeTag(final ASN1Tag tag) throws IOException {
        byte tagByte = (byte) (tag.getAsn1TagClass().getValue() | tag.getAsn1Encoding().getValue() | tag.getTag());
        write(tagByte);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        out.write(b, off, len);
    }
}
