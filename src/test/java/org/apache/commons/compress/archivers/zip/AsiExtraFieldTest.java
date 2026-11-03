/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.apache.commons.compress.archivers.zip;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.zip.CRC32;
import java.util.zip.ZipException;

import org.apache.commons.compress.utils.IOUtils;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.junit.Test;

/**
 * JUnit testcases for org.apache.commons.compress.archivers.zip.AsiExtraField.
 *
 */
public class AsiExtraFieldTest implements UnixStat {

    /**
     * Test file mode magic.
     */
    @Test
    public void testModes() {
        final AsiExtraField a = new AsiExtraField();
        a.setMode(0123);
        assertEquals("plain file", 0100123, a.getMode());
        a.setDirectory(true);
        assertEquals("directory", 040123, a.getMode());
        a.setLinkedFile("test");
        assertEquals("symbolic link", 0120123, a.getMode());
    }

    /**
     * Test content.
     */
    @Test
    public void testContent() {
        final AsiExtraField a = new AsiExtraField();
        a.setMode(0123);
        a.setUserId(5);
        a.setGroupId(6);
        byte[] b = a.getLocalFileDataData();

        // CRC manually calculated, sorry
        byte[] expect = {(byte)0xC6, 0x02, 0x78, (byte)0xB6, // CRC
                         0123, (byte)0x80,                   // mode
                         0, 0, 0, 0,                         // link length
                         5, 0, 6, 0};                        // uid, gid
        assertEquals("no link", expect.length, b.length);
        for (int i=0; i<expect.length; i++) {
            assertEquals("no link, byte "+i, expect[i], b[i]);
        }

        a.setLinkedFile("test");
        expect = new byte[] {0x75, (byte)0x8E, 0x41, (byte)0xFD, // CRC
                             0123, (byte)0xA0,                   // mode
                             4, 0, 0, 0,                         // link length
                             5, 0, 6, 0,                         // uid, gid
                             (byte)'t', (byte)'e', (byte)'s', (byte)'t'};
        b = a.getLocalFileDataData();
        assertEquals("no link", expect.length, b.length);
        for (int i=0; i<expect.length; i++) {
            assertEquals("no link, byte "+i, expect[i], b[i]);
        }

    }

    /**
     * Test reparse
     */
    @Test
    public void testReparse() throws Exception {
        // CRC manually calculated, sorry
        byte[] data = {(byte)0xC6, 0x02, 0x78, (byte)0xB6, // CRC
                       0123, (byte)0x80,                   // mode
                       0, 0, 0, 0,                         // link length
                       5, 0, 6, 0};                        // uid, gid
        AsiExtraField a = new AsiExtraField();
        a.parseFromLocalFileData(data, 0, data.length);
        assertEquals("length plain file", data.length,
                     a.getLocalFileDataLength().getValue());
        assertTrue("plain file, no link", !a.isLink());
        assertTrue("plain file, no dir", !a.isDirectory());
        assertEquals("mode plain file", FILE_FLAG | 0123, a.getMode());
        assertEquals("uid plain file", 5, a.getUserId());
        assertEquals("gid plain file", 6, a.getGroupId());

        data = new byte[] {0x75, (byte)0x8E, 0x41, (byte)0xFD, // CRC
                           0123, (byte)0xA0,                   // mode
                           4, 0, 0, 0,                         // link length
                           5, 0, 6, 0,                         // uid, gid
                           (byte)'t', (byte)'e', (byte)'s', (byte)'t'};
        a = new AsiExtraField();
        a.parseFromLocalFileData(data, 0, data.length);
        assertEquals("length link", data.length,
                     a.getLocalFileDataLength().getValue());
        assertTrue("link, is link", a.isLink());
        assertTrue("link, no dir", !a.isDirectory());
        assertEquals("mode link", LINK_FLAG | 0123, a.getMode());
        assertEquals("uid link", 5, a.getUserId());
        assertEquals("gid link", 6, a.getGroupId());
        assertEquals("test", a.getLinkedFile());

        data = new byte[] {(byte)0x8E, 0x01, (byte)0xBF, (byte)0x0E, // CRC
                           0123, (byte)0x40,                         // mode
                           0, 0, 0, 0,                               // link
                           5, 0, 6, 0};                          // uid, gid
        a = new AsiExtraField();
        a.parseFromLocalFileData(data, 0, data.length);
        assertEquals("length dir", data.length,
                     a.getLocalFileDataLength().getValue());
        assertTrue("dir, no link", !a.isLink());
        assertTrue("dir, is dir", a.isDirectory());
        assertEquals("mode dir", DIR_FLAG | 0123, a.getMode());
        assertEquals("uid dir", 5, a.getUserId());
        assertEquals("gid dir", 6, a.getGroupId());

        data = new byte[] {0, 0, 0, 0,                           // bad CRC
                           0123, (byte)0x40,                     // mode
                           0, 0, 0, 0,                           // link
                           5, 0, 6, 0};                          // uid, gid
        a = new AsiExtraField();
        try {
            a.parseFromLocalFileData(data, 0, data.length);
            fail("should raise bad CRC exception");
        } catch (final Exception e) {
            assertEquals("Bad CRC checksum, expected 0 instead of ebf018e",
                         e.getMessage());
        }
    }

    /**
     * A link length that points far beyond the available data must
     * not make the parser allocate a huge array (CVE-2021-36090).
     */
    @Test
    public void testReparseRejectsHugeLinkLength() throws Exception {
        final byte[] data = createAsiData(0x7FFFFFFFL, new byte[0]);
        final AsiExtraField a = new AsiExtraField();
        try {
            a.parseFromLocalFileData(data, 0, data.length);
            fail("should raise bad link length exception");
        } catch (final ZipException e) {
            assertEquals("Bad symbolic link name length 2147483647 in ASI extra field",
                         e.getMessage());
        }
    }

    @Test
    public void testReparseRejectsNegativeLinkLength() throws Exception {
        final byte[] data = createAsiData(0xFFFFFFFFL, new byte[0]);
        final AsiExtraField a = new AsiExtraField();
        try {
            a.parseFromLocalFileData(data, 0, data.length);
            fail("should raise bad link length exception");
        } catch (final ZipException e) {
            assertEquals("Bad symbolic link name length -1 in ASI extra field",
                         e.getMessage());
        }
    }

    @Test
    public void testReparseRejectsLinkLengthExceedingData() throws Exception {
        final byte[] data = createAsiData(5, new byte[] {'t', 'e', 's', 't'});
        final AsiExtraField a = new AsiExtraField();
        try {
            a.parseFromCentralDirectoryData(data, 0, data.length);
            fail("should raise bad link length exception");
        } catch (final ZipException e) {
            assertEquals("Bad symbolic link name length 5 in ASI extra field",
                         e.getMessage());
        }
    }

    @Test
    public void testReparseAcceptsLinkLengthMatchingData() throws Exception {
        final byte[] data = createAsiData(4, new byte[] {'t', 'e', 's', 't'});
        final AsiExtraField a = new AsiExtraField();
        a.parseFromLocalFileData(data, 0, data.length);
        assertTrue(a.isLink());
        assertEquals("test", a.getLinkedFile());
        assertEquals(5, a.getUserId());
        assertEquals(6, a.getGroupId());
    }

    @Test
    public void testExtraFieldUtilsRejectsHugeLinkLength() throws Exception {
        final byte[] asi = createAsiData(0x7FFFFFFFL, new byte[0]);
        final byte[] extra = new byte[4 + asi.length];
        System.arraycopy(new AsiExtraField().getHeaderId().getBytes(), 0, extra, 0, 2);
        System.arraycopy(ZipShort.getBytes(asi.length), 0, extra, 2, 2);
        System.arraycopy(asi, 0, extra, 4, asi.length);
        try {
            ExtraFieldUtils.parse(extra);
            fail("should raise bad link length exception");
        } catch (final ZipException e) {
            assertEquals("Bad symbolic link name length 2147483647 in ASI extra field",
                         e.getMessage());
        }
    }

    /**
     * Reading an archive containing an ASI extra field with a crafted
     * link length must fail gracefully rather than with an
     * OutOfMemoryError (CVE-2021-36090).
     *
     * <p>With the default {@link ZipArchiveEntry.ExtraFieldParsingMode#BEST_EFFORT}
     * parsing mode the broken field is kept as an {@link
     * UnrecognizedExtraField} and the entry stays readable, parsing
     * the field strictly fails with a ZipException.</p>
     */
    @Test
    public void testReadingArchiveWithHugeLinkLengthFailsGracefully() throws Exception {
        final byte[] archive = createArchiveWithAsiData(createAsiData(0x7FFFFFFFL, new byte[0]));

        try (ZipArchiveInputStream in = new ZipArchiveInputStream(new ByteArrayInputStream(archive))) {
            final ZipArchiveEntry entry = in.getNextZipEntry();
            assertNotNull(entry);
            assertBadLinkLength(entry);
            assertArrayEquals(new byte[] {'a', 'b', 'c'}, IOUtils.toByteArray(in));
        }

        try (ZipFile zf = new ZipFile(new SeekableInMemoryByteChannel(archive))) {
            final ZipArchiveEntry entry = zf.getEntry("test.txt");
            assertNotNull(entry);
            assertBadLinkLength(entry);
            try (InputStream in = zf.getInputStream(entry)) {
                assertArrayEquals(new byte[] {'a', 'b', 'c'}, IOUtils.toByteArray(in));
            }
        }
    }

    private static void assertBadLinkLength(final ZipArchiveEntry entry) {
        final ZipExtraField asi = entry.getExtraField(new AsiExtraField().getHeaderId());
        assertTrue("expected UnrecognizedExtraField but got " + asi,
                   asi instanceof UnrecognizedExtraField);
        try {
            entry.getExtraFields(ZipArchiveEntry.ExtraFieldParsingMode.STRICT_FOR_KNOW_EXTRA_FIELDS);
            fail("should raise bad link length exception");
        } catch (final ZipException e) {
            assertEquals("Bad symbolic link name length 2147483647 in ASI extra field",
                         e.getMessage());
        }
    }

    private static byte[] createArchiveWithAsiData(final byte[] asiData) throws Exception {
        final UnrecognizedExtraField asi = new UnrecognizedExtraField();
        asi.setHeaderId(new AsiExtraField().getHeaderId());
        asi.setLocalFileDataData(asiData);
        asi.setCentralDirectoryData(asiData);

        final ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ZipArchiveOutputStream zos = new ZipArchiveOutputStream(bos)) {
            final ZipArchiveEntry entry = new ZipArchiveEntry("test.txt");
            entry.addExtraField(asi);
            zos.putArchiveEntry(entry);
            zos.write(new byte[] {'a', 'b', 'c'});
            zos.closeArchiveEntry();
        }
        return bos.toByteArray();
    }

    /**
     * Creates the data of an ASI extra field (including a valid CRC)
     * that claims the given link length.
     */
    private static byte[] createAsiData(final long linkLength, final byte[] link) {
        final byte[] tmp = new byte[10 + link.length];
        System.arraycopy(ZipShort.getBytes(LINK_FLAG | 0123), 0, tmp, 0, 2); // mode
        System.arraycopy(ZipLong.getBytes(linkLength), 0, tmp, 2, 4);        // link length
        System.arraycopy(ZipShort.getBytes(5), 0, tmp, 6, 2);                // uid
        System.arraycopy(ZipShort.getBytes(6), 0, tmp, 8, 2);                // gid
        System.arraycopy(link, 0, tmp, 10, link.length);
        final CRC32 crc = new CRC32();
        crc.update(tmp);
        final byte[] data = new byte[4 + tmp.length];
        System.arraycopy(ZipLong.getBytes(crc.getValue()), 0, data, 0, 4);
        System.arraycopy(tmp, 0, data, 4, tmp.length);
        return data;
    }

    @Test
    public void testClone() {
        final AsiExtraField s1 = new AsiExtraField();
        s1.setUserId(42);
        s1.setGroupId(12);
        s1.setLinkedFile("foo");
        s1.setMode(0644);
        s1.setDirectory(true);
        final AsiExtraField s2 = (AsiExtraField) s1.clone();
        assertNotSame(s1, s2);
        assertEquals(s1.getUserId(), s2.getUserId());
        assertEquals(s1.getGroupId(), s2.getGroupId());
        assertEquals(s1.getLinkedFile(), s2.getLinkedFile());
        assertEquals(s1.getMode(), s2.getMode());
        assertEquals(s1.isDirectory(), s2.isDirectory());
    }
}
