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
package org.apache.commons.compress.archivers.sevenz;

import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Random;
import java.util.zip.CRC32;

import javax.crypto.Cipher;

import org.apache.commons.compress.AbstractTestCase;
import org.apache.commons.compress.MemoryLimitException;
import org.apache.commons.compress.PasswordRequiredException;
import org.apache.commons.compress.utils.IOUtils;
import org.apache.commons.compress.utils.MultiReadOnlySeekableByteChannel;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.junit.Test;

public class SevenZFileTest extends AbstractTestCase {
    private static final String TEST2_CONTENT = "<?xml version = '1.0'?>\r\n<!DOCTYPE"
        + " connections>\r\n<meinxml>\r\n\t<leer />\r\n</meinxml>\n";

    // https://issues.apache.org/jira/browse/COMPRESS-320
    @Test
    public void testRandomlySkippingEntries() throws Exception {
        // Read sequential reference.
        final Map<String, byte[]> entriesByName = new HashMap<>();
        SevenZFile archive = new SevenZFile(getFile("COMPRESS-320/Copy.7z"));
        SevenZArchiveEntry entry;
        while ((entry = archive.getNextEntry()) != null) {
            if (entry.hasStream()) {
                entriesByName.put(entry.getName(), readFully(archive));
            }
        }
        archive.close();

        final String[] variants = {
            "BZip2-solid.7z",
            "BZip2.7z",
            "Copy-solid.7z",
            "Copy.7z",
            "Deflate-solid.7z",
            "Deflate.7z",
            "LZMA-solid.7z",
            "LZMA.7z",
            "LZMA2-solid.7z",
            "LZMA2.7z",
            // TODO: unsupported compression method.
            // "PPMd-solid.7z",
            // "PPMd.7z",
        };

        // TODO: use randomizedtesting for predictable, but different, randomness.
        final Random rnd = new Random(0xdeadbeef);
        for (final String fileName : variants) {
            archive = new SevenZFile(getFile("COMPRESS-320/" + fileName));

            while ((entry = archive.getNextEntry()) != null) {
                // Sometimes skip reading entries.
                if (rnd.nextBoolean()) {
                    continue;
                }

                if (entry.hasStream()) {
                    assertTrue(entriesByName.containsKey(entry.getName()));
                    final byte [] content = readFully(archive);
                    assertTrue("Content mismatch on: " + fileName + "!" + entry.getName(),
                               Arrays.equals(content, entriesByName.get(entry.getName())));
                }
            }

            archive.close();
        }
    }

    private byte[] readFully(final SevenZFile archive) throws IOException {
        final byte [] buf = new byte [1024];
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (int len = 0; (len = archive.read(buf)) > 0;) {
            baos.write(buf, 0, len);
        }
        return baos.toByteArray();
    }

    @Test
    public void testAllEmptyFilesArchive() throws Exception {
        try (SevenZFile archive = new SevenZFile(getFile("7z-empty-mhc-off.7z"))) {
            assertNotNull(archive.getNextEntry());
        }
    }

    @Test
    public void testHelloWorldHeaderCompressionOffCopy() throws Exception {
        checkHelloWorld("7z-hello-mhc-off-copy.7z");
    }

    @Test
    public void testHelloWorldHeaderCompressionOffLZMA2() throws Exception {
        checkHelloWorld("7z-hello-mhc-off-lzma2.7z");
    }

    @Test
    public void test7zUnarchive() throws Exception {
        test7zUnarchive(getFile("bla.7z"), SevenZMethod.LZMA);
    }

    @Test
    public void test7zDeflateUnarchive() throws Exception {
        test7zUnarchive(getFile("bla.deflate.7z"), SevenZMethod.DEFLATE);
    }

    @Test
    public void test7zDeflate64Unarchive() throws Exception {
        test7zUnarchive(getFile("bla.deflate64.7z"), SevenZMethod.DEFLATE64);
    }

    @Test
    public void test7zDecryptUnarchive() throws Exception {
        if (isStrongCryptoAvailable()) {
            test7zUnarchive(getFile("bla.encrypted.7z"), SevenZMethod.LZMA, // stack LZMA + AES
                            "foo".getBytes("UTF-16LE"));
        }
    }

    @Test
    public void test7zDecryptUnarchiveUsingCharArrayPassword() throws Exception {
        if (isStrongCryptoAvailable()) {
            test7zUnarchive(getFile("bla.encrypted.7z"), SevenZMethod.LZMA, // stack LZMA + AES
                            "foo".toCharArray());
        }
    }

    private void test7zUnarchive(final File f, final SevenZMethod m) throws Exception {
        test7zUnarchive(f, m, (char[]) null);
    }

    @Test
    public void testEncryptedArchiveRequiresPassword() throws Exception {
        try {
            new SevenZFile(getFile("bla.encrypted.7z")).close();
            fail("shouldn't decrypt without a password");
        } catch (final PasswordRequiredException ex) {
            final String msg = ex.getMessage();
            assertTrue("Should start with whining about being unable to decrypt",
                       msg.startsWith("Cannot read encrypted content from "));
            assertTrue("Should finish the sentence properly",
                       msg.endsWith(" without a password."));
            assertTrue("Should contain archive's name",
                       msg.contains("bla.encrypted.7z"));
        }
    }

    /**
     * @see "https://issues.apache.org/jira/browse/COMPRESS-256"
     */
    @Test
    public void testCompressedHeaderWithNonDefaultDictionarySize() throws Exception {
        try (SevenZFile sevenZFile = new SevenZFile(getFile("COMPRESS-256.7z"))) {
            int count = 0;
            while (sevenZFile.getNextEntry() != null) {
                count++;
            }
            assertEquals(446, count);
        }
    }

    @Test
    public void testSignatureCheck() {
        assertTrue(SevenZFile.matches(SevenZFile.sevenZSignature,
                                      SevenZFile.sevenZSignature.length));
        assertTrue(SevenZFile.matches(SevenZFile.sevenZSignature,
                                      SevenZFile.sevenZSignature.length + 1));
        assertFalse(SevenZFile.matches(SevenZFile.sevenZSignature,
                                      SevenZFile.sevenZSignature.length - 1));
        assertFalse(SevenZFile.matches(new byte[] { 1, 2, 3, 4, 5, 6 }, 6));
        assertTrue(SevenZFile.matches(new byte[] { '7', 'z', (byte) 0xBC,
                                                   (byte) 0xAF, 0x27, 0x1C}, 6));
        assertFalse(SevenZFile.matches(new byte[] { '7', 'z', (byte) 0xBC,
                                                    (byte) 0xAF, 0x27, 0x1D}, 6));
    }

    @Test
    public void testReadingBackLZMA2DictSize() throws Exception {
        final File output = new File(dir, "lzma2-dictsize.7z");
        try (SevenZOutputFile outArchive = new SevenZOutputFile(output)) {
            outArchive.setContentMethods(Arrays.asList(new SevenZMethodConfiguration(SevenZMethod.LZMA2, 1 << 20)));
            final SevenZArchiveEntry entry = new SevenZArchiveEntry();
            entry.setName("foo.txt");
            outArchive.putArchiveEntry(entry);
            outArchive.write(new byte[] { 'A' });
            outArchive.closeArchiveEntry();
        }

        try (SevenZFile archive = new SevenZFile(output)) {
            final SevenZArchiveEntry entry = archive.getNextEntry();
            final SevenZMethodConfiguration m = entry.getContentMethods().iterator().next();
            assertEquals(SevenZMethod.LZMA2, m.getMethod());
            assertEquals(1 << 20, m.getOptions());
        }
    }

    @Test
    public void testReadingBackDeltaDistance() throws Exception {
        final File output = new File(dir, "delta-distance.7z");
        try (SevenZOutputFile outArchive = new SevenZOutputFile(output)) {
            outArchive.setContentMethods(Arrays.asList(new SevenZMethodConfiguration(SevenZMethod.DELTA_FILTER, 32),
                    new SevenZMethodConfiguration(SevenZMethod.LZMA2)));
            final SevenZArchiveEntry entry = new SevenZArchiveEntry();
            entry.setName("foo.txt");
            outArchive.putArchiveEntry(entry);
            outArchive.write(new byte[] { 'A' });
            outArchive.closeArchiveEntry();
        }

        try (SevenZFile archive = new SevenZFile(output)) {
            final SevenZArchiveEntry entry = archive.getNextEntry();
            final SevenZMethodConfiguration m = entry.getContentMethods().iterator().next();
            assertEquals(SevenZMethod.DELTA_FILTER, m.getMethod());
            assertEquals(32, m.getOptions());
        }
    }

    @Test
    public void getEntriesOfUnarchiveTest() throws IOException {
        try (SevenZFile sevenZFile = new SevenZFile(getFile("bla.7z"))) {
            final Iterable<SevenZArchiveEntry> entries = sevenZFile.getEntries();
            final Iterator<SevenZArchiveEntry> iter = entries.iterator();
            SevenZArchiveEntry entry = iter.next();
            assertEquals("test1.xml", entry.getName());
            entry = iter.next();
            assertEquals("test2.xml", entry.getName());
            assertFalse(iter.hasNext());
        }
    }

    @Test
    public void getEntriesOfUnarchiveInMemoryTest() throws IOException {
        byte[] data = null;
        try (FileInputStream fis = new FileInputStream(getFile("bla.7z"))) {
            data = IOUtils.toByteArray(fis);
        }
        try (SevenZFile sevenZFile = new SevenZFile(new SeekableInMemoryByteChannel(data))) {
            final Iterable<SevenZArchiveEntry> entries = sevenZFile.getEntries();
            final Iterator<SevenZArchiveEntry> iter = entries.iterator();
            SevenZArchiveEntry entry = iter.next();
            assertEquals("test1.xml", entry.getName());
            entry = iter.next();
            assertEquals("test2.xml", entry.getName());
            assertFalse(iter.hasNext());
        }
    }

    /**
     * @see "https://issues.apache.org/jira/browse/COMPRESS-348"
     */
    @Test
    public void readEntriesOfSize0() throws IOException {
        try (SevenZFile sevenZFile = new SevenZFile(getFile("COMPRESS-348.7z"))) {
            int entries = 0;
            SevenZArchiveEntry entry = sevenZFile.getNextEntry();
            while (entry != null) {
                entries++;
                final int b = sevenZFile.read();
                if ("2.txt".equals(entry.getName()) || "5.txt".equals(entry.getName())) {
                    assertEquals(-1, b);
                } else {
                    assertNotEquals(-1, b);
                }
                entry = sevenZFile.getNextEntry();
            }
            assertEquals(5, entries);
        }
    }

    @Test(expected = MemoryLimitException.class)
    public void limitExtractionMemory() throws IOException {
        try (SevenZFile sevenZFile = new SevenZFile(getFile("bla.7z"),
            SevenZFileOptions.builder().withMaxMemoryLimitInKb(1).build())) {
            // Do nothing. Exception should be thrown
        }
    }

    @Test
    public void test7zMultiVolumeUnarchive() throws Exception {
        try (SevenZFile sevenZFile = new SevenZFile(MultiReadOnlySeekableByteChannel
            .forFiles(getFile("bla-multi.7z.001"), getFile("bla-multi.7z.002")))) {
            test7zUnarchive(sevenZFile, SevenZMethod.LZMA2);
        }
    }

    @Test
    public void getDefaultNameWorksAsExpected() throws Exception {
        try (SevenZFile sevenZFile = new SevenZFile(getFile("bla.deflate64.7z"))) {
            assertEquals("bla.deflate64", sevenZFile.getDefaultName());
        }
        try (SevenZFile sevenZFile = new SevenZFile(Files.newByteChannel(getFile("bla.deflate64.7z").toPath()))) {
            assertNull(sevenZFile.getDefaultName());
        }
        try (SevenZFile sevenZFile = new SevenZFile(Files.newByteChannel(getFile("bla.deflate64.7z").toPath()), "foo")) {
            assertEquals("foo~", sevenZFile.getDefaultName());
        }
        try (SevenZFile sevenZFile = new SevenZFile(Files.newByteChannel(getFile("bla.deflate64.7z").toPath()), ".foo")) {
            assertEquals(".foo~", sevenZFile.getDefaultName());
        }
    }

    @Test
    public void noNameMeansNoNameByDefault() throws Exception {
        try (SevenZFile sevenZFile = new SevenZFile(getFile("bla-nonames.7z"))) {
            SevenZArchiveEntry ae = sevenZFile.getNextEntry();
            assertNotNull(ae);
            assertNull(ae.getName());
            ae = sevenZFile.getNextEntry();
            assertNotNull(ae);
            assertNull(ae.getName());
            assertNull(sevenZFile.getNextEntry());
        }
    }

    @Test
    public void noNameCanBeReplacedByDefaultName() throws Exception {
        try (SevenZFile sevenZFile = new SevenZFile(getFile("bla-nonames.7z"),
            SevenZFileOptions.builder().withUseDefaultNameForUnnamedEntries(true).build())) {
            SevenZArchiveEntry ae = sevenZFile.getNextEntry();
            assertNotNull(ae);
            assertEquals("bla-nonames", ae.getName());
            ae = sevenZFile.getNextEntry();
            assertNotNull(ae);
            assertEquals("bla-nonames", ae.getName());
            assertNull(sevenZFile.getNextEntry());
        }
    }

    @Test
    public void givenNameWinsOverDefaultName() throws Exception {
        try (SevenZFile sevenZFile = new SevenZFile(getFile("bla.7z"),
            SevenZFileOptions.builder().withUseDefaultNameForUnnamedEntries(true).build())) {
            SevenZArchiveEntry ae = sevenZFile.getNextEntry();
            assertNotNull(ae);
            assertEquals("test1.xml", ae.getName());
            ae = sevenZFile.getNextEntry();
            assertNotNull(ae);
            assertEquals("test2.xml", ae.getName());
            assertNull(sevenZFile.getNextEntry());
        }
    }

    /**
     * @see "https://issues.apache.org/jira/browse/COMPRESS-542"
     */
    @Test
    public void rejectsNextHeaderSizeBeyondEndOfArchive() throws IOException {
        final byte[] header = { NID.kHeader, NID.kEnd };
        assertCraftedArchiveIsRejected(craftArchive(0, Integer.MAX_VALUE, new byte[0], header),
            "nextHeaderSize is out of bounds");
    }

    @Test
    public void rejectsNextHeaderOffsetBeyondEndOfArchive() throws IOException {
        final byte[] header = { NID.kHeader, NID.kEnd };
        assertCraftedArchiveIsRejected(craftArchive(1L << 40, header.length, new byte[0], header),
            "nextHeaderOffset is out of bounds");
    }

    @Test
    public void rejectsArchivePropertyLargerThanHeader() throws IOException {
        final ByteArrayOutputStream header = new ByteArrayOutputStream();
        header.write(NID.kHeader);
        header.write(NID.kArchiveProperties);
        header.write(1);
        writeNumber(header, Integer.MAX_VALUE);
        header.write(NID.kEnd);
        header.write(NID.kEnd);
        assertCraftedArchiveIsRejected(craftArchive(header.toByteArray()), "invalid property size");
    }

    @Test
    public void rejectsHugeNumberOfPackStreams() throws IOException {
        final ByteArrayOutputStream header = new ByteArrayOutputStream();
        header.write(NID.kHeader);
        header.write(NID.kMainStreamsInfo);
        header.write(NID.kPackInfo);
        writeNumber(header, 0);
        writeNumber(header, Integer.MAX_VALUE);
        header.write(NID.kSize);
        writeNumber(header, 1000);
        header.write(NID.kEnd);
        header.write(NID.kEnd);
        header.write(NID.kEnd);
        assertCraftedArchiveIsRejected(craftArchive(header.toByteArray()), "packSize (1000) is out of range");
    }

    @Test
    public void rejectsPackStreamCrcsMissingFromHeader() throws IOException {
        // 4 * numPackStreams overflows an int
        final ByteArrayOutputStream header = new ByteArrayOutputStream();
        header.write(NID.kHeader);
        header.write(NID.kMainStreamsInfo);
        header.write(NID.kPackInfo);
        writeNumber(header, 0);
        writeNumber(header, 1 << 30);
        header.write(NID.kCRC);
        header.write(1);
        header.write(NID.kEnd);
        header.write(NID.kEnd);
        header.write(NID.kEnd);
        assertCraftedArchiveIsRejected(craftArchive(header.toByteArray()), "invalid number of CRCs in PackInfo");
    }

    @Test
    public void rejectsHugeNumberOfFolders() throws IOException {
        final ByteArrayOutputStream header = new ByteArrayOutputStream();
        header.write(NID.kHeader);
        header.write(NID.kMainStreamsInfo);
        header.write(NID.kUnpackInfo);
        header.write(NID.kFolder);
        writeNumber(header, Integer.MAX_VALUE);
        header.write(0);
        // first folder, no coders
        writeNumber(header, 0);
        header.write(NID.kEnd);
        header.write(NID.kEnd);
        assertCraftedArchiveIsRejected(craftArchive(header.toByteArray()), "Folder without coders");
    }

    @Test
    public void rejectsHugeNumberOfCoders() throws IOException {
        final ByteArrayOutputStream header = new ByteArrayOutputStream();
        writeFolderHeaderStart(header);
        writeNumber(header, Integer.MAX_VALUE);
        // more alternative methods
        header.write(0x80);
        header.write(NID.kEnd);
        assertCraftedArchiveIsRejected(craftArchive(header.toByteArray()), "Alternative methods are unsupported");
    }

    @Test
    public void rejectsCoderPropertiesLargerThanHeader() throws IOException {
        final ByteArrayOutputStream header = new ByteArrayOutputStream();
        writeFolderHeaderStart(header);
        writeNumber(header, 1);
        // id size 1, simple coder with attributes
        header.write(0x21);
        header.write(0x21);
        writeNumber(header, Integer.MAX_VALUE);
        header.write(NID.kEnd);
        assertCraftedArchiveIsRejected(craftArchive(header.toByteArray()), "invalid propertiesSize in folder");
    }

    @Test
    public void rejectsHugeNumberOfBindPairs() throws IOException {
        final ByteArrayOutputStream header = new ByteArrayOutputStream();
        writeFolderHeaderStart(header);
        writeNumber(header, 1);
        // id size 1, complex coder
        header.write(0x11);
        header.write(0);
        writeNumber(header, 1);
        writeNumber(header, Integer.MAX_VALUE);
        header.write(NID.kEnd);
        assertCraftedArchiveIsRejected(craftArchive(header.toByteArray()),
            "Total input streams can't be less than the number of bind pairs");
    }

    @Test
    public void rejectsHugeNumberOfPackedStreamsInFolder() throws IOException {
        final ByteArrayOutputStream header = new ByteArrayOutputStream();
        writeFolderHeaderStart(header);
        writeNumber(header, 1);
        // id size 1, complex coder
        header.write(0x11);
        header.write(0);
        writeNumber(header, Integer.MAX_VALUE);
        writeNumber(header, 1);
        writeNumber(header, Integer.MAX_VALUE);
        header.write(NID.kEnd);
        assertCraftedArchiveIsRejected(craftArchive(header.toByteArray()),
            "packedStreamIndex is bigger than number of totalInStreams");
    }

    @Test
    public void rejectsHugeNumberOfSubStreamsWithoutSizes() throws IOException {
        final ByteArrayOutputStream header = new ByteArrayOutputStream();
        header.write(NID.kHeader);
        header.write(NID.kMainStreamsInfo);
        writeSingleCopyFolderStreamsInfo(header, 0);
        header.write(NID.kSubStreamsInfo);
        header.write(NID.kNumUnpackStream);
        writeNumber(header, Integer.MAX_VALUE);
        header.write(NID.kEnd);
        header.write(NID.kEnd);
        header.write(NID.kEnd);
        assertCraftedArchiveIsRejected(craftArchive(header.toByteArray()),
            "missing unpack sizes for folder with 2147483647 substreams");
    }

    @Test
    public void rejectsHugeNumberOfFilesWithoutFolders() throws IOException {
        final ByteArrayOutputStream header = new ByteArrayOutputStream();
        header.write(NID.kHeader);
        header.write(NID.kFilesInfo);
        writeNumber(header, Integer.MAX_VALUE);
        header.write(NID.kEnd);
        header.write(NID.kEnd);
        assertCraftedArchiveIsRejected(craftArchive(header.toByteArray()), "archive with entries but no folders");
    }

    @Test
    public void rejectsMoreFilesThanSubStreams() throws IOException {
        final ByteArrayOutputStream header = new ByteArrayOutputStream();
        header.write(NID.kHeader);
        header.write(NID.kMainStreamsInfo);
        writeSingleCopyFolderStreamsInfo(header, 0);
        header.write(NID.kSubStreamsInfo);
        header.write(NID.kEnd);
        header.write(NID.kEnd);
        header.write(NID.kFilesInfo);
        writeNumber(header, Integer.MAX_VALUE);
        header.write(NID.kEnd);
        header.write(NID.kEnd);
        assertCraftedArchiveIsRejected(craftArchive(header.toByteArray()),
            "archive doesn't contain enough substreams for entries");
    }

    @Test
    public void rejectsFileNamesNotMatchingNumberOfFiles() throws IOException {
        final ByteArrayOutputStream header = new ByteArrayOutputStream();
        header.write(NID.kHeader);
        header.write(NID.kFilesInfo);
        writeNumber(header, Integer.MAX_VALUE);
        header.write(NID.kName);
        writeNumber(header, 5);
        header.write(0);
        header.write('a');
        header.write(0);
        header.write(0);
        header.write(0);
        header.write(NID.kEnd);
        header.write(NID.kEnd);
        assertCraftedArchiveIsRejected(craftArchive(header.toByteArray()),
            "Invalid number of file names (1 instead of 2147483647)");
    }

    @Test
    public void rejectsFileNamesLargerThanHeader() throws IOException {
        final ByteArrayOutputStream header = new ByteArrayOutputStream();
        header.write(NID.kHeader);
        header.write(NID.kFilesInfo);
        writeNumber(header, 1);
        header.write(NID.kName);
        writeNumber(header, Integer.MAX_VALUE);
        header.write(0);
        header.write('a');
        header.write(0);
        header.write(0);
        header.write(0);
        header.write(NID.kEnd);
        header.write(NID.kEnd);
        try (SevenZFile sevenZFile = new SevenZFile(new SeekableInMemoryByteChannel(craftArchive(header.toByteArray())))) {
            fail("Expected archive to be rejected");
        } catch (final IOException | BufferUnderflowException expected) {
            // the names are checked against the bytes actually present before allocating anything
        }
    }

    @Test
    public void rejectsEncodedHeaderWithHugeUnpackSize() throws IOException {
        final byte[] packedStream = "hello".getBytes("US-ASCII");
        final ByteArrayOutputStream header = new ByteArrayOutputStream();
        header.write(NID.kEncodedHeader);
        header.write(NID.kPackInfo);
        writeNumber(header, 0);
        writeNumber(header, 1);
        header.write(NID.kSize);
        writeNumber(header, packedStream.length);
        header.write(NID.kEnd);
        header.write(NID.kUnpackInfo);
        header.write(NID.kFolder);
        writeNumber(header, 1);
        header.write(0);
        // single COPY coder
        writeNumber(header, 1);
        header.write(0x01);
        header.write(0x00);
        header.write(NID.kCodersUnpackSize);
        writeNumber(header, Integer.MAX_VALUE);
        header.write(NID.kEnd);
        header.write(NID.kEnd);
        final byte[] headerBytes = header.toByteArray();
        assertCraftedArchiveIsRejected(craftArchive(packedStream.length, headerBytes.length, packedStream, headerBytes),
            "premature end of stream");
    }

    @Test
    public void rejectsSubStreamSizesExceedingFolderUnpackSize() throws IOException {
        final ByteArrayOutputStream header = new ByteArrayOutputStream();
        header.write(NID.kHeader);
        header.write(NID.kMainStreamsInfo);
        writeSingleCopyFolderStreamsInfo(header, 1);
        header.write(NID.kSubStreamsInfo);
        header.write(NID.kNumUnpackStream);
        writeNumber(header, 2);
        header.write(NID.kSize);
        writeNumber(header, 5);
        header.write(NID.kEnd);
        header.write(NID.kEnd);
        header.write(NID.kEnd);
        assertCraftedArchiveIsRejected(craftArchive(header.toByteArray()),
            "sum of unpack sizes of folder exceeds total unpack size");
    }

    @Test
    public void rejectsArchiveWhoseMetadataExceedsMemoryLimit() throws IOException {
        // 8192 entries without streams only take 1024 bytes of header
        // but need more than a MB once they are turned into SevenZArchiveEntry instances
        final int numberOfEntries = 8192;
        final ByteArrayOutputStream header = new ByteArrayOutputStream();
        header.write(NID.kHeader);
        header.write(NID.kFilesInfo);
        writeNumber(header, numberOfEntries);
        header.write(NID.kEmptyStream);
        writeNumber(header, numberOfEntries / 8);
        for (int i = 0; i < numberOfEntries / 8; i++) {
            header.write(0xff);
        }
        header.write(NID.kEnd);
        header.write(NID.kEnd);
        final byte[] archive = craftArchive(header.toByteArray());

        // the archive itself is fine and can be read without a memory limit
        try (SevenZFile sevenZFile = new SevenZFile(new SeekableInMemoryByteChannel(archive))) {
            int entries = 0;
            for (final SevenZArchiveEntry entry : sevenZFile.getEntries()) {
                assertFalse(entry.hasStream());
                entries++;
            }
            assertEquals(numberOfEntries, entries);
        }

        try (SevenZFile sevenZFile = new SevenZFile(new SeekableInMemoryByteChannel(archive),
            SevenZFileOptions.builder().withMaxMemoryLimitInKb(1024).build())) {
            fail("Expected MemoryLimitException");
        } catch (final MemoryLimitException expected) {
            assertEquals(1024, expected.getMemoryLimitInKb());
            assertTrue("Unexpected estimate: " + expected.getMemoryNeededInKb(),
                expected.getMemoryNeededInKb() > 1024);
        }
    }

    private static void assertCraftedArchiveIsRejected(final byte[] archive, final String expectedMessage) {
        try (SevenZFile sevenZFile = new SevenZFile(new SeekableInMemoryByteChannel(archive))) {
            fail("Expected IOException containing: " + expectedMessage);
        } catch (final IOException e) {
            assertTrue("Unexpected message: " + e.getMessage(), e.getMessage().contains(expectedMessage));
        }
    }

    private static void writeFolderHeaderStart(final ByteArrayOutputStream header) {
        header.write(NID.kHeader);
        header.write(NID.kMainStreamsInfo);
        header.write(NID.kUnpackInfo);
        header.write(NID.kFolder);
        writeNumber(header, 1);
        header.write(0);
    }

    private static void writeSingleCopyFolderStreamsInfo(final ByteArrayOutputStream header, final long unpackSize) {
        header.write(NID.kPackInfo);
        writeNumber(header, 0);
        writeNumber(header, 1);
        header.write(NID.kSize);
        writeNumber(header, 0);
        header.write(NID.kEnd);
        header.write(NID.kUnpackInfo);
        header.write(NID.kFolder);
        writeNumber(header, 1);
        header.write(0);
        writeNumber(header, 1);
        header.write(0x01);
        header.write(0x00);
        header.write(NID.kCodersUnpackSize);
        writeNumber(header, unpackSize);
        header.write(NID.kEnd);
    }

    private static byte[] craftArchive(final byte[] header) {
        return craftArchive(0, header.length, new byte[0], header);
    }

    private static byte[] craftArchive(final long nextHeaderOffset, final long nextHeaderSize,
                                       final byte[] packedStreams, final byte[] header) {
        final CRC32 crc = new CRC32();
        crc.update(header);
        final ByteBuffer startHeader = ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN);
        startHeader.putLong(nextHeaderOffset);
        startHeader.putLong(nextHeaderSize);
        startHeader.putInt((int) crc.getValue());
        crc.reset();
        crc.update(startHeader.array());
        final ByteBuffer archive = ByteBuffer.allocate(SevenZFile.SIGNATURE_HEADER_SIZE + packedStreams.length
            + header.length).order(ByteOrder.LITTLE_ENDIAN);
        archive.put(SevenZFile.sevenZSignature);
        archive.put((byte) 0);
        archive.put((byte) 4);
        archive.putInt((int) crc.getValue());
        archive.put(startHeader.array());
        archive.put(packedStreams);
        archive.put(header);
        return archive.array();
    }

    private static void writeNumber(final ByteArrayOutputStream out, long value) {
        int firstByte = 0;
        int mask = 0x80;
        int i;
        for (i = 0; i < 8; i++) {
            if (value < ((1L << ( 7  * (i + 1))))) {
                firstByte |= (value >>> (8 * i));
                break;
            }
            firstByte |= mask;
            mask >>>= 1;
        }
        out.write(firstByte);
        for (; i > 0; i--) {
            out.write((int) (0xff & value));
            value >>>= 8;
        }
    }

    private void test7zUnarchive(final File f, final SevenZMethod m, final byte[] password) throws Exception {
        try (SevenZFile sevenZFile = new SevenZFile(f, password)) {
            test7zUnarchive(sevenZFile, m);
        }
    }

    private void test7zUnarchive(final File f, final SevenZMethod m, final char[] password) throws Exception {
        try (SevenZFile sevenZFile = new SevenZFile(f, password)) {
            test7zUnarchive(sevenZFile, m);
        }
    }

    private void test7zUnarchive(SevenZFile sevenZFile, final SevenZMethod m) throws Exception {
        SevenZArchiveEntry entry = sevenZFile.getNextEntry();
        assertEquals("test1.xml", entry.getName());
        assertEquals(m, entry.getContentMethods().iterator().next().getMethod());
        entry = sevenZFile.getNextEntry();
        assertEquals("test2.xml", entry.getName());
        assertEquals(m, entry.getContentMethods().iterator().next().getMethod());
        final byte[] contents = new byte[(int) entry.getSize()];
        int off = 0;
        while ((off < contents.length)) {
            final int bytesRead = sevenZFile.read(contents, off, contents.length - off);
            assert (bytesRead >= 0);
            off += bytesRead;
        }
        assertEquals(TEST2_CONTENT, new String(contents, "UTF-8"));
        assertNull(sevenZFile.getNextEntry());
    }

    private void checkHelloWorld(final String filename) throws Exception {
        try (SevenZFile sevenZFile = new SevenZFile(getFile(filename))) {
            final SevenZArchiveEntry entry = sevenZFile.getNextEntry();
            assertEquals("Hello world.txt", entry.getName());
            final byte[] contents = new byte[(int) entry.getSize()];
            int off = 0;
            while ((off < contents.length)) {
                final int bytesRead = sevenZFile.read(contents, off, contents.length - off);
                assert (bytesRead >= 0);
                off += bytesRead;
            }
            assertEquals("Hello, world!\n", new String(contents, "UTF-8"));
            assertNull(sevenZFile.getNextEntry());
        }
    }

    private static boolean isStrongCryptoAvailable() throws NoSuchAlgorithmException {
        return Cipher.getMaxAllowedKeyLength("AES/ECB/PKCS5Padding") >= 256;
    }
}
