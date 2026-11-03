/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.commons.compress.archivers.sevenz;

import java.io.IOException;
import java.util.Iterator;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;


/**
 * Unit tests for class {@link Folder}.
 *
 * @date 26.06.2017
 * @see Folder
 **/
public class FolderTest {


    @Test
    public void testGetUnpackSizeForCoderOne() {

        Folder folder = new Folder();
        Coder[] coderArray = new Coder[5];
        Coder coder = new Coder();
        folder.coders = coderArray;

        assertEquals(0L, folder.getUnpackSizeForCoder(coder));

    }


    @Test
    public void testGetUnpackSizeOne() {

        Folder folder = new Folder();
        folder.totalOutputStreams = 266L;
        BindPair[] bindPairArray = new BindPair[1];
        BindPair bindPair = new BindPair();
        bindPairArray[0] = bindPair;
        folder.bindPairs = bindPairArray;
        folder.totalOutputStreams = 1L;

        assertEquals(0L, folder.getUnpackSize());

    }


    @Test
    public void testGetUnpackSizeTwo() {

        Folder folder = new Folder();

        assertEquals(0L, folder.getUnpackSize());

    }


    @Test
    public void testFindBindPairForInStream() {

        Folder folder = new Folder();
        BindPair[] bindPairArray = new BindPair[1];
        BindPair bindPair = new BindPair();
        bindPairArray[0] = bindPair;
        folder.bindPairs = bindPairArray;

        assertEquals(0, folder.findBindPairForInStream(0));

    }


    @Test
    public void testGetOrderedCodersFollowsBindPairs() throws Exception {

        Coder first = new Coder();
        Coder second = new Coder();
        Folder folder = folder(new Coder[] { first, second }, new long[] { 0 },
            bindPair(1, 0));

        Iterator<Coder> coders = folder.getOrderedCoders().iterator();
        assertSame(first, coders.next());
        assertSame(second, coders.next());
        assertFalse(coders.hasNext());

    }


    @Test(timeout = 10000)
    public void testGetOrderedCodersRejectsCoderBoundToItself() throws Exception {

        Folder folder = folder(new Coder[] { new Coder() }, new long[] { 0 },
            bindPair(0, 0));

        assertRejectsCoderChain(folder);

    }


    @Test(timeout = 10000)
    public void testGetOrderedCodersRejectsCyclicCoderChain() throws Exception {

        Folder folder = folder(new Coder[] { new Coder(), new Coder() }, new long[] { 0 },
            bindPair(1, 0), bindPair(0, 1));

        assertRejectsCoderChain(folder);

    }


    @Test(timeout = 10000)
    public void testGetOrderedCodersRejectsChainEnteringLoop() throws Exception {

        Folder folder = folder(new Coder[] { new Coder(), new Coder(), new Coder() }, new long[] { 0 },
            bindPair(1, 0), bindPair(1, 1));

        assertRejectsCoderChain(folder);

    }


    @Test
    public void testGetOrderedCodersStopsAtOutOfRangeCoderIndex() throws Exception {

        Coder only = new Coder();
        Folder folder = folder(new Coder[] { only }, new long[] { 0 },
            bindPair(1, 0));

        Iterator<Coder> coders = folder.getOrderedCoders().iterator();
        assertSame(only, coders.next());
        assertFalse(coders.hasNext());

        folder.packedStreams = new long[] { 5 };
        assertFalse(folder.getOrderedCoders().iterator().hasNext());

    }


    @Test
    public void testGetOrderedCodersWithoutPackedStreamsIsEmpty() throws Exception {

        Folder folder = folder(new Coder[] { new Coder() }, new long[0]);

        assertFalse(folder.getOrderedCoders().iterator().hasNext());

    }


    private static Folder folder(final Coder[] coders, final long[] packedStreams,
                                 final BindPair... bindPairs) {
        Folder folder = new Folder();
        folder.coders = coders;
        folder.packedStreams = packedStreams;
        folder.bindPairs = bindPairs;
        return folder;
    }


    private static BindPair bindPair(final long inIndex, final long outIndex) {
        BindPair bindPair = new BindPair();
        bindPair.inIndex = inIndex;
        bindPair.outIndex = outIndex;
        return bindPair;
    }


    private static void assertRejectsCoderChain(final Folder folder) {
        try {
            folder.getOrderedCoders();
            fail("expected an IOException for a coder used more than once in the coder chain");
        } catch (IOException ex) {
            assertTrue(ex.getMessage(), ex.getMessage().contains("same coder more than once"));
        }
    }


}