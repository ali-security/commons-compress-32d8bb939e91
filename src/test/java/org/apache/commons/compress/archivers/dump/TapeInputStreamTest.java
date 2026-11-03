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
package org.apache.commons.compress.archivers.dump;

import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class TapeInputStreamTest {

    @Parameters(name = "recsPerBlock={0}")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {
                new Object[] { -1 },
                new Object[] { 0 },
                // RECORD_SIZE * (1 << 22) overflows to a block size of 0
                new Object[] { 1 << 22 },
                new Object[] { Integer.MAX_VALUE / 1000 },
                new Object[] { Integer.MAX_VALUE },
            });
    }

    private final int recsPerBlock;

    public TapeInputStreamTest(final int recsPerBlock) {
        this.recsPerBlock = recsPerBlock;
    }

    @Test
    public void testResetBlockSizeWithInvalidValues() throws Exception {
        try (TapeInputStream tapeInputStream = new TapeInputStream(new ByteArrayInputStream(new byte[1]))) {
            try {
                tapeInputStream.resetBlockSize(recsPerBlock, true);
                fail("expected an IOException for recsPerBlock=" + recsPerBlock);
            } catch (final IOException ex) {
                // expected
            }
        }
    }
}
