/**
 * Copyright (C) 2011-2017 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.mbed.coap.packet;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;

/**
 * This class implements RFC7959 (Block-Wise Transfers in the Constrained Application Protocol)
 *
 * @author szymon
 */
public final class BlockOption implements Serializable {

    private final int blockNr;
    private final boolean more;
    private final BlockSize blockSize;

    public BlockOption(int blockNr, BlockSize blockSize, boolean more) {
        this.blockNr = blockNr;
        this.blockSize = blockSize;
        this.more = more;
    }

    public BlockOption(byte[] raw) {
        int bl = DataConvertingUtility.readVariableULong(raw).intValue();
        blockNr = bl >> 4;
        more = (bl & 0x8) != 0;
        byte szx = (byte) (bl & 0x07);
        blockSize = BlockSize.fromRawSzx(szx);
    }

    public byte[] toBytes() {
        int block = blockNr << 4;
        if (more) {
            block |= 1 << 3;
        }
        block |= blockSize.toRawSzx();
        return DataConvertingUtility.convertVariableUInt(block);
    }

    /**
     * @return the blockNr
     */
    public int getNr() {
        return blockNr;
    }

    public BlockSize getBlockSize() {
        return blockSize;
    }

    public boolean isBert() {
        return blockSize.bert;
    }

    /**
     * @return the size
     */
    public int getSize() {
        return blockSize.getSize();
    }

    public boolean hasMore() {
        return more;
    }

    /**
     * Creates next block option instance with incremented block number. Set
     * more flag according to payload size.
     *
     * @param fullPayload full payload
     * @return BlockOption
     */
    public BlockOption nextBlock(byte[] fullPayload) {
        return nextBertBlock(fullPayload, 1);
    }

    public BlockOption nextBertBlock(byte[] fullPayload, int bertBlocksPerMessage) {
        if (fullPayload.length > (blockNr + bertBlocksPerMessage + 1) * getSize()) {
            //has more
            return new BlockOption(blockNr + bertBlocksPerMessage, blockSize, true);
        } else {
            return new BlockOption(blockNr + bertBlocksPerMessage, blockSize, false);
        }

    }

    public int appendPayload(ByteArrayOutputStream origPayload, byte[] block) {
        try {
            origPayload.write(block);
        } catch (IOException e) {
            // should never happen
            throw new RuntimeException("Can't append payload to buffer", e);
        }
        return block.length / getSize(); // return count of blocks added, needed for BERT
    }

    public byte[] createBlockPart(byte[] fullPayload) {
        //block size 16
        //b0: 0 - 15
        //b1: 16 - 31

        int startPos = blockNr * getSize();
        if (startPos > fullPayload.length - 1) {
            //payload to small
            return null;
        }
        int len = getSize();
        if (startPos + len > fullPayload.length) {
            len = fullPayload.length - startPos;
        }
        byte[] nwPayload = new byte[len];
        System.arraycopy(fullPayload, startPos, nwPayload, 0, len);
        //LOGGER.trace("createBlockPart() payload-len: " + fullPayload.length + " start: " +startPos + " len: " + len);
        return nwPayload;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof BlockOption)) {
            return false;
        }
        if (obj.hashCode() != this.hashCode()) {
            return false;
        }

        return ((BlockOption) obj).blockSize == this.blockSize
                && ((BlockOption) obj).blockNr == this.blockNr
                && ((BlockOption) obj).more == this.more;
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 67 * hash + this.blockNr;
        hash = 67 * hash + this.blockSize.szx;
        hash = 67 * hash + (this.blockSize.bert ? 1 : 0);
        hash = 67 * hash + (this.more ? 1 : 0);
        return hash;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.blockNr);
        sb.append('|').append(more ? "more" : "last");
        sb.append('|').append(getSize());
        if (isBert()) {
            sb.append('|').append("BERT");
        }
        return sb.toString();
    }
}
