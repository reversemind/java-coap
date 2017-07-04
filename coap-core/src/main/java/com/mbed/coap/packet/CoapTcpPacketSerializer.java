package com.mbed.coap.packet;

import com.mbed.coap.exception.CoapException;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;

/**
 * This class implements serialization on de-serialization for CoAP over TCP packet.
 * draft-ietf-core-coap-tcp-tls-09
 */
public final class CoapTcpPacketSerializer {

    /**
     * De-serialize CoAP over TCP message from input stream.
     *
     * @param remoteAddress remote address
     * @param is input stream
     * @return CoapPacket instance
     * @throws CoapException if input stream can not be de-serialized
     */
    public static CoapPacket deserialize(InetSocketAddress remoteAddress, InputStream is) throws CoapException {
        StrictInputStream inputStream = new StrictInputStream(is);
        CoapPacket cp = new CoapPacket(remoteAddress);

        try {
            // Len & TKL
            int tempByte = inputStream.read();
            int plLen = readPayloadLen(tempByte, is);
            byte tokenLen = (byte) (tempByte & 0x0F);

            // Code
            tempByte = inputStream.read();
            if (tempByte >= 1 && tempByte <= 10) {
                //method code
                cp.setMethod(Method.valueOf(tempByte));
            } else {
                cp.setCode(Code.valueOf(tempByte));
            }
            cp.setMessageType(null); //override default

            //TKL Bytes
            cp.setToken(inputStream.readBytes(tokenLen));

            //Options
            HeaderOptions options = new HeaderOptions();
            boolean hasPayloadMarker = options.deserialize(inputStream);
            cp.setHeaderOptions(options);

            //Payload
            if (hasPayloadMarker) {
                cp.setPayload(inputStream.readBytes(plLen));
            } else if (plLen > 0) {
                throw new EOFException();
            }

        } catch (IOException iOException) {
            throw new CoapException(iOException);
        }

        return cp;
    }

    private static int readPayloadLen(int firstByte, InputStream inputStream) throws IOException {
        int plLen = firstByte >>> 4;

        //Extended Length
        if (plLen == 13) {
            plLen += inputStream.read();

        } else if (plLen == 14) {
            plLen = inputStream.read() << 8;
            plLen += inputStream.read();
            plLen += 269;

        } else if (plLen == 15) {
            plLen = inputStream.read() << 24;
            plLen += inputStream.read() << 16;
            plLen += inputStream.read() << 8;
            plLen += inputStream.read();
            plLen += 65805;
        }

        return plLen;
    }

    public static long readPayloadLength(InputStream inputStream) throws IOException {
        return readPayloadLen(inputStream.read(), inputStream);
    }

    /**
     * Serialize CoAP over TCP message
     *
     * @param coapPacket CoAP packet object
     * @return serialized data
     * @throws CoapException exception if coap packet can not be serialized
     */
    public static byte[] serialize(CoapPacket coapPacket) throws CoapException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();

        writeTo(os, coapPacket);

        return os.toByteArray();
    }

    /**
     * Writes serialized CoAP packet to given OutputStream.
     *
     * @param os output stream
     * @param coapPacket CoAP packet object
     * @throws CoapException serialization exception
     */
    public static void writeTo(OutputStream os, CoapPacket coapPacket) throws CoapException {
        try {
            // Len & TKL
            int tempByte = coapPacket.getToken().length;
            int plLen = coapPacket.getPayload().length;

            if (plLen < 13) {
                tempByte += (plLen << 4);
            } else if (plLen < 269) {
                tempByte += (13 << 4);
            } else if (plLen < 65805) {
                tempByte += (14 << 4);
            } else {
                tempByte += (15 << 4);
            }

            os.write(tempByte);

            //Extended Length
            if (plLen >= 13 && plLen < 269) {
                os.write(plLen - 13);
            } else if (plLen >= 269 && plLen < 65805) {
                os.write((0xFF00 & (plLen - 269)) >> 8);
                os.write(0x00FF & (plLen - 269));
            } else if (plLen >= 65805) {
                os.write((0xFF000000 & (plLen - 65805)) >> 24);
                os.write((0x00FF0000 & (plLen - 65805)) >> 16);
                os.write((0x0000FF00 & (plLen - 65805)) >> 8);
                os.write(0x000000FF & (plLen - 65805));
            }

            // Code
            Code code = coapPacket.getCode();
            Method method = coapPacket.getMethod();

            if (code != null && method != null) {
                throw new CoapException("Forbidden operation: 'code' and 'method' use at a same time");
            }
            if (code != null) {
                os.write(code.getCoapCode());
            } else if (method != null) {
                os.write(method.getCode());
            } else { //no code or method used
                os.write(0);
            }

            //TKL Bytes
            os.write(coapPacket.getToken());

            //Options
            coapPacket.headers().serialize(os);

            //Payload
            if (coapPacket.getPayload() != null && coapPacket.getPayload().length > 0) {
                os.write(CoapPacket.PAYLOAD_MARKER);
                os.write(coapPacket.getPayload());
            }

        } catch (IOException iOException) {
            throw new CoapException(iOException.getMessage(), iOException);
        }
    }


    private static class StrictInputStream extends InputStream {
        private final InputStream inputStream;

        StrictInputStream(InputStream inputStream) {
            this.inputStream = inputStream;
        }

        private byte[] readBytes(int len) throws IOException {
            byte[] bytes = new byte[len];
            read(bytes);
            return bytes;
        }

        @Override
        public int read() throws IOException {
            int val = inputStream.read();
            if (val < 0) {
                throw new EOFException();
            }
            return val;
        }

        @Override
        public int read(byte[] b) throws IOException {
            if (b.length == 0) {
                return 0;
            }
            if (inputStream.read(b) != b.length) {
                throw new EOFException();
            }
            return b.length;
        }

        @Override
        public int available() throws IOException {
            return inputStream.available();
        }
    }
}
