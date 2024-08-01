package org.itxtech.daedalus.provider;

import android.util.Log;

import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.Map;

public class TrafficHandler {
    private static final String TAG = "TrafficHandler";
    private static final int MTU = 1500; // Assuming MTU is defined as a constant

    private boolean isRunning = true;
    private ExecutorService executorService = Executors.newSingleThreadExecutor();
    private Map<String, String> localDomainMap; // Assuming this is defined elsewhere in the class

    public void handleTraffic(FileDescriptor fileDescriptor) {
        executorService.execute(() -> {
            Log.d(TAG, "handleTraffic: Starting to handle traffic");
            try (FileInputStream inputStream = new FileInputStream(fileDescriptor);
                 FileOutputStream outputStream = new FileOutputStream(fileDescriptor)) {
                
                byte[] packet = new byte[MTU];

                while (isRunning) {
                    try {
                        int length = inputStream.read(packet);
                        if (length > 0) {
                            Log.d(TAG, "handleTraffic: Received packet of length " + length);
                            byte[] processedPacket = processPacket(packet, length);
                            if (processedPacket != null) {
                                outputStream.write(processedPacket);
                                Log.d(TAG, "handleTraffic: Wrote processed packet");
                            }
                        }
                    } catch (Exception e) {
                        Log.e(TAG, "Error handling traffic: " + e.getMessage(), e);
                    }
                }
            } catch (Exception e) {
                Log.e(TAG, "Error in handleTraffic: " + e.getMessage(), e);
            }
        });
    }

    private byte[] processPacket(byte[] packet, int length) {
        ByteBuffer buffer = ByteBuffer.wrap(packet, 0, length).order(ByteOrder.BIG_ENDIAN);

        try {
            // Check if it's an IPv4 packet
            if ((buffer.get(0) >> 4) != 4) {
                Log.d(TAG, "processPacket: Not an IPv4 packet");
                return packet;
            }

            // Check if it's a UDP packet
            if (buffer.get(9) != 17) {
                Log.d(TAG, "processPacket: Not a UDP packet");
                return packet;
            }

            // Extract source and destination ports
            int sourcePort = buffer.getShort(20) & 0xFFFF;
            int destPort = buffer.getShort(22) & 0xFFFF;

            // Check if it's a DNS query (destination port 53)
            if (destPort != 53) {
                Log.d(TAG, "processPacket: Not a DNS query");
                return packet;
            }

            Log.d(TAG, "processPacket: Processing DNS query");

            // Extract DNS query
            ByteBuffer dnsBuffer = ByteBuffer.wrap(packet, 28, length - 28);
            String query = extractDnsQuery(dnsBuffer);

            Log.d(TAG, "processPacket: Extracted DNS query: " + query);

            // Check if the query ends with .gtblcl.com
            if (query.endsWith(".gtblcl.com")) {
                String localQuery = query.replace(".gtblcl.com", ".local");
                String localIp = localDomainMap.get(localQuery);

                if (localIp != null) {
                    Log.d(TAG, "processPacket: Found local IP for query: " + localIp);
                    // Construct DNS response
                    return constructDnsResponse(packet, localIp);
                } else {
                    Log.d(TAG, "processPacket: No local IP found for query");
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error processing packet: " + e.getMessage(), e);
        }

        return packet;
    }

    private String extractDnsQuery(ByteBuffer buffer) {
        StringBuilder query = new StringBuilder();
        try {
            buffer.position(12); // Skip header
            int length = buffer.get() & 0xFF;

            while (length != 0) {
                for (int i = 0; i < length; i++) {
                    query.append((char) (buffer.get() & 0xFF));
                }
                length = buffer.get() & 0xFF;
                if (length != 0) query.append('.');
            }
        } catch (Exception e) {
            Log.e(TAG, "Error extracting DNS query: " + e.getMessage(), e);
        }

        return query.toString();
    }

    private byte[] constructDnsResponse(byte[] query, String ip) {
        Log.d(TAG, "constructDnsResponse: Constructing DNS response for IP " + ip);
        byte[] response = query.clone();
        ByteBuffer buffer = ByteBuffer.wrap(response).order(ByteOrder.BIG_ENDIAN);

        try {
            // Modify DNS header
            buffer.put(2, (byte) 0x81); // QR = 1, Opcode = 0, AA = 0, TC = 0, RD = 1
            buffer.put(3, (byte) 0x80); // RA = 1, Z = 0, RCODE = 0
            buffer.putShort(6, (short) 1); // ANCOUNT = 1

            // Find the end of the query
            int endOfQuery = 12;
            while (buffer.get(endOfQuery) != 0) endOfQuery++;
            endOfQuery += 5; // Skip null byte and QTYPE/QCLASS

            // Construct answer
            buffer.putShort(endOfQuery, (short) 0xC00C); // Pointer to domain name
            buffer.putShort(endOfQuery + 2, (short) 1); // TYPE A
            buffer.putShort(endOfQuery + 4, (short) 1); // CLASS IN
            buffer.putInt(endOfQuery + 6, 300); // TTL (5 minutes)
            buffer.putShort(endOfQuery + 10, (short) 4); // RDLENGTH

            // Put IP address
            String[] octets = ip.split("\\.");
            for (int i = 0; i < octets.length; i++) {
                buffer.put(endOfQuery + 12 + i, (byte) Integer.parseInt(octets[i]));
            }

            Log.d(TAG, "constructDnsResponse: DNS response constructed successfully");
        } catch (Exception e) {
            Log.e(TAG, "Error constructing DNS response: " + e.getMessage(), e);
        }

        return response;
    }

    public void stopTrafficHandling() {
        isRunning = false;
        executorService.shutdown();
    }
}