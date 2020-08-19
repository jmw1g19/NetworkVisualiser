import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.voip.RtcpReceiverReport;
import org.jnetpcap.protocol.voip.RtcpSenderReport;
import org.jnetpcap.protocol.voip.Rtp;
import org.jnetpcap.protocol.voip.Sdp;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Set;

/**
 * This class is responsible for performing analysis on a list of captured packets.
 */
public class PacketProcessor {
    /**
     * This function returns the total size - in bytes - of the list of packets.
     * @param packets The list of packets.
     * @return The total size of all the packets, in bytes.
     */
    public static int totalSize(ArrayList<JPacket> packets){
        int size = 0;
        for(JPacket p : packets){
            size = size + p.getTotalSize();
        }
        return size;
    }

    /**
     * This function returns the amount of bytes transferred per second covered in a packet list.
     * @param packets The list of packets to check.
     * @param startingSecond The first seconds value in the packet list, so data is adjusted.
     * @return A hash table with pairs of seconds and total data in bytes.
     */
    public static Hashtable<Long, Integer> dataPerSecond (ArrayList<JPacket> packets, Long startingSecond){
        Hashtable<Long, Integer> data = new Hashtable<>();
        for(JPacket p : packets){
            // We normalise the seconds values relative to the start of the capture.
            Long second = p.getCaptureHeader().seconds() - startingSecond;
            if (data.containsKey(second)){
                data.put(second, data.get(second) + p.getTotalSize());
            }
            else{
                data.put(second, p.getTotalSize());
            }
        }
        return data; // In this format, we can easily import it into a graph.
    }

    /**
     * This function return the number of packets received per second covered in a packet list.
     * @param packets The list of packets to check.
     * @param startingSecond The first seconds value in the packet list, so data is adjusted.
     * @return A hash table with pairs of seconds and packets received.
     */
    public static Hashtable<Long, Integer> packetsPerSecond (ArrayList<JPacket> packets, Long startingSecond){
        Hashtable<Long, Integer> data = new Hashtable<>();
        for(JPacket p : packets){
            // We normalise the seconds values relative to the start of the capture.
            Long second = p.getCaptureHeader().seconds() - startingSecond;
            if (data.containsKey(second)){
                data.put(second, data.get(second) + 1);
            }
            else{
                data.put(second, 1);
            }
        }
        return data; // In this format, we can easily import it into a graph.
    }

    /**
     * This function returns all packets from a list which have a specified header.
     * @param packets The list of packets to check.
     * @param header The header to search for.
     * @return A list containing all packets which have the given header.
     */
    public static ArrayList<JPacket> findPacketsWithHeader(ArrayList<JPacket> packets, JHeader header){
        ArrayList<JPacket> matchingPackets = new ArrayList<>();
        for(JPacket p : packets){
            if(p.hasHeader(header)) { matchingPackets.add(p); }
        }
        return matchingPackets;
    }

    /**
     * This function returns a one-line string which summarises the packet, based on the headers.
     * @param packet The packet to produce a summary for.
     * @return A String, containing the summary.
     */
    public static String generatePacketSummary(JPacket packet){
        String summary = "";
        // To provide the most useful summary, we must start at layer 7 and work downwards, capturing the first
        // header we find.
        // TODO: Additional comments and other protocols.

        // Layer 7 - HTTP
        // 'HTTP 200 OK' / 'HTTP GET /sites/...'
        if(packet.hasHeader(new Http())){
            Http header = new Http();
            if(packet.getHeader(header).isResponse()){
                String responseCode = packet.getHeader(header).fieldValue(Http.Response.ResponseCode);
                String responseMessage = packet.getHeader(header).fieldValue(Http.Response.ResponseCodeMsg);
                String response = responseCode + " " + responseMessage;
                summary += "HTTP " + response;
            }
            else{
                String requestMethod = packet.getHeader(header).fieldValue(Http.Request.RequestMethod);
                String requestURL = packet.getHeader(header).fieldValue(Http.Request.RequestUrl);
                String request = requestMethod + requestURL;
                summary += "HTTP " + request;
            }
        }
        // Layer 7 - RTP
        // 'RTP - 30 bytes | Sequence 10884 Timestamp 185608827'
        else if(packet.hasHeader(new Rtp())){
            Rtp header = new Rtp();
            int size = packet.getHeader(header).size();
            int sequence = packet.getHeader(header).sequence();
            long timestamp = packet.getHeader(header).timestamp();
            summary += "RTP - " + size + " bytes | Sequence " + sequence + " Timestamp " + timestamp;
        }
        // Layer 7 - RTCP-RR
        // TODO: Find the fields in a ReceiverReport.
        else if(packet.hasHeader(new RtcpReceiverReport())){
            summary = "RTCP Receiver Report";
        }
        // Layer 7 - RTCP-SR
        // TODO: Find the fields in a SenderReport.
        else if(packet.hasHeader(new RtcpSenderReport())){
            summary = "RTCP Sender Report";
        }
        // Layer 7 - SDP
        // 'SDP - audio 10142 RTP/AVP 18 0 8 101'
        else if(packet.hasHeader(new Sdp())){
            Sdp header = new Sdp();
            String mediaDescription = packet.getHeader(header).getDescription();
            summary = "SDP - " + mediaDescription;
        }
        // Layer 4 - UDP
        // 'UDP - 52 bytes'
        else if(packet.hasHeader(new Udp())){
            Udp header = new Udp();
            summary = "UDP - " + packet.getHeader(header).length() + " bytes";
        }
        // Layer 4 - TCP
        // 'TCP Acknowledgment | 127.0.0.1:80 --> 127.0.0.1:1923'
        else if(packet.hasHeader(new Tcp())){
            Tcp header = new Tcp();
            summary += "TCP ";
            if(packet.getHeader(header).flags_ACK()){ summary += "Acknowledgment "; }
            if(packet.getHeader(header).flags_PSH()){ summary += "Push "; }
            if(packet.getHeader(header).flags_SYN()){ summary += "Synchronisation "; }
            if(packet.getHeader(header).flags_URG()){ summary += "Urgent "; }
            if(packet.getHeader(header).flags_RST()){ summary += "Reset "; }
            if(packet.getHeader(header).flags_FIN()){ summary += "Final "; }
            int source = packet.getHeader(header).source();
            int destination = packet.getHeader(header).destination();
            // TODO: Optimise.
            Ip4 ipHeader = new Ip4();
            byte[] sourceBytes = packet.getHeader(ipHeader).source();
            String sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sourceBytes);
            byte[] destinationBytes = packet.getHeader(ipHeader).destination();
            String destinationIP = org.jnetpcap.packet.format.FormatUtils.ip(destinationBytes);
            summary += ("| " + sourceIP + ":" + source + " --> " + destinationIP + ":" + destination);
        }
        // Layer 3 - IP
        // 'IP - 127.0.0.1 --> 127.0.0.1'
        else if(packet.hasHeader(new Ip4())){
            Ip4 header = new Ip4();
            byte[] sourceBytes = packet.getHeader(header).source();
            String sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sourceBytes);
            byte[] destinationBytes = packet.getHeader(header).destination();
            String destinationIP = org.jnetpcap.packet.format.FormatUtils.ip(destinationBytes);
            summary += "IP - " + sourceIP + " --> " + destinationIP;
        }
        // Layer 2 - ARP
        // 'ARP Request - ab:cd:ef:gh looking for 127.0.0.1'
        else if (packet.hasHeader(new Arp())){
            summary = "ARP ";
            Arp header = new Arp();
            // Is it a request or a reply?
            if(packet.getHeader(header).operation() == 1) {
                summary += "Request - ";
                byte[] SHA = packet.getHeader(header).sha();
                String sourceMAC = org.jnetpcap.packet.format.FormatUtils.mac(SHA);
                byte[] TPA = packet.getHeader(header).tpa();
                String targetIP = org.jnetpcap.packet.format.FormatUtils.ip(TPA);
                summary += sourceMAC + " looking for " + targetIP;
            }
            else{
                summary += "Reply - ";
                byte[] SHA = packet.getHeader(header).sha();
                String sourceMAC = org.jnetpcap.packet.format.FormatUtils.mac(SHA);
                byte[] SPA = packet.getHeader(header).spa();
                String sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(SPA);
                summary += sourceIP + " is " + sourceMAC;
            }
        }
        // Layer 2 - Ethernet
        // 'Ethernet [LAN] 54 bytes ab:cd:ef:gh --> ab:cd:ef:gh'
        else if (packet.hasHeader(new Ethernet())){
            Ethernet header = new Ethernet();
            int size = packet.getHeader(header).getPayloadLength();
            byte[] sourceBytes = packet.getHeader(header).source();
            byte[] destinationBytes = packet.getHeader(header).destination();
            String sourceMAC = org.jnetpcap.packet.format.FormatUtils.mac(sourceBytes);
            String destinationMAC = org.jnetpcap.packet.format.FormatUtils.mac(destinationBytes);
            summary = "Ethernet [LAN] " + size + " bytes " + sourceMAC + " --> " + destinationMAC;
        }
        return summary;
    }

    /**
     * This function returns the number of TCP packets which have the RST flag.
     * @param packetList The list of packets to check through.
     * @return An integer with the number of reset connections.
     */
    public static int resetTCPConnections(ArrayList<JPacket> packetList){
        int count = 0;
        Tcp header = new Tcp();
        ArrayList<JPacket> tcpPackets = findPacketsWithHeader(packetList, new Tcp());
        for(JPacket p : tcpPackets){
            if(p.getHeader(header).flags_RST()) { count++; }
        }
        return count;
    }

    /**
     * This function returns the amount of TCP packets which have the URG flag set.
     * @param packetList The list of packets to check through.
     * @return An integer with the number of 'urgent' packets.
     */
    public static int urgentTCPPackets(ArrayList<JPacket> packetList){
        int count = 0;
        Tcp header = new Tcp();
        ArrayList<JPacket> tcpPackets = findPacketsWithHeader(packetList, new Tcp());
        for(JPacket p : tcpPackets){
            if(p.getHeader(header).flags_URG()) { count++; }
        }
        return count;
    }

    public static ArrayList<String> listTCPConnections(ArrayList<JPacket> packetList){
        // The idea is to find the number of TCP unique pairs. For this, we'll need a Set, and the IP/TCP headers.
        Set<String> pairs = new HashSet<String>();
        Tcp tcpHeader = new Tcp();
        Ip4 ipHeader = new Ip4();
        ArrayList<JPacket> tcpPackets = findPacketsWithHeader(packetList, new Tcp());
        for(JPacket p : tcpPackets){
            int source = p.getHeader(tcpHeader).source();
            int destination = p.getHeader(tcpHeader).destination();
            byte[] sourceBytes = p.getHeader(ipHeader).source();
            String sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sourceBytes);
            byte[] destinationBytes = p.getHeader(ipHeader).destination();
            String destinationIP = org.jnetpcap.packet.format.FormatUtils.ip(destinationBytes);
            if(!pairs.contains(destinationIP + ":" + destination + " and " + sourceIP + ":" + source)) {
                pairs.add(sourceIP + ":" + source + " and " + destinationIP + ":" + destination);
            }
            // TODO: Is this a reset packet? If so, that means another connection may be established.
            // To check this, we'd need to see if a three-way handshake occurs.
        }
        return new ArrayList<String>(pairs);
    }
    // Function ideas:
    // -- Categorise each packet into a group based on their headers; video, VoIP, etc.
    // -- TCP conversation count, failed acknowledgment percentage, retransmission rate, etc.
    // -- Aggregate source/destination IP addresses; who's communicating the most
}
