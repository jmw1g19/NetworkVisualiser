import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;

import java.util.ArrayList;
import java.util.Hashtable;

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
            return summary;
        }
        // Layer 4 - TCP
        // TCP Acknowledgment | 127.0.0.1:80 --> 127.0.0.1:1923
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
            return summary;
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
            return summary;
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
            return summary;
        }
        // Layer 2 - Ethernet
        // Work In Progress
        else if (packet.hasHeader(new Ethernet())){
            return "Ethernet";
        }
        return summary;
    }

    // Function ideas:
    // -- Categorise each packet into a group based on their headers; video, VoIP, etc.
    // -- TCP conversation count, failed acknowledgment percentage, retransmission rate, etc.
    // -- Aggregate source/destination IP addresses; who's communicating the most
}
