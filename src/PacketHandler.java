import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;

import java.util.ArrayList;

/**
 * This class is responsible for handling packets as they arrive.
 */
public class PacketHandler implements PcapPacketHandler {
    ArrayList<JPacket> packetList;

    /**
     * Creates a new PacketHandler, with the specified packet list.
     * @param packetListReference The variable containing the packet list.
     */
    public PacketHandler(ArrayList<JPacket> packetListReference) {
        packetList = packetListReference;
    }

    /**
     * This method handles what should occur every time a new packet is received.
     * @param pcapPacket The packet that has been received.
     * @param o Not quite sure the purpose of this parameter...
     */
    @Override
    public void nextPacket(PcapPacket pcapPacket, Object o) {
        // We can do some pre-processing here before adding them into the PacketList.
        // For now, we'll just add each packet to the PacketList.
        System.out.println("Packet!");
        packetList.add(pcapPacket);

        // Example: outputting the source and destination of all IP packets.
        Ip4 ip = new Ip4();
        if (pcapPacket.hasHeader(ip)) {
            byte[] sIP; byte[] dIP;
            sIP = ip.source();
            dIP = ip.destination();

            String sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
            String destinationIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);

            System.out.println("IP packet found! Source: " + sourceIP + " Destination: " + destinationIP);
        }

    }
}