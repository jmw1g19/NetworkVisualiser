import org.jnetpcap.packet.JPacket;

import java.util.ArrayList;

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
}
