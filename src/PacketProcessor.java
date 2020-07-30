import org.jnetpcap.packet.JPacket;

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
            if (data.keySet().contains(second)){
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
            if (data.keySet().contains(second)){
                data.put(second, data.get(second) + 1);
            }
            else{
                data.put(second, 1);
            }
        }
        return data; // In this format, we can easily import it into a graph.
    }

    // Function ideas:
    // -- Categorise each packet into a group based on their headers; video, VoIP, etc.
    // -- TCP conversation count, failed acknowledgment percentage, retransmission rate, etc.
    // -- Aggregate source/destination IP addresses; who's communicating the most
}
