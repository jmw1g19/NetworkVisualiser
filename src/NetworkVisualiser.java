import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import org.jnetpcap.*;
import org.jnetpcap.packet.*;

public class NetworkVisualiser {
    static Scanner userInput = new Scanner(System.in);
    public static void main(String[] args) throws IOException {
        StringBuilder errorBuffer = new StringBuilder(); // Used to store any error messages.
        List<PcapIf> allDevices = new ArrayList<PcapIf>(); // Stores the list of NICs.

        // Find all NICs and store them in our ArrayList.
        int r = Pcap.findAllDevs(allDevices, errorBuffer);
        if (r != Pcap.OK || allDevices.isEmpty()) { // If something goes wrong, output the StringBuffer.
            System.err.printf("Can't read list of devices, error is %s",
                    errorBuffer.toString());
            return;
        }
        System.out.println("Network devices found:");

        // Output all the device information.
        int i = 0;
        for (PcapIf device : allDevices) {
            String description = (device.getDescription() != null) ? device
                    .getDescription() : "No description available";
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(),
                    description);
        }
        PcapIf device = allDevices.get(userInput.nextInt()); // Allow the user to select a device.
        System.out.printf("\n'%s' was selected!\n",
                (device.getDescription() != null) ? device.getDescription()
                        : device.getName());

        // Define all the data to open a live connection:
        int snapLength = 64 * 1024; // Capture all packets, no truncation.
        int flags = Pcap.MODE_PROMISCUOUS; // Capture all packets by making NIC act promiscuous.
        int timeout = 10 * 1000; // Set timeout to 10 seconds.

        // Start the connection.
        Pcap pcap = Pcap.openLive(device.getName(), snapLength, flags, timeout, errorBuffer);
        // If an error occurs, pcap will be null.
        if (pcap == null) {
            System.err.printf("Error while opening device for capture: "
                    + errorBuffer.toString());
            return;
        }

        // Store a list of all the packets.
        ArrayList<JPacket> packets = new ArrayList<>();

        // Start Pcap capturing thread.
        PcapThread pcapCapture = new PcapThread(pcap, packets);
        pcapCapture.start();

        // Wait for the user to press something, then (safely) stop capture and wait for thread to terminate.
        System.in.read();
        pcapCapture.stopCapture();
        try {
            pcapCapture.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        // Output all the packets.
        // TODO: Ignore RTCP-SDES items.
        try{
            for(JPacket p : packets){
                System.out.println(p.toString());
            }
        }
        catch(Exception e){

        }

        // Example processing: total amount of data captured.
        System.out.println("You captured " + PacketProcessor.totalSize(packets) + " bytes worth of data!");

        // Close our connection.
        pcap.close();
    }

    /**
     * This thread is responsible for capturing packets.
     * By multi-threading, the user will retain control of the GUI (when it is written) whilst packets are being captured.
     */
    static class PcapThread extends Thread {
        Pcap pcap;
        ArrayList<JPacket> packets;

        public PcapThread(Pcap pcapObject, ArrayList<JPacket> packetList) {
            pcap = pcapObject;
            packets = packetList;
        }

        public void run(){
            pcap.loop(Pcap.LOOP_INFINITE, new PacketHandler(packets), "build");
        }

        public void stopCapture(){
            pcap.breakloop();
        }
    }
}
