import javafx.application.Application;
import javafx.stage.Stage;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JPacket;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class NetworkVisualiser extends Application {
    static Scanner userInput = new Scanner(System.in); // For now, we will have a static scanner for input.
    static ArrayList<JPacket> packets = new ArrayList<>(); // Stores a list of all the packets captured on this instance.

    /**
     * The main function. Responsible for starting the program by selecting an NIC and capturing packets,
     * before generating the UI.
     */
    public static void main(String[] args) throws IOException {
        StringBuilder errorBuffer = new StringBuilder(); // Used to store any error messages.
        List<PcapIf> allDevices = new ArrayList<>(); // Stores the list of NICs.

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
            System.err.print("Error while opening device for capture: "
                    + errorBuffer.toString());
            return;
        }

        // Start Pcap capturing thread.
        PcapThread pcapCapture = new PcapThread(pcap, packets);
        pcapCapture.start();

        // Wait for the user to press something, then (safely) stop capture and wait for thread to terminate.
        //noinspection ResultOfMethodCallIgnored
        System.in.read();
        pcapCapture.stopCapture();
        try {
            pcapCapture.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        // Example processing: total amount of data captured, packets per second and data per second.
        System.out.println("You captured " + PacketProcessor.totalSize(packets) + " bytes worth of data!");
        System.out.println(PacketProcessor.packetsPerSecond(packets, packets.get(0).getCaptureHeader().seconds()));
        System.out.println(PacketProcessor.dataPerSecond(packets, packets.get(0).getCaptureHeader().seconds()));

        // Close our connection.
        pcap.close();
        launch(args);
    }

    /**
     * This function will start the JavaFX Application Thread, and show the GUI to the user.
     * Since we delegated generating the GUI to the UserInterface class, we just call all the necessary functions here.
     */
    @Override
    public void start(Stage stage){
        // Create a new UserInterface.
        UserInterface UI = new UserInterface();

        // Call all its' functions.
        UI.generateChart(packets);
        UI.generatePacketSelector(packets);

        // Set the 'stage' object, adjust some options, and show the GUI.
        stage.setScene(UI.getRoot());
        stage.setTitle("NetworkVisualiser - Work In Progress");
        stage.setMinHeight(600);
        stage.setMinWidth(600);
        stage.show();
    }

    /**
     * This thread is responsible for capturing packets.
     * By multi-threading, the user can stop the capture whenever they wish, as control is maintained over the console.
     */
    static class PcapThread extends Thread {
        Pcap pcap;
        ArrayList<JPacket> packets;

        // The constructor merely sets member variables.
        public PcapThread(Pcap pcapObject, ArrayList<JPacket> packetList) {
            pcap = pcapObject;
            packets = packetList;
        }

        // When the thread is started, capture begins.
        public void run(){
            pcap.loop(Pcap.LOOP_INFINITE, new PacketHandler(packets), "build");
        }

        // A special function to stop capture safely, before terminating the thread.
        public void stopCapture(){
            pcap.breakloop();
        }
    }
}