import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.chart.AreaChart;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.XYChart;
import javafx.stage.Stage;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JPacket;

import java.io.IOException;
import java.util.*;

public class NetworkVisualiser extends Application {
    static Scanner userInput = new Scanner(System.in); // For now, we will have a static scanner for input.
    static Hashtable<Long, Integer> data; // For now, we'll have a static dictionary for the processed packet data.
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

        // Example processing: total amount of data captured, packets per second and data per second.
        System.out.println("You captured " + PacketProcessor.totalSize(packets) + " bytes worth of data!");
        System.out.println(PacketProcessor.packetsPerSecond(packets, packets.get(0).getCaptureHeader().seconds()));
        data = PacketProcessor.dataPerSecond(packets, packets.get(0).getCaptureHeader().seconds());
        System.out.println(data);

        // Close our connection.
        pcap.close();
        launch(args);
    }

    @Override
    public void start(Stage stage){
        // Set up x-axis and y-axis.
        Long startingRange = Collections.min(data.keySet());
        Long endingRange = Collections.max(data.keySet());
        // TODO: Adjust y-axis values to eliminate unnecessary space.
        NumberAxis xAxis = new NumberAxis(startingRange, endingRange, 1);
        NumberAxis yAxis = new NumberAxis();
        xAxis.setLabel("Time Since Capture Began (Seconds)");
        yAxis.setLabel("Bytes Transferred");

        // Add all data from the processed packets.
        AreaChart<Number, Number> packetChart = new AreaChart<>(xAxis, yAxis);
        packetChart.setTitle("Network Activity");
        XYChart.Series chartData = new XYChart.Series();
        chartData.setName("Bytes Per Second");
        for (Long second : data.keySet()) {
            chartData.getData().add(new XYChart.Data(second, data.get(second)));
        }
        packetChart.getData().addAll(chartData);
        packetChart.setCreateSymbols(false);
        packetChart.setLegendVisible(false);

        // Set up our JavaFX GUI.
        Scene scene  = new Scene(packetChart,800,600);
        stage.setScene(scene);
        stage.show();
    }

    /**
     * This thread is responsible for capturing packets.
     * By multi-threading, the user will retain control of the GUI (when it is written) whilst packets are being captured.
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