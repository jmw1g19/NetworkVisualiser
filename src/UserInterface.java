import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.chart.AreaChart;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.PieChart;
import javafx.scene.chart.XYChart;
import javafx.scene.chart.XYChart.Data;
import javafx.scene.control.*;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.*;
import javafx.scene.text.Font;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Hashtable;

/**
 * This class is responsible for generating all UI components.
 * Each part of the UI is a separate function for modularity; updating one tab won't impact another.
 */
@SuppressWarnings("rawtypes")
public class UserInterface{
    TabPane mainContent; // Our root node in the scene graph, a TabPane.
    GridPane chartPane = new GridPane(); // A GridPane is used for the 'Overall' tab.
    GridPane layer4Pane = new GridPane(); // A GridPane is ued for the 'Layer 4' tab.

    /**
     * The constructor for the class. Responsible for setting up the overall structure of the UI.
     */
    public UserInterface() {
        // Set-up the 'Overall' tab.
        RowConstraints equalSizing = new RowConstraints();
        equalSizing.setPercentHeight(50);
        chartPane.getRowConstraints().add(equalSizing);
        ColumnConstraints fullWidth = new ColumnConstraints();
        fullWidth.setPercentWidth(100);
        chartPane.getColumnConstraints().add(fullWidth);
        chartPane.setPadding(new Insets(10));
        chartPane.setHgap(5);

        // Set-up the 'Layer 4' tab.
        layer4Pane.getRowConstraints().addAll(equalSizing, equalSizing);
        ColumnConstraints twoSegments = new ColumnConstraints();
        twoSegments.setPercentWidth(50);
        twoSegments.setHgrow(Priority.ALWAYS);
        layer4Pane.getColumnConstraints().addAll(twoSegments, twoSegments);
        layer4Pane.setPadding(new Insets(5));

        // Generate the tab objects.
        Tab tab1 = new Tab("Overall", chartPane);
        Tab tab2 = new Tab("Layer 2"  , new Label("Work In Progress"));
        Tab tab3 = new Tab("Layer 3" , new Label("Work In Progress"));
        Tab tab4 = new Tab("Layer 4"  , layer4Pane);
        Tab tab5 = new Tab("Layer 7" , new Label("Work In Progress"));

        // Set up the TabPane.
        mainContent = new TabPane();
        mainContent.setTabClosingPolicy(TabPane.TabClosingPolicy.UNAVAILABLE);
        mainContent.getTabs().addAll(tab1, tab2, tab3, tab4, tab5);
    }

    /**
     * This function returns the root node in the UI.
     * @return A Scene object, which has our TabPane set as its' content.
     */
    public Scene getRoot(){
        return new Scene(mainContent,800, 600);
    }

    /**
     * This function generates the packet selector for the 'Overall' tab.
     * @param packetList The list of packets to generate a ListView for.
     */
    public void generatePacketSelector(ArrayList<JPacket> packetList){
        // Create a ListView and populate it with information for each packet.
        ListView<String> packetSelector = new ListView<String>();
        int count = 0;
        for(JPacket p : packetList) {
            packetSelector.getItems().add("Packet " + (count + 1) + ": " + p.getTotalSize() +  " bytes | " +
                PacketProcessor.generatePacketSummary(p));
            count++;
        }

        // Set up event handling for the ListView.
        packetSelector.addEventHandler(MouseEvent.MOUSE_CLICKED, new UserInterfaceHandler.PacketClick(packetSelector, packetList));

        // Display the selector beneath the graph on the 'Overall' tab.
        GridPane.setColumnIndex(packetSelector, 0);
        GridPane.setRowIndex(packetSelector, 1);

        // Add a Label to help the user...
        Label instructions = new Label("Double click on a packet to view more information about it");
        instructions.setFont(new Font(9));
        GridPane.setColumnIndex(instructions, 0);
        GridPane.setRowIndex(instructions, 2);

        chartPane.getChildren().addAll(packetSelector, instructions);
    }

    /**
     * This function generates the chart for the 'Overall' tab.
     * @param packetList The list of packets to place into the chart.
     */
    public void generateChart(ArrayList<JPacket> packetList){
        // Capture the data needed for the chart - the amount of data sent each second.
        Hashtable<Long, Integer> data = PacketProcessor.dataPerSecond(packetList, packetList.get(0).getCaptureHeader().seconds());

        // Set up the x-axis and y-axis.
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
            chartData.getData().add(new Data(second, data.get(second)));
        }
        packetChart.getData().addAll(chartData);

        // Format the chart, and add to the pane responsible for the 'Overall' tab.
        packetChart.setCreateSymbols(false);
        packetChart.setLegendVisible(false);
        GridPane.setColumnIndex(packetChart, 0);
        GridPane.setRowIndex(packetChart, 0);
        chartPane.getChildren().add(packetChart);
    }

    public void generateLayer4Information(ArrayList<JPacket> packetList){
        // TCP vs. UDP Pie Chart
        ObservableList<PieChart.Data> pieChartData =
                FXCollections.observableArrayList(
                        new PieChart.Data("TCP", PacketProcessor.findPacketsWithHeader(packetList, new Tcp()).size()),
                        new PieChart.Data("UDP", PacketProcessor.findPacketsWithHeader(packetList, new Udp()).size()));
        final PieChart chart = new PieChart(pieChartData);
        chart.setLegendVisible(false);
        chart.setTitle("TCP vs. UDP");
        layer4Pane.getChildren().add(chart);
        GridPane.setColumnIndex(chart, 1);
        GridPane.setRowIndex(chart, 0);

        // Statistics Panel
        VBox statisticsPanel = new VBox();
        statisticsPanel.setSpacing(10);

        Label tcpStatisticsHeader = new Label("TCP Statistics"); tcpStatisticsHeader.setUnderline(true);
        tcpStatisticsHeader.setFont(new Font(16));
        tcpStatisticsHeader.setMaxSize(Double.POSITIVE_INFINITY, Double.POSITIVE_INFINITY);
        VBox.setVgrow(tcpStatisticsHeader, Priority.ALWAYS); tcpStatisticsHeader.setAlignment(Pos.CENTER);

        Label connectionCount = new Label(PacketProcessor.listTCPConnections(packetList).size() + " unique connections");
        connectionCount.setMaxSize(Double.POSITIVE_INFINITY, Double.POSITIVE_INFINITY);
        VBox.setVgrow(connectionCount, Priority.ALWAYS); connectionCount.setAlignment(Pos.CENTER);
        Button showConnections = new Button("Show List of Connections");
        showConnections.setStyle("-fx-font-size: 0.75em; ");

        Label threeWayHandshakes = new Label("___ three-way handshakes");
        threeWayHandshakes.setMaxSize(Double.POSITIVE_INFINITY, Double.POSITIVE_INFINITY);
        VBox.setVgrow(threeWayHandshakes, Priority.ALWAYS); threeWayHandshakes.setAlignment(Pos.CENTER);
        Button showHandshakes = new Button("Show All Handshakes");
        showHandshakes.setStyle("-fx-font-size: 0.75em; ");

        Label urgentPackets = new Label(PacketProcessor.urgentTCPPackets(packetList) + " urgent packets");
        urgentPackets.setMaxSize(Double.POSITIVE_INFINITY, Double.POSITIVE_INFINITY);
        VBox.setVgrow(urgentPackets, Priority.ALWAYS); urgentPackets.setAlignment(Pos.CENTER);
        Button showUrgent = new Button("Show All Urgent Packets");
        showUrgent.setStyle("-fx-font-size: 0.75em; ");

        Label resetConnections = new Label(PacketProcessor.resetTCPConnections(packetList) + " reset connections");
        resetConnections.setMaxSize(Double.POSITIVE_INFINITY, Double.POSITIVE_INFINITY);
        VBox.setVgrow(resetConnections, Priority.ALWAYS); resetConnections.setAlignment(Pos.CENTER);
        Button showResets = new Button("Show All Reset Packets");
        showResets.setStyle("-fx-font-size: 0.75em; ");

        statisticsPanel.getChildren().addAll(tcpStatisticsHeader, connectionCount, showConnections,
                threeWayHandshakes, showHandshakes, urgentPackets, showUrgent, resetConnections, showResets);

        layer4Pane.getChildren().add(statisticsPanel);
        statisticsPanel.setAlignment(Pos.CENTER);
        GridPane.setColumnIndex(statisticsPanel, 0);
        GridPane.setRowIndex(statisticsPanel, 1);
        GridPane.setFillHeight(statisticsPanel, true); GridPane.setFillWidth(statisticsPanel, true);
        statisticsPanel.setMaxSize(Double.MAX_VALUE, Double.MAX_VALUE);
    }
}
