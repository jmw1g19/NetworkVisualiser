import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.chart.AreaChart;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.XYChart;
import javafx.scene.chart.XYChart.Data;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.ColumnConstraints;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.RowConstraints;
import javafx.scene.text.Font;
import org.jnetpcap.packet.JPacket;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Hashtable;

/**
 * This class is responsible for generating all UI components.
 */
@SuppressWarnings("rawtypes")
public class UserInterface{
    TabPane mainContent; // Our root node in the scene graph, a TabPane.
    GridPane chartPane = new GridPane(); // A GridPane is used for the 'Overall' tab.

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

        // Generate the tab objects.
        Tab tab1 = new Tab("Overall", chartPane);
        Tab tab2 = new Tab("Layer 2"  , new Label("Work In Progress"));
        Tab tab3 = new Tab("Layer 3" , new Label("Work In Progress"));
        Tab tab4 = new Tab("Layer 4"  , new Label("Work In Progress"));
        Tab tab5 = new Tab("Layer 5" , new Label("Work In Progress"));
        Tab tab6 = new Tab("Layer 6"  , new Label("Work In Progress"));
        Tab tab7 = new Tab("Layer 7" , new Label("Work In Progress"));

        // Set up the TabPane.
        mainContent = new TabPane();
        mainContent.setTabClosingPolicy(TabPane.TabClosingPolicy.UNAVAILABLE);
        mainContent.getTabs().addAll(tab1, tab2, tab3, tab4, tab5, tab6, tab7);
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
}
