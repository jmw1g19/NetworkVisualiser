import javafx.scene.Scene;
import javafx.scene.chart.AreaChart;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.XYChart;
import javafx.scene.chart.XYChart.Data;
import javafx.scene.control.Label;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.layout.VBox;
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
    VBox chartPane = new VBox(); // For now, a VBox will be used for the 'Overall' tab.

    /**
     * The contructor for the class. Responsible for setting up the overall structure of the UI.
     */
    public UserInterface() {
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
        chartPane.getChildren().add(packetChart);
    }
}
