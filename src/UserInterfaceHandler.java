import javafx.event.EventHandler;
import javafx.scene.control.*;
import javafx.scene.input.MouseButton;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.VBox;
import org.jnetpcap.packet.JPacket;

import java.util.ArrayList;

/**
 * This class wil be responsible for handling GUI events.
 * Instances of these EventHandlers are created by UserInterface.
 */
public class UserInterfaceHandler {
    /**
     * This class handles clicking on a packet in the packet selector on the 'Overall' tab of the UI.
     */
    public static class PacketClick implements EventHandler<MouseEvent>{
        /**
         * This class represents a custom Dialog to show the raw packet to the user.
         */
        private class PacketDialogBox extends Dialog{
            /**
             * The constructor sets up the design of the Dialog.
             * @param packetNumber The number of the packet in the capture.
             * @param packet The JPacket itself.
             */
            public PacketDialogBox(int packetNumber, JPacket packet) {
                // Set up header/title text.
                this.setHeaderText("Packet " + packetNumber);
                this.setTitle("Packet Information");

                // We use a TextArea to show the raw packet text.
                TextArea packetText = new TextArea();
                packetText.setText(packet.toString());
                packetText.setEditable(false);

                // We customise the Dialog further.
                this.getDialogPane().setContent(packetText);
                this.getDialogPane().setMinWidth(500);
                this.getDialogPane().getButtonTypes().setAll(ButtonType.OK);
                // TODO: Export packet to file.
            }
        }

        ArrayList<JPacket> packets; // We need the list of packets for reference.
        ListView list; // As we're in a separate class, we need a reference back to the ListView.

        /**
         * This constructor assigns our two member variables.
         * @param listObject The ListView this class will be attached to.
         * @param packetList The full list of packets.
         */
        public PacketClick(ListView listObject, ArrayList<JPacket> packetList){
            packets = packetList;
            list = listObject;
        }

        /**
         * This class handles when the ListView is clicked.
         * @param event The generated MouseEvent.
         */
        @Override
        public void handle(MouseEvent event) {
            // If the user has clicked on an item, and have double-clicked...
            if(!event.getTarget().toString().contains("null") && event.getButton().equals(MouseButton.PRIMARY)
                && event.getClickCount() == 2){
                // Instantiate dialog box for selected packet.
                int indexSelected = list.getSelectionModel().getSelectedIndex();
                Dialog dialogBox = new PacketDialogBox(indexSelected + 1, packets.get(indexSelected));

                // Show the dialog box to the user.
                dialogBox.showAndWait();
            }
        }
    }

    /**
     * This class handles any button that resembles "Show Connections" across the GUI.
     */
    public static class ConnectionListClick implements EventHandler<MouseEvent>{
        /**
         * This class represents a custom Dialog to show a list of strings, which represent connections.
         */
        public class ConnectionListDialogBox extends Dialog{
            /**
             * This instantiates a new Dialog, using the supplied ArrayList of strings.
             * @param connections The list of connections to show.
             */
            public ConnectionListDialogBox(ArrayList<String> connections){
                // Set up header/title text.
                this.setHeaderText("Connection List");
                this.setTitle("Connection List");

                // We use a ScrollPane so the Dialog doesn't extend vertically, and a VBox to position the items.
                ScrollPane pane = new ScrollPane();
                VBox stringList = new VBox();
                pane.setContent(stringList);
                pane.setPrefHeight(150);

                // Create a Label for each item, and add it to the VBox.
                for(String item : connections) {
                    item.trim();
                    Label text = new Label(item);
                    stringList.getChildren().add(text);
                }

                // We customise the Dialog further.
                this.getDialogPane().setContent(pane);
                this.getDialogPane().setMinWidth(500);
                this.getDialogPane().getButtonTypes().setAll(ButtonType.OK);

            }
        }

        ArrayList<String> connections; // The list of connections this EventHandler will pass to our Dialog.

        /**
         * This constructor assigns the variable needed to store the connections.
         * @param data An ArrayList of strings, representing connections.
         */
        public ConnectionListClick(ArrayList<String> data){
            this.connections = data;
        }

        /**
         * This class handles when the Button is clicked.
         * @param mouseEvent The mouseEvent which is generated.
         */
        @Override
        public void handle(MouseEvent mouseEvent) {
            // Create and show the Dialog.
            Dialog dialogBox = new ConnectionListDialogBox(connections);
            dialogBox.showAndWait();
        }
    }
}
