import javafx.event.EventHandler;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Dialog;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import javafx.scene.input.MouseButton;
import javafx.scene.input.MouseEvent;
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
}
