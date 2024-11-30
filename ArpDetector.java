import jpcap.*;
import jpcap.packet.*;
import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;
import java.io.IOException;
import java.net.InetAddress;
import java.text.DecimalFormat;
import java.util.Date;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;

public class ArpDetector extends JFrame {

    private JTable packetTable;
    private JComboBox<String> interfaceComboBox;
    private JButton startButton;
    private JButton stopButton;
    private JProgressBar progressBar;
    private DefaultTableModel tableModel;
    private NetworkInterface[] devices;
    private JpcapCaptor captor;
    private boolean monitoring;
    private final BlockingQueue<ARPPacket> packetQueue = new LinkedBlockingQueue<>();
    private final ConcurrentHashMap<String, String> ipMacMap = new ConcurrentHashMap<>();

    public ArpDetector() {
        setTitle("ARP Detector");
        setSize(1000, 600);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        // Top Panel
        JPanel topPanel = new JPanel(new FlowLayout());
        interfaceComboBox = new JComboBox<>();
        startButton = new JButton("Start Monitoring");
        stopButton = new JButton("Stop Monitoring");
        stopButton.setEnabled(false); // Initially disabled
        progressBar = new JProgressBar();
        progressBar.setIndeterminate(false);
        progressBar.setString("Idle");
        progressBar.setStringPainted(true);

        // Button Colors
        startButton.setBackground(Color.GREEN);
        startButton.setForeground(Color.BLACK);
        stopButton.setBackground(Color.RED);
        stopButton.setForeground(Color.WHITE);

        topPanel.add(new JLabel("Select Interface:"));
        topPanel.add(interfaceComboBox);
        topPanel.add(startButton);
        topPanel.add(stopButton);
        topPanel.add(progressBar);

        add(topPanel, BorderLayout.NORTH);

        // Packet Table
        String[] columnNames = {"Time", "Source", "Destination", "Protocol", "Length", "Info"};
        tableModel = new DefaultTableModel(columnNames, 0);
        packetTable = new JTable(tableModel);
        customizeTable(packetTable);
        JScrollPane scrollPane = new JScrollPane(packetTable);

        add(scrollPane, BorderLayout.CENTER);

        // Button Actions
        startButton.addActionListener(e -> startMonitoring());
        stopButton.addActionListener(e -> stopMonitoring());

        loadNetworkInterfaces();
    }

    private void customizeTable(JTable table) {
        // Set row height and font
        table.setRowHeight(20);
        table.setFont(new Font("Monospaced", Font.PLAIN, 12));

        // Customize table header
        JTableHeader header = table.getTableHeader();
        header.setFont(new Font("SansSerif", Font.BOLD, 12));
        header.setReorderingAllowed(false);
        header.setResizingAllowed(true);
        ((DefaultTableCellRenderer) header.getDefaultRenderer()).setHorizontalAlignment(SwingConstants.CENTER);

        // Set default row color to blue
        table.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component comp = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (!isSelected) {
                    comp.setBackground(new Color(173, 216, 230)); // Light blue for safe packet
                } else {
                    comp.setBackground(new Color(173, 216, 230)); // Light blue for selected row
                }
                return comp;
            }
        });

        // Add thin grid lines
        table.setShowGrid(true);
        table.setGridColor(Color.LIGHT_GRAY);

        // Adjust column widths
        TableColumnModel columnModel = table.getColumnModel();
        columnModel.getColumn(0).setPreferredWidth(100); // Time
        columnModel.getColumn(1).setPreferredWidth(150); // Source
        columnModel.getColumn(2).setPreferredWidth(150); // Destination
        columnModel.getColumn(3).setPreferredWidth(100); // Protocol
        columnModel.getColumn(4).setPreferredWidth(70);  // Length
        columnModel.getColumn(5).setPreferredWidth(300); // Info
    }

    private void loadNetworkInterfaces() {
        try {
            devices = JpcapCaptor.getDeviceList();
            for (int i = 0; i < devices.length; i++) {
                interfaceComboBox.addItem(i + ": " + devices[i].name + " (" + devices[i].description + ")");
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Failed to load network interfaces!", "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void startMonitoring() {
        int index = interfaceComboBox.getSelectedIndex();
        if (index == -1) {
            JOptionPane.showMessageDialog(this, "Please select a network interface!", "Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        try {
            captor = JpcapCaptor.openDevice(devices[index], 65535, true, 20);
            monitoring = true;

            // Set up progress bar and buttons
            UIManager.put("ProgressBar.foreground", Color.GREEN);
            progressBar.setIndeterminate(true);
            progressBar.setString("Monitoring...");
            startButton.setEnabled(false);
            stopButton.setEnabled(true);

            tableModel.setRowCount(0); // Clear previous data

            // Start a thread to capture packets
            new Thread(() -> capturePackets()).start();

            // Start a SwingWorker for processing packets in the background
            new PacketProcessingWorker().execute();

        } catch (IOException ex) {
            JOptionPane.showMessageDialog(this, "Error: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void stopMonitoring() {
        if (monitoring) {
            monitoring = false;

            // Stop capturing packets
            if (captor != null) {
                captor.close();
            }

            // Reset Progress Bar to Default
            UIManager.put("ProgressBar.foreground", Color.LIGHT_GRAY);
            progressBar.setIndeterminate(false);
            progressBar.setString("Idle");

            startButton.setEnabled(true);
            stopButton.setEnabled(false);

            JOptionPane.showMessageDialog(this, "Monitoring stopped!", "Info", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void capturePackets() {
        try {
            while (monitoring) {
                Packet packet = captor.getPacket();
                if (packet instanceof ARPPacket) {
                    packetQueue.put((ARPPacket) packet);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void processPacket(ARPPacket arpPacket) {
        try {
            String time = new DecimalFormat("0.000").format(new Date().getTime() / 1000.0);
            String sourceIP = InetAddress.getByAddress(arpPacket.sender_protoaddr).getHostAddress();
            String sourceMAC = macToString(arpPacket.sender_hardaddr);
            String destinationIP = InetAddress.getByAddress(arpPacket.target_protoaddr).getHostAddress();
            String protocol = "ARP";
            int length = arpPacket.len;
            String info = "Sender MAC: " + sourceMAC;

            // Check for ARP spoofing and update row color
            boolean isSpoofing = detectArpSpoofing(sourceIP, sourceMAC);

            // Add packet to the table with appropriate row color
            SwingUtilities.invokeLater(() -> {
                tableModel.addRow(new Object[]{time, sourceIP, destinationIP, protocol, length, info});
                int lastRow = tableModel.getRowCount() - 1;
                if (isSpoofing) {
                    packetTable.setRowSelectionInterval(lastRow, lastRow);
                    packetTable.setSelectionBackground(Color.RED);
                    showErrorPanel("ARP Spoofing detected! IP: " + sourceIP + ", MAC: " + sourceMAC);
                } else {
                    packetTable.setRowSelectionInterval(lastRow, lastRow);
                    packetTable.setSelectionBackground(new Color(173, 216, 230)); // Light blue for safe packet
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private boolean detectArpSpoofing(String ipAddress, String macAddress) {
        String existingMAC = ipMacMap.get(ipAddress);

        if (existingMAC != null && !existingMAC.equals(macAddress)) {
            // Spoofing detected
            return true;
        }

        // Update the map with the new IP-MAC association
        ipMacMap.put(ipAddress, macAddress);
        return false;
    }

    private void showErrorPanel(String message) {
        JOptionPane.showMessageDialog(this, message, "ARP Spoofing Alert", JOptionPane.WARNING_MESSAGE);
    }

    private String macToString(byte[] mac) {
        StringBuilder sb = new StringBuilder();
        for (byte b : mac) {
            sb.append(String.format("%02X:", b));
        }
        return sb.substring(0, sb.length() - 1);
    }

    private class PacketProcessingWorker extends SwingWorker<Void, ARPPacket> {
        @Override
        protected Void doInBackground() throws Exception {
            while (monitoring) {
                ARPPacket packet = packetQueue.take(); // Blocking call, waits for packets
                publish(packet);
            }
            return null;
        }

        @Override
        protected void process(List<ARPPacket> chunks) {
            for (ARPPacket packet : chunks) {
                processPacket(packet);
            }
        }

        @Override
        protected void done() {
            stopMonitoring();
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            ArpDetector frame = new ArpDetector();
            frame.setVisible(true);
        });
    }
}
