import javax.crypto.*;
import javax.crypto.spec.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.plaf.basic.BasicScrollBarUI;
import javax.swing.plaf.basic.BasicTabbedPaneUI;
import javax.sound.sampled.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.*;

public class GoogleStyleCryptoSuiteNET extends JFrame {

    // --- GOOGLE MATERIAL PALETTE ---
    private static final Color GOOGLE_BLUE = new Color(26, 115, 232);
    private static final Color GOOGLE_RED = new Color(217, 48, 37);
    private static final Color GOOGLE_GREEN = new Color(30, 142, 62);
    private static final Color GOOGLE_YELLOW = new Color(249, 171, 0);
    private static final Color GOOGLE_GRAY_BG = new Color(248, 249, 250);
    private static final Color GOOGLE_SURFACE = new Color(255, 255, 255);
    private static final Color GOOGLE_TEXT_MAIN = new Color(32, 33, 36);
    private static final Color GOOGLE_TEXT_SEC = new Color(95, 99, 104);
    private static final Color GOOGLE_BORDER = new Color(218, 220, 224);

    // --- CRYPTO CONFIG ---
    private static final int LAYERS = 1; 
    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
    private static final String HASH_ALGO = "SHA3-512";
    private static final String KDF_ALGO = "PBKDF2WithHmacSHA512";
    private static final int IV_LEN = 12;
    private static final int TAG_LEN = 128;
    private static final int SALT_LEN = 32;
    private static final int ITERATIONS = 100000;

    // --- NETWORK CONFIG ---
    private static final String MSG_SEPARATOR = "|||";
    // Data Packets
    private static final int PACKET_MSG = 1;
    private static final int PACKET_FILE_TCP = 2;
    private static final int PACKET_UDP_FILE_START = 3;
    private static final int PACKET_UDP_FILE_DATA = 4;
    private static final int PACKET_UDP_FILE_END = 5;
    private static final int PACKET_VOICE = 6; 
    // Call Signaling Packets (Giao thức bắt tay)
    private static final int PACKET_CALL_REQ = 10;    // Yêu cầu gọi
    private static final int PACKET_CALL_ACCEPT = 11; // Chấp nhận
    private static final int PACKET_CALL_REJECT = 12; // Từ chối
    private static final int PACKET_CALL_END = 13;    // Kết thúc
    
    private static final String TARGET_ALL = ">> Gửi tất cả (Broadcast)";
    private static final long MAX_FILE_SIZE = 50L * 1024 * 1024;
    private static final int UDP_CHUNK_SIZE = 45 * 1024;
    private static final int AUDIO_CHUNK_SIZE = 1024;

    // --- UI COMPONENTS ---
    private JTextArea msgInput, msgOutput;
    private JPasswordField msgPass;
    private JTextField srcField, dstField;
    private JPasswordField filePass;
    private JProgressBar progressBar;
    private JLabel statusLabel;

    // Network UI
    private JTextField txtIp, txtPort, txtChatInput, txtNickName;
    private JPasswordField txtNetPass;
    private JComboBox<String> cmbProtocol, cmbTarget;
    private MaterialButton btnHost, btnConnect, btnDisconnect, btnSendMsg, btnSendFile;
    private MaterialButton btnCall; 
    private JLabel lblNetStatus;
    private JPanel chatBody;
    private JScrollPane chatScrollPane;

    // --- LOGIC VARIABLES ---
    private Socket tcpSocket;
    private DataOutputStream tcpOut;
    private DataInputStream tcpIn;
    private DatagramSocket udpSocket;
    private ConcurrentHashMap<String, InetSocketAddress> knownPeers = new ConcurrentHashMap<>();
    private ConcurrentHashMap<String, FileOutputStream> udpFileReceivers = new ConcurrentHashMap<>();
    private ConcurrentHashMap<String, String> udpFileNames = new ConcurrentHashMap<>();
    private volatile boolean isRunning = false;
    private boolean isUDP = false;

    // --- AUDIO / CALL STATE ---
    private volatile boolean isCallActive = false; // Đã kết nối và đang nói chuyện
    private volatile boolean isDialing = false;    // Đang chờ bắt máy
    private TargetDataLine microphone;
    private SourceDataLine speakers;

    public GoogleStyleCryptoSuiteNET() {
        setTitle("Military Crypto Suite - Full Video Call Logic TÁC GIẢ: Nguyễn Thái Hiệp/CÔNG TY TNHH SX-TM-DV HÒA MỸ HƯNG");
        setSize(1200, 850);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        getContentPane().setBackground(GOOGLE_GRAY_BG);
        setLayout(new BorderLayout());

        setUIFont(new javax.swing.plaf.FontUIResource("Segoe UI", Font.PLAIN, 14));

        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setUI(new MaterialTabbedPaneUI());
        tabbedPane.setFont(new Font("Segoe UI", Font.BOLD, 14));
        tabbedPane.setBackground(GOOGLE_SURFACE);
        tabbedPane.setForeground(GOOGLE_TEXT_SEC);

        tabbedPane.addTab("MÃ HÓA VĂN BẢN", createMessagePanel());
        tabbedPane.addTab("KÉT SẮT FILE", createFilePanel());
        tabbedPane.addTab("LIÊN LẠC (CHAT/VOICE)", createNetworkPanel());

        add(tabbedPane, BorderLayout.CENTER);
    }

    // =========================================================================
    // UI SETUP (Standard)
    // =========================================================================
    
    private JPanel createMessagePanel() {
        JPanel container = new JPanel(new GridLayout(1, 2, 20, 0)); container.setBackground(GOOGLE_GRAY_BG); container.setBorder(new EmptyBorder(20, 20, 20, 20));
        JPanel leftCard = createCardPanel(); leftCard.setLayout(new BorderLayout(0, 15));
        JPanel headerLeft = new JPanel(new BorderLayout()); headerLeft.setBackground(GOOGLE_SURFACE);
        headerLeft.add(createTitleLabel("Văn bản gốc"), BorderLayout.WEST);
        MaterialButton btnPaste = new MaterialButton("Dán", GOOGLE_BLUE, true);
        MaterialButton btnClear = new MaterialButton("Xóa", GOOGLE_TEXT_SEC, true);
        JPanel toolsLeft = new JPanel(new FlowLayout(FlowLayout.RIGHT)); toolsLeft.setBackground(GOOGLE_SURFACE); toolsLeft.add(btnPaste); toolsLeft.add(btnClear); headerLeft.add(toolsLeft, BorderLayout.EAST);
        msgInput = createMaterialTextArea();
        btnPaste.addActionListener(e -> msgInput.paste()); btnClear.addActionListener(e -> { msgInput.setText(""); msgInput.requestFocus(); });
        JPanel passPanel = new JPanel(new BorderLayout(10, 5)); passPanel.setBackground(GOOGLE_SURFACE);
        passPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(GOOGLE_BORDER), "Khóa bí mật", TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, new Font("Segoe UI", Font.BOLD, 12), GOOGLE_TEXT_SEC));
        msgPass = createMaterialPasswordField(); MaterialButton btnGen = new MaterialButton("🎲 Tạo Key", GOOGLE_YELLOW, true); btnGen.addActionListener(e -> generateAndSaveKey(msgPass));
        passPanel.add(msgPass, BorderLayout.CENTER); passPanel.add(btnGen, BorderLayout.EAST);
        JPanel actionPanel = new JPanel(new GridLayout(1, 2, 10, 0)); actionPanel.setBackground(GOOGLE_SURFACE);
        MaterialButton btnEnc = new MaterialButton("🔒 MÃ HÓA", GOOGLE_BLUE, false); MaterialButton btnDec = new MaterialButton("🔓 GIẢI MÃ", GOOGLE_GREEN, false);
        btnEnc.setPreferredSize(new Dimension(0, 45)); btnEnc.addActionListener(e -> handleMsgCrypto(true)); btnDec.addActionListener(e -> handleMsgCrypto(false));
        actionPanel.add(btnEnc); actionPanel.add(btnDec);
        JPanel leftBody = new JPanel(new BorderLayout(0, 10)); leftBody.setBackground(GOOGLE_SURFACE); leftBody.add(createMaterialScrollPane(msgInput), BorderLayout.CENTER); leftBody.add(passPanel, BorderLayout.SOUTH);
        leftCard.add(headerLeft, BorderLayout.NORTH); leftCard.add(leftBody, BorderLayout.CENTER); leftCard.add(actionPanel, BorderLayout.SOUTH);
        JPanel rightCard = createCardPanel(); rightCard.setLayout(new BorderLayout(0, 15));
        JPanel headerRight = new JPanel(new BorderLayout()); headerRight.setBackground(GOOGLE_SURFACE); headerRight.add(createTitleLabel("Kết quả"), BorderLayout.WEST);
        MaterialButton btnCopy = new MaterialButton("Sao chép", GOOGLE_BLUE, true); btnCopy.addActionListener(e -> { msgOutput.selectAll(); msgOutput.copy(); }); headerRight.add(btnCopy, BorderLayout.EAST);
        msgOutput = createMaterialTextArea(); msgOutput.setEditable(false); msgOutput.setBackground(new Color(241, 243, 244));
        rightCard.add(headerRight, BorderLayout.NORTH); rightCard.add(createMaterialScrollPane(msgOutput), BorderLayout.CENTER);
        container.add(leftCard); container.add(rightCard); return container;
    }

    private JPanel createFilePanel() {
        JPanel container = new JPanel(new GridBagLayout()); container.setBackground(GOOGLE_GRAY_BG);
        GridBagConstraints gbc = new GridBagConstraints(); gbc.gridx=0; gbc.gridy=0; gbc.weightx=1; gbc.fill=GridBagConstraints.HORIZONTAL; gbc.insets=new Insets(10,100,10,100);
        JPanel card = createCardPanel(); card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS)); card.setBorder(new EmptyBorder(30, 40, 30, 40));
        card.add(createTitleLabel("Cấu hình file")); card.add(Box.createVerticalStrut(20));
        srcField = createMaterialTextField(); dstField = createMaterialTextField(); filePass = createMaterialPasswordField();
        card.add(createFormRow("File Nguồn:", srcField, "Chọn File", e -> chooseFile(srcField, false))); card.add(Box.createVerticalStrut(15));
        card.add(createFormRow("Lưu Tại:", dstField, "Chọn Nơi Lưu", e -> chooseFile(dstField, true))); card.add(Box.createVerticalStrut(15));
        JPanel pPass = new JPanel(new BorderLayout(10, 0)); pPass.setBackground(GOOGLE_SURFACE);
        JLabel l = new JLabel("Mật Khẩu:"); l.setForeground(GOOGLE_TEXT_SEC); l.setPreferredSize(new Dimension(80, 35));
        pPass.add(l, BorderLayout.WEST); pPass.add(filePass, BorderLayout.CENTER); MaterialButton btnGen = new MaterialButton("Sinh Key", GOOGLE_YELLOW, true);
        btnGen.addActionListener(e -> generateAndSaveKey(filePass)); pPass.add(btnGen, BorderLayout.EAST); card.add(pPass); card.add(Box.createVerticalStrut(30));
        JPanel pBtn = new JPanel(new GridLayout(1, 2, 20, 0)); pBtn.setBackground(GOOGLE_SURFACE);
        MaterialButton btnE = new MaterialButton("MÃ HÓA FILE", GOOGLE_BLUE, false); MaterialButton btnD = new MaterialButton("GIẢI MÃ FILE", GOOGLE_GREEN, false);
        btnE.setPreferredSize(new Dimension(0, 50)); btnE.addActionListener(e -> processFile(true)); btnD.addActionListener(e -> processFile(false));
        pBtn.add(btnE); pBtn.add(btnD); card.add(pBtn); card.add(Box.createVerticalStrut(20));
        statusLabel = new JLabel("Sẵn sàng."); statusLabel.setForeground(GOOGLE_TEXT_SEC);
        progressBar = new JProgressBar(); progressBar.setForeground(GOOGLE_BLUE); progressBar.setBackground(GOOGLE_BORDER); progressBar.setBorderPainted(false); progressBar.setPreferredSize(new Dimension(0, 5));
        card.add(statusLabel); card.add(Box.createVerticalStrut(5)); card.add(progressBar);
        container.add(card, gbc); return container;
    }

    private JPanel createNetworkPanel() {
        JPanel panel = new JPanel(new BorderLayout(15, 0)); panel.setBackground(GOOGLE_GRAY_BG); panel.setBorder(new EmptyBorder(15, 15, 15, 15));
        JPanel sidebar = createCardPanel(); sidebar.setPreferredSize(new Dimension(300, 0)); sidebar.setLayout(new BoxLayout(sidebar, BoxLayout.Y_AXIS)); sidebar.setBorder(new EmptyBorder(20, 20, 20, 20));
        sidebar.add(createTitleLabel("Cài đặt mạng")); sidebar.add(Box.createVerticalStrut(20));
        cmbProtocol = new JComboBox<>(new String[]{"TCP (Chat/File)", "UDP (Chat/File/Voice)"}); styleComboBox(cmbProtocol);
        sidebar.add(createLabel("Giao thức:")); sidebar.add(cmbProtocol); sidebar.add(Box.createVerticalStrut(10));
        txtNickName = createMaterialTextField(); txtNickName.setText("Operator");
        sidebar.add(createLabel("Tên hiển thị:")); sidebar.add(txtNickName); sidebar.add(Box.createVerticalStrut(10));
        txtIp = createMaterialTextField(); txtIp.setText("127.0.0.1");
        sidebar.add(createLabel("IP Đối phương:")); sidebar.add(txtIp); sidebar.add(Box.createVerticalStrut(10));
        txtPort = createMaterialTextField(); txtPort.setText("8888");
        sidebar.add(createLabel("Cổng (Port):")); sidebar.add(txtPort); sidebar.add(Box.createVerticalStrut(10));
        sidebar.add(createLabel("Khóa kênh (Key):")); 
        JPanel pNetKey = new JPanel(new BorderLayout(5, 0)); pNetKey.setBackground(GOOGLE_SURFACE);
        txtNetPass = createMaterialPasswordField(); MaterialButton btnGenNet = new MaterialButton("🎲", GOOGLE_YELLOW, true);
        btnGenNet.setPreferredSize(new Dimension(40, 30)); btnGenNet.addActionListener(e -> generateAndSaveKey(txtNetPass));
        pNetKey.add(txtNetPass, BorderLayout.CENTER); pNetKey.add(btnGenNet, BorderLayout.EAST); sidebar.add(pNetKey); sidebar.add(Box.createVerticalStrut(20));
        btnHost = new MaterialButton("HOST (MÁY CHỦ)", GOOGLE_BLUE, false); btnConnect = new MaterialButton("CONNECT (MÁY KHÁCH)", GOOGLE_GREEN, false);
        btnDisconnect = new MaterialButton("NGẮT KẾT NỐI", GOOGLE_RED, false); btnDisconnect.setEnabled(false);
        sidebar.add(btnHost); sidebar.add(Box.createVerticalStrut(10)); sidebar.add(btnConnect); sidebar.add(Box.createVerticalStrut(10)); sidebar.add(btnDisconnect); sidebar.add(Box.createVerticalStrut(20));
        lblNetStatus = new JLabel("OFFLINE"); lblNetStatus.setFont(new Font("Segoe UI", Font.BOLD, 12)); lblNetStatus.setForeground(GOOGLE_TEXT_SEC); lblNetStatus.setHorizontalAlignment(SwingConstants.CENTER);
        sidebar.add(lblNetStatus);

        JPanel chatPanel = createCardPanel(); chatPanel.setLayout(new BorderLayout());
        JPanel chatHeader = new JPanel(new BorderLayout()); chatHeader.setBackground(GOOGLE_SURFACE); chatHeader.setBorder(BorderFactory.createEmptyBorder(15, 20, 15, 20));
        
        JPanel headerTools = new JPanel(new FlowLayout(FlowLayout.RIGHT)); headerTools.setBackground(GOOGLE_SURFACE);
        btnCall = new MaterialButton("📞 GỌI ĐIỆN", GOOGLE_GREEN, false);
        btnCall.setEnabled(false);
        headerTools.add(btnCall);

        chatHeader.add(createTitleLabel("Kênh liên lạc"), BorderLayout.WEST);
        cmbTarget = new JComboBox<>(); styleComboBox(cmbTarget); cmbTarget.addItem(TARGET_ALL); cmbTarget.setEnabled(false);
        JPanel topRight = new JPanel(new BorderLayout(5,0)); topRight.setBackground(GOOGLE_SURFACE);
        topRight.add(cmbTarget, BorderLayout.CENTER); topRight.add(headerTools, BorderLayout.EAST);
        chatHeader.add(topRight, BorderLayout.EAST);
        chatPanel.add(chatHeader, BorderLayout.NORTH);

        chatBody = new JPanel(); chatBody.setLayout(new BoxLayout(chatBody, BoxLayout.Y_AXIS)); chatBody.setBackground(Color.WHITE);
        chatScrollPane = createMaterialScrollPane(chatBody); chatPanel.add(chatScrollPane, BorderLayout.CENTER);

        JPanel chatFooter = new JPanel(new BorderLayout(10, 0)); chatFooter.setBackground(GOOGLE_SURFACE); chatFooter.setBorder(new EmptyBorder(15, 20, 15, 20));
        btnSendFile = new MaterialButton("📎", GOOGLE_TEXT_SEC, true); btnSendFile.setPreferredSize(new Dimension(40, 40));
        txtChatInput = createMaterialTextField(); txtChatInput.setFont(new Font("Segoe UI", Font.PLAIN, 16));
        btnSendMsg = new MaterialButton("GỬI", GOOGLE_BLUE, false);
        chatFooter.add(btnSendFile, BorderLayout.WEST); chatFooter.add(txtChatInput, BorderLayout.CENTER); chatFooter.add(btnSendMsg, BorderLayout.EAST);
        chatPanel.add(chatFooter, BorderLayout.SOUTH);
        panel.add(sidebar, BorderLayout.WEST); panel.add(chatPanel, BorderLayout.CENTER);

        btnHost.addActionListener(e -> startServer()); btnConnect.addActionListener(e -> startClient());
        btnDisconnect.addActionListener(e -> disconnect());
        btnSendMsg.addActionListener(e -> sendNetMessage()); txtChatInput.addActionListener(e -> sendNetMessage());
        btnSendFile.addActionListener(e -> sendNetFile());
        btnCall.addActionListener(e -> handleCallButton()); // LOGIC MỚI CHO NÚT GỌI
        cmbProtocol.addActionListener(e -> {
            boolean udp = cmbProtocol.getSelectedItem().toString().contains("UDP");
            cmbTarget.setEnabled(udp);
            if(udp) { btnCall.setText("📞 GỌI ĐIỆN"); } else { btnCall.setText("🚫 CHỈ UDP"); btnCall.setEnabled(false); }
        });
        return panel;
    }

    // =========================================================================
    // CALL SIGNALLING & LOGIC (PHẦN QUAN TRỌNG: XỬ LÝ GỌI/NGHE)
    // =========================================================================

    // 1. Khi bấm nút Gọi
    private void handleCallButton() {
        if (!isUDP) { JOptionPane.showMessageDialog(this, "Chỉ hỗ trợ gọi qua UDP!"); return; }
        
        if (isCallActive || isDialing) {
            // Đang gọi thì bấm nút này nghĩa là Dừng/Hủy
            endCallLocally("Bạn đã kết thúc cuộc gọi.");
            sendSignal(PACKET_CALL_END); // Gửi tín hiệu báo bên kia tắt
        } else {
            // Chưa gọi -> Bắt đầu gọi
            isDialing = true;
            btnCall.setText("ĐANG GỌI...");
            btnCall.setBackground(GOOGLE_YELLOW);
            addMessageBubble("SYSTEM", "📞 Đang quay số...", false, true);
            sendSignal(PACKET_CALL_REQ); // Gửi yêu cầu kết nối
        }
    }

    // 2. Gửi tín hiệu điều khiển (Signaling)
    private void sendSignal(int type) {
        try {
            // Payload rỗng hoặc chứa tên, nhưng ở đây gửi rỗng cho nhanh (0 byte)
            sendUDPPacket(type, new byte[0]); 
        } catch (Exception e) { e.printStackTrace(); }
    }

    // 3. Xử lý khi nhận được tín hiệu (Tại UDP Listener)
    private void handleIncomingSignal(int type, String senderKey) {
        SwingUtilities.invokeLater(() -> {
            switch(type) {
                case PACKET_CALL_REQ: // Có người gọi đến
                    if (isCallActive || isDialing) {
                        // Đang bận -> Tự động từ chối
                        sendSignal(PACKET_CALL_REJECT);
                    } else {
                        // Hiện Popup hỏi
                        int choice = JOptionPane.showConfirmDialog(this, 
                            "📞 CUỘC GỌI ĐẾN!\n\nTừ IP: " + senderKey + "\nBạn có muốn nghe máy không?", 
                            "Incoming Call", JOptionPane.YES_NO_OPTION);
                        
                        if (choice == JOptionPane.YES_OPTION) {
                            // CHẤP NHẬN
                            sendSignal(PACKET_CALL_ACCEPT);
                            startAudioStreams(); // Bắt đầu thu/phát
                            isCallActive = true;
                            btnCall.setText("📴 DỪNG GỌI");
                            btnCall.setBackground(GOOGLE_RED);
                            addMessageBubble("SYSTEM", "✅ Cuộc gọi đã kết nối!", false, true);
                        } else {
                            // TỪ CHỐI
                            sendSignal(PACKET_CALL_REJECT);
                            addMessageBubble("SYSTEM", "🚫 Bạn đã từ chối cuộc gọi.", false, true);
                        }
                    }
                    break;

                case PACKET_CALL_ACCEPT: // Bên kia đã đồng ý
                    if (isDialing) {
                        isDialing = false;
                        isCallActive = true;
                        startAudioStreams(); // Bắt đầu thu/phát
                        btnCall.setText("📴 DỪNG GỌI");
                        btnCall.setBackground(GOOGLE_RED);
                        addMessageBubble("SYSTEM", "✅ Đối phương đã nghe máy!", false, true);
                    }
                    break;

                case PACKET_CALL_REJECT: // Bên kia từ chối
                    isDialing = false;
                    btnCall.setText("📞 GỌI ĐIỆN");
                    btnCall.setBackground(GOOGLE_GREEN);
                    addMessageBubble("SYSTEM", "🚫 Đối phương đang bận hoặc từ chối.", false, true);
                    break;

                case PACKET_CALL_END: // Bên kia cúp máy
                    endCallLocally("📴 Đối phương đã tắt máy.");
                    break;
            }
        });
    }

    // 4. Kết thúc cuộc gọi tại máy mình
    private void endCallLocally(String msg) {
        isCallActive = false;
        isDialing = false;
        btnCall.setText("📞 GỌI ĐIỆN");
        btnCall.setBackground(GOOGLE_GREEN);
        
        // Tắt Mic & Loa
        if(microphone != null) { microphone.close(); microphone = null; }
        if(speakers != null) { speakers.close(); speakers = null; }
        
        addMessageBubble("SYSTEM", msg, false, true);
    }

    // 5. Khởi động luồng Âm thanh (Chỉ chạy khi 2 bên đã ACCEPT)
    private void startAudioStreams() {
        // Thread Thu Âm (Gửi đi)
        new Thread(() -> {
            try {
                AudioFormat format = new AudioFormat(8000.0f, 16, 1, true, true);
                DataLine.Info info = new DataLine.Info(TargetDataLine.class, format);
                if (!AudioSystem.isLineSupported(info)) return;
                
                microphone = (TargetDataLine) AudioSystem.getLine(info);
                microphone.open(format);
                microphone.start();

                byte[] buffer = new byte[AUDIO_CHUNK_SIZE];
                char[] pass = txtNetPass.getPassword();

                while (isCallActive && isRunning && microphone != null && microphone.isOpen()) {
                    int count = microphone.read(buffer, 0, buffer.length);
                    if (count > 0) {
                        byte[] pcm = Arrays.copyOf(buffer, count);
                        // Encrypt audio (1 Layer)
                        byte[] encData = encryptData1Layer(pcm, pass);
                        sendUDPPacket(PACKET_VOICE, encData);
                    }
                }
            } catch (Exception e) { e.printStackTrace(); }
        }).start();

        // Loa (Nhận) sẽ được khởi tạo khi gói tin VOICE đầu tiên đến hoặc init trước
        try {
            AudioFormat format = new AudioFormat(8000.0f, 16, 1, true, true);
            DataLine.Info info = new DataLine.Info(SourceDataLine.class, format);
            speakers = (SourceDataLine) AudioSystem.getLine(info);
            speakers.open(format);
            speakers.start();
        } catch(Exception e) { e.printStackTrace(); }
    }

    // 6. Phát âm thanh khi nhận gói tin VOICE
    private void playAudioPacket(byte[] encData) {
        if (!isCallActive) return; // Nếu chưa kết nối thì không phát tiếng (tránh nghe lén)
        try {
            if(speakers == null || !speakers.isOpen()) {
                // Re-init if needed
                AudioFormat format = new AudioFormat(8000.0f, 16, 1, true, true);
                speakers = (SourceDataLine) AudioSystem.getLine(new DataLine.Info(SourceDataLine.class, format));
                speakers.open(format);
                speakers.start();
            }
            char[] pass = txtNetPass.getPassword();
            byte[] pcmData = decryptData1Layer(encData, pass);
            speakers.write(pcmData, 0, pcmData.length);
        } catch (Exception e) {}
    }


    // =========================================================================
    // CORE NETWORK LOGIC
    // =========================================================================
    
    private void disconnect() {
        if(isCallActive) sendSignal(PACKET_CALL_END);
        isRunning = false; 
        endCallLocally("Ngắt kết nối mạng.");
        try { if (tcpSocket != null) tcpSocket.close(); if (udpSocket != null) udpSocket.close(); } catch (Exception e) {}
        SwingUtilities.invokeLater(() -> {
            lblNetStatus.setText("OFFLINE"); lblNetStatus.setForeground(GOOGLE_RED);
            btnHost.setEnabled(true); btnConnect.setEnabled(true); btnDisconnect.setEnabled(false); cmbProtocol.setEnabled(true); btnCall.setEnabled(false);
        });
    }

    private void listenUDP() {
        byte[] buf = new byte[65000];
        try {
            while(isRunning) {
                DatagramPacket p = new DatagramPacket(buf, buf.length);
                udpSocket.receive(p);
                String key = p.getAddress().getHostAddress() + ":" + p.getPort();
                
                // Add peer if new
                if(!knownPeers.containsKey(key)) {
                    knownPeers.put(key, new InetSocketAddress(p.getAddress(), p.getPort()));
                    SwingUtilities.invokeLater(()->cmbTarget.addItem(key));
                }
                
                // Parse Packet
                byte[] receivedData = Arrays.copyOf(p.getData(), p.getLength());
                ByteBuffer bb = ByteBuffer.wrap(receivedData);
                if(bb.remaining()<4) continue;
                int type = bb.getInt();
                byte[] payload = new byte[bb.remaining()];
                bb.get(payload);

                // Dispatch
                if (type == PACKET_VOICE) {
                    playAudioPacket(payload);
                } else if (type >= 10 && type <= 13) {
                    handleIncomingSignal(type, key);
                } else {
                    processUDPPayload(type, payload, key);
                }
            }
        } catch(IOException e) { if(isRunning) updateNetStatus("UDP Stopped", GOOGLE_RED); }
    }

    private void sendNetFile() {
        if (!isRunning) return;
        JFileChooser fc = new JFileChooser();
        if(fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File f = fc.getSelectedFile();
            if (f.length() > MAX_FILE_SIZE) { JOptionPane.showMessageDialog(this, "File > 50MB quá lớn!"); return; }
            new Thread(()->{
                try {
                    char[] pass = txtNetPass.getPassword();
                    String nick = txtNickName.getText().isEmpty() ? "Anon" : txtNickName.getText();
                    String metaMsg = nick + MSG_SEPARATOR + "📎 Đang gửi file: " + f.getName();
                    byte[] encMeta = encryptData7Layers(metaMsg.getBytes(StandardCharsets.UTF_8), pass);
                    
                    if(isUDP) {
                        sendUDPPacket(PACKET_MSG, encMeta);
                        byte[] encName = encryptData7Layers(f.getName().getBytes(StandardCharsets.UTF_8), pass);
                        sendUDPPacket(PACKET_UDP_FILE_START, encName);
                        try(FileInputStream fis = new FileInputStream(f)) {
                            byte[] buffer = new byte[UDP_CHUNK_SIZE]; int bytesRead;
                            while ((bytesRead = fis.read(buffer)) != -1) {
                                sendUDPPacket(PACKET_UDP_FILE_DATA, encryptData7Layers(Arrays.copyOf(buffer, bytesRead), pass));
                                Thread.sleep(2); 
                            }
                        }
                        sendUDPPacket(PACKET_UDP_FILE_END, new byte[0]);
                        addMessageBubble("Tôi", "Đã bắn file UDP: " + f.getName(), true, false);
                    } else {
                        synchronized(tcpOut) {
                            tcpOut.writeInt(PACKET_MSG); tcpOut.writeInt(encMeta.length); tcpOut.write(encMeta);
                            byte[] encName = encryptData7Layers(f.getName().getBytes(StandardCharsets.UTF_8), pass);
                            tcpOut.writeInt(PACKET_FILE_TCP); tcpOut.writeInt(encName.length); tcpOut.write(encName);
                            File tmp = File.createTempFile("send", ".tmp"); cryptStream(f, tmp, pass, true);
                            tcpOut.writeLong(tmp.length());
                            try(FileInputStream fis=new FileInputStream(tmp)){ byte[] b=new byte[4096]; int r; while((r=fis.read(b))!=-1) tcpOut.write(b,0,r); }
                            tmp.delete();
                        }
                        addMessageBubble("Tôi", "Đã gửi file TCP: " + f.getName(), true, false);
                    }
                } catch(Exception e) { e.printStackTrace(); addMessageBubble("SYSTEM", "Lỗi gửi file: " + e.getMessage(), false, true); }
            }).start();
        }
    }
    
    private void sendUDPPacket(int type, byte[] data) throws IOException {
        ByteBuffer bb = ByteBuffer.allocate(4 + data.length);
        bb.putInt(type); bb.put(data); byte[] payload = bb.array();
        String target = (String) cmbTarget.getSelectedItem();
        if(TARGET_ALL.equals(target)) {
            for(InetSocketAddress addr : knownPeers.values()) udpSocket.send(new DatagramPacket(payload, payload.length, addr.getAddress(), addr.getPort()));
        } else {
            InetSocketAddress addr = knownPeers.get(target);
            if(addr!=null) udpSocket.send(new DatagramPacket(payload, payload.length, addr.getAddress(), addr.getPort()));
        }
    }

    private void processUDPPayload(int type, byte[] payload, String senderKey) {
        try {
            char[] pass = txtNetPass.getPassword();
            if (type == PACKET_MSG) {
                String fullStr = new String(decryptData7Layers(payload, pass), StandardCharsets.UTF_8);
                String[] parts = fullStr.split(java.util.regex.Pattern.quote(MSG_SEPARATOR));
                addMessageBubble(parts.length > 0 ? parts[0] : senderKey, parts.length > 1 ? parts[1] : fullStr, false, false);
            } else if (type == PACKET_UDP_FILE_START) {
                String fileName = new String(decryptData7Layers(payload, pass), StandardCharsets.UTF_8);
                File f = new File("UDP_RECV_" + System.currentTimeMillis() + "_" + fileName);
                udpFileReceivers.put(senderKey, new FileOutputStream(f, true));
                udpFileNames.put(senderKey, f.getAbsolutePath());
            } else if (type == PACKET_UDP_FILE_DATA) {
                FileOutputStream fos = udpFileReceivers.get(senderKey);
                if (fos != null) fos.write(decryptData7Layers(payload, pass));
            } else if (type == PACKET_UDP_FILE_END) {
                FileOutputStream fos = udpFileReceivers.get(senderKey);
                if (fos != null) { fos.close(); udpFileReceivers.remove(senderKey); addMessageBubble(senderKey, "✅ Đã nhận file: " + udpFileNames.get(senderKey), false, false); }
            }
        } catch (Exception e) {}
    }
    
    private void listenTCP() {
        try {
            while(isRunning) {
                int type = tcpIn.readInt();
                if(type == PACKET_MSG) {
                    int len = tcpIn.readInt(); byte[] data = new byte[len]; tcpIn.readFully(data);
                    String fullStr = new String(decryptData7Layers(data, txtNetPass.getPassword()), StandardCharsets.UTF_8);
                    String[] parts = fullStr.split(java.util.regex.Pattern.quote(MSG_SEPARATOR));
                    addMessageBubble(parts.length > 0 ? parts[0] : "TCP", parts.length > 1 ? parts[1] : fullStr, false, false);
                } else if (type == PACKET_FILE_TCP) {
                    int nLen = tcpIn.readInt(); byte[] nEnc = new byte[nLen]; tcpIn.readFully(nEnc);
                    String fName = new String(decryptData7Layers(nEnc, txtNetPass.getPassword()), StandardCharsets.UTF_8);
                    long fLen = tcpIn.readLong();
                    File tmp = File.createTempFile("recv", ".tmp");
                    try(FileOutputStream fos=new FileOutputStream(tmp)){ byte[] b=new byte[4096]; long rem=fLen; while(rem>0){ int r = tcpIn.read(b,0,(int)Math.min(b.length, rem)); if(r==-1) break; fos.write(b,0,r); rem-=r; } }
                    File finalF = new File("TCP_RECV_" + System.currentTimeMillis() + "_" + fName);
                    cryptStream(tmp, finalF, txtNetPass.getPassword(), false); tmp.delete();
                    addMessageBubble("TCP Peer", "✅ Đã nhận file: " + finalF.getAbsolutePath(), false, false);
                }
            }
        } catch(IOException e) { if(isRunning) updateNetStatus("TCP Disconnected", GOOGLE_RED); } catch (Exception e) { e.printStackTrace(); }
    }

    private void startServer() { new Thread(() -> { try { int port = Integer.parseInt(txtPort.getText()); isUDP = cmbProtocol.getSelectedItem().toString().contains("UDP"); if (isUDP) { udpSocket = new DatagramSocket(port); updateNetStatus("Listening UDP " + port, GOOGLE_GREEN); connectionReady(); } else { ServerSocket ss = new ServerSocket(port); updateNetStatus("Waiting TCP...", GOOGLE_YELLOW); tcpSocket = ss.accept(); tcpOut = new DataOutputStream(tcpSocket.getOutputStream()); tcpIn = new DataInputStream(tcpSocket.getInputStream()); connectionReady(); } } catch (Exception e) { updateNetStatus("Error: " + e.getMessage(), GOOGLE_RED); } }).start(); }
    private void startClient() { new Thread(() -> { try { String ip = txtIp.getText(); int port = Integer.parseInt(txtPort.getText()); isUDP = cmbProtocol.getSelectedItem().toString().contains("UDP"); if (isUDP) { udpSocket = new DatagramSocket(); String key = ip + ":" + port; knownPeers.put(key, new InetSocketAddress(ip, port)); SwingUtilities.invokeLater(() -> { if(cmbTarget.getItemCount()>1) cmbTarget.removeItemAt(1); cmbTarget.addItem(key); cmbTarget.setSelectedItem(key); }); updateNetStatus("UDP Ready", GOOGLE_GREEN); connectionReady(); } else { updateNetStatus("Connecting TCP...", GOOGLE_YELLOW); tcpSocket = new Socket(ip, port); tcpOut = new DataOutputStream(tcpSocket.getOutputStream()); tcpIn = new DataInputStream(tcpSocket.getInputStream()); connectionReady(); } } catch (Exception e) { updateNetStatus("Error: " + e.getMessage(), GOOGLE_RED); } }).start(); }
    private void connectionReady() { SwingUtilities.invokeLater(() -> { lblNetStatus.setText("ONLINE"); lblNetStatus.setForeground(GOOGLE_GREEN); btnHost.setEnabled(false); btnConnect.setEnabled(false); btnDisconnect.setEnabled(true); cmbProtocol.setEnabled(false); cmbTarget.setEnabled(isUDP); if(isUDP) btnCall.setEnabled(true); }); isRunning = true; new Thread(isUDP ? this::listenUDP : this::listenTCP).start(); }
    private void updateNetStatus(String msg, Color c) { SwingUtilities.invokeLater(() -> { lblNetStatus.setText(msg); lblNetStatus.setForeground(c); addMessageBubble("SYSTEM", msg, false, true); }); }
    private void sendNetMessage() { if (!isRunning) return; String msg = txtChatInput.getText(); if (msg.trim().isEmpty()) return; String nick = txtNickName.getText().trim(); if(nick.isEmpty()) nick = "Anon"; String finalPayload = nick + MSG_SEPARATOR + msg; try { char[] pass = txtNetPass.getPassword(); if(pass.length == 0) { JOptionPane.showMessageDialog(this, "Nhập Key!"); return; } byte[] enc = encryptData7Layers(finalPayload.getBytes(StandardCharsets.UTF_8), pass); if (isUDP) sendUDPPacket(PACKET_MSG, enc); else synchronized(tcpOut) { tcpOut.writeInt(PACKET_MSG); tcpOut.writeInt(enc.length); tcpOut.write(enc); tcpOut.flush(); } addMessageBubble("Tôi", msg, true, false); txtChatInput.setText(""); } catch (Exception e) { addMessageBubble("SYSTEM", "Err: " + e.getMessage(), false, true); } }

    // =========================================================================
    // CRYPTO & UTILS
    // =========================================================================
    private String generateSecureString() { SecureRandom r=new SecureRandom(); StringBuilder s=new StringBuilder(64); String c="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"; for(int i=0;i<64;i++)s.append(c.charAt(r.nextInt(c.length()))); return s.toString(); }
    private void generateAndSaveKey(JPasswordField f) { String key = generateSecureString(); f.setText(key); try { String timeStamp = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss").format(new Date()); String fileName = "SecretKey_" + timeStamp + ".txt"; File file = new File(fileName); try (PrintWriter out = new PrintWriter(file)) { out.println("=== MILITARY CRYPTO SUITE KEY ==="); out.println("KEY: " + key); } JOptionPane.showMessageDialog(this, "✅ Đã lưu Key tại:\n" + file.getAbsolutePath()); } catch (Exception e) {} }
    private void handleMsgCrypto(boolean e) { try { if(e) msgOutput.setText(Base64.getEncoder().encodeToString(encryptData7Layers(msgInput.getText().getBytes(), msgPass.getPassword()))); else msgOutput.setText(new String(decryptData7Layers(Base64.getDecoder().decode(msgInput.getText()), msgPass.getPassword()))); } catch(Exception x){ JOptionPane.showMessageDialog(this, x.getMessage()); } }
    private void chooseFile(JTextField f, boolean s) { JFileChooser c=new JFileChooser(); if((s?c.showSaveDialog(this):c.showOpenDialog(this))==JFileChooser.APPROVE_OPTION) f.setText(c.getSelectedFile().getAbsolutePath()); }
    private void processFile(boolean enc) { new SwingWorker<Void,Void>(){ protected Void doInBackground() throws Exception{ statusLabel.setText("Processing..."); progressBar.setIndeterminate(true); File s=new File(srcField.getText()), d=new File(dstField.getText()); if(enc && s.isDirectory()) { File z=new File(s.getParent(), s.getName()+".zip"); zipFolder(s.toPath(), z.toPath()); cryptStream(z,d,filePass.getPassword(),true); z.delete(); } else if(!enc && d.isDirectory()) { File t=new File(d,"t.zip"); cryptStream(s,t,filePass.getPassword(),false); unzipFolder(t.toPath(),d.toPath()); t.delete(); } else cryptStream(s,d,filePass.getPassword(),enc); return null; } protected void done(){ progressBar.setIndeterminate(false); statusLabel.setText("Hoàn thành."); JOptionPane.showMessageDialog(null,"Thành công"); }}.execute(); }
    
    // Crypto Engine
    private byte[] encryptData1Layer(byte[] in, char[] p) throws Exception { byte[] s=new byte[SALT_LEN], iv=new byte[IV_LEN]; new SecureRandom().nextBytes(s); new SecureRandom().nextBytes(iv); KeyChain c=genKeys(p,s,iv, 1); Cipher ci=Cipher.getInstance(ENCRYPT_ALGO); ci.init(Cipher.ENCRYPT_MODE,c.keys.get(0),new GCMParameterSpec(TAG_LEN,c.ivs.get(0))); byte[] d=ci.doFinal(in); return ByteBuffer.allocate(s.length+iv.length+d.length).put(s).put(iv).put(d).array(); }
    private byte[] decryptData1Layer(byte[] in, char[] p) throws Exception { ByteBuffer bb=ByteBuffer.wrap(in); byte[] s=new byte[SALT_LEN]; bb.get(s); byte[] iv=new byte[IV_LEN]; bb.get(iv); byte[] d=new byte[bb.remaining()]; bb.get(d); KeyChain c=genKeys(p,s,iv, 1); Cipher ci=Cipher.getInstance(ENCRYPT_ALGO); ci.init(Cipher.DECRYPT_MODE,c.keys.get(0),new GCMParameterSpec(TAG_LEN,c.ivs.get(0))); return ci.doFinal(d); }
    private byte[] encryptData7Layers(byte[] in, char[] p) throws Exception { byte[] s=new byte[SALT_LEN], iv=new byte[IV_LEN]; new SecureRandom().nextBytes(s); new SecureRandom().nextBytes(iv); KeyChain c=genKeys(p,s,iv, LAYERS); byte[] d=in; for(int i=0;i<LAYERS;i++){ Cipher ci=Cipher.getInstance(ENCRYPT_ALGO); ci.init(Cipher.ENCRYPT_MODE,c.keys.get(i),new GCMParameterSpec(TAG_LEN,c.ivs.get(i))); d=ci.doFinal(d); } return ByteBuffer.allocate(s.length+iv.length+d.length).put(s).put(iv).put(d).array(); }
    private byte[] decryptData7Layers(byte[] in, char[] p) throws Exception { ByteBuffer bb=ByteBuffer.wrap(in); byte[] s=new byte[SALT_LEN]; bb.get(s); byte[] iv=new byte[IV_LEN]; bb.get(iv); byte[] d=new byte[bb.remaining()]; bb.get(d); KeyChain c=genKeys(p,s,iv, LAYERS); for(int i=LAYERS-1;i>=0;i--){ Cipher ci=Cipher.getInstance(ENCRYPT_ALGO); ci.init(Cipher.DECRYPT_MODE,c.keys.get(i),new GCMParameterSpec(TAG_LEN,c.ivs.get(i))); d=ci.doFinal(d); } return d; }
    private void cryptStream(File s, File d, char[] p, boolean e) throws Exception { try(FileInputStream is=new FileInputStream(s); FileOutputStream os=new FileOutputStream(d)){ byte[] sa=new byte[SALT_LEN], iv=new byte[IV_LEN]; if(e){ new SecureRandom().nextBytes(sa); new SecureRandom().nextBytes(iv); os.write(sa); os.write(iv); } else { if(is.read(sa)!=SALT_LEN || is.read(iv)!=IV_LEN) throw new IOException("Bad File"); } KeyChain c=genKeys(p,sa,iv, LAYERS); Cipher ci=Cipher.getInstance(ENCRYPT_ALGO); if(e){ OutputStream out=os; for(int i=LAYERS-1;i>=0;i--){ ci.init(Cipher.ENCRYPT_MODE,c.keys.get(i),new GCMParameterSpec(TAG_LEN,c.ivs.get(i))); out=new CipherOutputStream(out,ci); } byte[] b=new byte[4096]; int n; while((n=is.read(b))!=-1) out.write(b,0,n); out.close(); } else { InputStream in=is; for(int i=LAYERS-1;i>=0;i--){ ci.init(Cipher.DECRYPT_MODE,c.keys.get(i),new GCMParameterSpec(TAG_LEN,c.ivs.get(i))); in=new CipherInputStream(in,ci); } byte[] b=new byte[4096]; int n; while((n=in.read(b))!=-1) os.write(b,0,n); } } }
    private static class KeyChain { List<SecretKey> keys=new ArrayList<>(); List<byte[]> ivs=new ArrayList<>(); }
    private KeyChain genKeys(char[] p, byte[] s, byte[] iv, int layers) throws Exception { KeyChain c=new KeyChain(); SecretKeyFactory f=SecretKeyFactory.getInstance(KDF_ALGO); SecretKey k=new SecretKeySpec(f.generateSecret(new PBEKeySpec(p,s,ITERATIONS,256)).getEncoded(),"AES"); byte[] civ=iv; for(int i=0;i<layers;i++) { c.keys.add(k); c.ivs.add(civ); if(i<layers-1){ MessageDigest md=MessageDigest.getInstance(HASH_ALGO); k=new SecretKeySpec(md.digest(k.getEncoded()),0,32,"AES"); byte[] h=md.digest(civ); civ=new byte[IV_LEN]; System.arraycopy(h,0,civ,0,IV_LEN); } } return c; }
    private void zipFolder(Path s, Path z) throws Exception { try(ZipOutputStream zo=new ZipOutputStream(new FileOutputStream(z.toFile()))){ Files.walkFileTree(s, new SimpleFileVisitor<Path>(){ public FileVisitResult visitFile(Path f, BasicFileAttributes a) throws IOException { zo.putNextEntry(new ZipEntry(s.relativize(f).toString())); Files.copy(f,zo); zo.closeEntry(); return FileVisitResult.CONTINUE; }}); }}
    private void unzipFolder(Path z, Path t) throws Exception { try(ZipInputStream zi=new ZipInputStream(new FileInputStream(z.toFile()))){ ZipEntry e; while((e=zi.getNextEntry())!=null){ File f=new File(t.toFile(),e.getName()); if(e.isDirectory()) f.mkdirs(); else { f.getParentFile().mkdirs(); Files.copy(zi,f.toPath(),StandardCopyOption.REPLACE_EXISTING); }}}}

    // Material Helpers
    private static void setUIFont(javax.swing.plaf.FontUIResource f){ Enumeration<Object> keys = UIManager.getDefaults().keys(); while(keys.hasMoreElements()){ Object key = keys.nextElement(); Object value = UIManager.get(key); if(value instanceof javax.swing.plaf.FontUIResource) UIManager.put(key, f); } }
    private JPanel createCardPanel() { JPanel p = new JPanel(); p.setBackground(GOOGLE_SURFACE); p.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(GOOGLE_BORDER, 1), BorderFactory.createEmptyBorder(15, 15, 15, 15))); return p; }
    private JLabel createTitleLabel(String text) { JLabel l = new JLabel(text); l.setFont(new Font("Segoe UI", Font.BOLD, 18)); l.setForeground(GOOGLE_TEXT_MAIN); return l; }
    private JLabel createLabel(String text) { JLabel l = new JLabel(text); l.setForeground(GOOGLE_TEXT_SEC); return l; }
    private JPanel createFormRow(String label, Component cmp, String btnText, ActionListener action) { JPanel p = new JPanel(new BorderLayout(10, 0)); p.setBackground(GOOGLE_SURFACE); JLabel l = new JLabel(label); l.setForeground(GOOGLE_TEXT_SEC); l.setPreferredSize(new Dimension(80, 35)); p.add(l, BorderLayout.WEST); p.add(cmp, BorderLayout.CENTER); if(btnText != null) { MaterialButton b = new MaterialButton(btnText, GOOGLE_GRAY_BG, true); b.setForeground(GOOGLE_TEXT_MAIN); b.addActionListener(action); p.add(b, BorderLayout.EAST); } return p; }
    private JTextField createMaterialTextField() { JTextField t = new JTextField(); t.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(GOOGLE_BORDER), BorderFactory.createEmptyBorder(5, 10, 5, 10))); t.setFont(new Font("Segoe UI", Font.PLAIN, 14)); return t; }
    private JPasswordField createMaterialPasswordField() { JPasswordField t = new JPasswordField(); t.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(GOOGLE_BORDER), BorderFactory.createEmptyBorder(5, 10, 5, 10))); return t; }
    private JTextArea createMaterialTextArea() { JTextArea t = new JTextArea(); t.setLineWrap(true); t.setWrapStyleWord(true); t.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10)); return t; }
    private JScrollPane createMaterialScrollPane(Component v) { JScrollPane s = new JScrollPane(v); s.setBorder(BorderFactory.createLineBorder(GOOGLE_BORDER)); s.getVerticalScrollBar().setUI(new BasicScrollBarUI() { @Override protected void configureScrollBarColors() { this.thumbColor = new Color(200, 200, 200); this.trackColor = GOOGLE_GRAY_BG; } @Override protected JButton createDecreaseButton(int orientation) { return createZeroButton(); } @Override protected JButton createIncreaseButton(int orientation) { return createZeroButton(); } }); return s; }
    private JButton createZeroButton() { JButton b = new JButton(); b.setPreferredSize(new Dimension(0,0)); return b; }
    private void styleComboBox(JComboBox box) { box.setBackground(GOOGLE_SURFACE); box.setBorder(BorderFactory.createLineBorder(GOOGLE_BORDER)); ((JComponent)box.getRenderer()).setOpaque(true); }
    static class MaterialButton extends JButton { private Color bgColor; private boolean isFlat; public MaterialButton(String text, Color bg, boolean flat) { super(text); this.bgColor = bg; this.isFlat = flat; setContentAreaFilled(false); setFocusPainted(false); setBorderPainted(false); setForeground(flat ? GOOGLE_TEXT_MAIN : Color.WHITE); setFont(new Font("Segoe UI", Font.BOLD, 13)); setCursor(new Cursor(Cursor.HAND_CURSOR)); addMouseListener(new MouseAdapter() { public void mouseEntered(MouseEvent e) { bgColor = isFlat ? new Color(230,230,230) : bgColor.darker(); repaint(); } public void mouseExited(MouseEvent e) { bgColor = bg; repaint(); } }); } @Override protected void paintComponent(Graphics g) { Graphics2D g2 = (Graphics2D)g.create(); g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON); g2.setColor(isEnabled() ? bgColor : Color.LIGHT_GRAY); g2.fillRoundRect(0, 0, getWidth(), getHeight(), 8, 8); g2.dispose(); super.paintComponent(g); } }
    static class MaterialTabbedPaneUI extends BasicTabbedPaneUI { @Override protected void installDefaults() { super.installDefaults(); shadow = lightHighlight = darkShadow = focus = new Color(0,0,0,0); } @Override protected void paintTabBorder(Graphics g, int tabPlacement, int tabIndex, int x, int y, int w, int h, boolean isSelected) {} @Override protected void paintTabBackground(Graphics g, int tabPlacement, int tabIndex, int x, int y, int w, int h, boolean isSelected) { g.setColor(isSelected ? new Color(232, 240, 254) : GOOGLE_SURFACE); g.fillRect(x, y, w, h); if (isSelected) { g.setColor(GOOGLE_BLUE); g.fillRect(x, h - 3, w, 3); } } }
    private void addMessageBubble(String sender, String msg, boolean isMe, boolean isSys) { SwingUtilities.invokeLater(() -> { JPanel wrapper = new JPanel(new BorderLayout()); wrapper.setBackground(Color.WHITE); wrapper.setBorder(new EmptyBorder(5, 10, 5, 10)); JPanel bubble = new JPanel() { @Override protected void paintComponent(Graphics g) { Graphics2D g2 = (Graphics2D) g; g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON); g2.setColor(isSys ? GOOGLE_YELLOW : (isMe ? GOOGLE_BLUE : new Color(241, 243, 244))); g2.fillRoundRect(0, 0, getWidth(), getHeight(), 18, 18); super.paintComponent(g); } }; bubble.setOpaque(false); bubble.setLayout(new BorderLayout(5, 5)); bubble.setBorder(new EmptyBorder(10, 15, 10, 15)); if (!isMe && !isSys) { JLabel name = new JLabel(sender); name.setFont(new Font("Segoe UI", Font.BOLD, 10)); name.setForeground(GOOGLE_TEXT_SEC); bubble.add(name, BorderLayout.NORTH); } JTextArea text = new JTextArea(msg); text.setOpaque(false); text.setEditable(false); text.setFont(new Font("Segoe UI", Font.PLAIN, 14)); text.setForeground(isSys ? Color.BLACK : (isMe ? Color.WHITE : GOOGLE_TEXT_MAIN)); text.setLineWrap(true); text.setWrapStyleWord(true); int maxWidth = (int) (chatScrollPane.getWidth() * 0.7); text.setSize(new Dimension(maxWidth, Short.MAX_VALUE)); bubble.add(text, BorderLayout.CENTER); JPanel alignPanel = new JPanel(new FlowLayout(isSys ? FlowLayout.CENTER : (isMe ? FlowLayout.RIGHT : FlowLayout.LEFT))); alignPanel.setBackground(Color.WHITE); alignPanel.add(bubble); wrapper.add(alignPanel, BorderLayout.CENTER); chatBody.add(wrapper); chatBody.revalidate(); JScrollBar vertical = chatScrollPane.getVerticalScrollBar(); vertical.setValue(vertical.getMaximum()); }); }

    public static void main(String[] args) { try { UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName()); } catch (Exception e) {} SwingUtilities.invokeLater(() -> new GoogleStyleCryptoSuiteNET().setVisible(true)); }
}