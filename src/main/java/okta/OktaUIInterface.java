package okta;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.utilities.Base64Utils;
import com.google.zxing.*;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;

import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Clipboard;
import java.awt.image.BufferedImage;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;
import java.awt.Dimension;

public class OktaUIInterface extends JPanel {

    private static final ScheduledExecutorService EXECUTOR_SERVICE = Executors.newSingleThreadScheduledExecutor();
    private ScheduledFuture<?> codeUpdateFuture;

    private final OktaHandler oktaHandler;
    private final MontoyaApi api;
    private final Base64Utils base64Utils;
    private final JTextField sharedSecretField;
    private final JTextField regexField;
    private final CircularProgressBar circularProgressBar;
    private final JButton copyTotpButton;

    public OktaUIInterface(MontoyaApi api, OktaHandler oktaHandler) {
        this.api = api;
        this.oktaHandler = oktaHandler;
        this.base64Utils = api.utilities().base64Utils();

        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // ========== INPUT PANEL ==========
        JPanel inputPanel = new JPanel(new GridBagLayout());
        inputPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.GRAY), "Okta Configuration", TitledBorder.LEFT, TitledBorder.TOP));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 8, 8, 8);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // QR Button
        gbc.gridx = 0;
        gbc.gridy = 0;
        ImageIcon qrIcon = null;
        try {
            java.net.URL iconURL = getClass().getResource("/qr-code.png");
            if (iconURL != null) {
                Image img = new ImageIcon(iconURL).getImage().getScaledInstance(20, 20, Image.SCALE_SMOOTH);
                qrIcon = new ImageIcon(img);
            } else {
                api.logging().logToError("QR icon not found in resources.");
            }
        } catch (Exception ex) {
            api.logging().logToError("Failed to load QR icon: " + ex.getMessage());
        }
        JButton uploadQrButton = new JButton("Import QR", qrIcon);
        uploadQrButton.setHorizontalTextPosition(SwingConstants.RIGHT);
        uploadQrButton.addActionListener(e -> showQrFileChooser());
        inputPanel.add(uploadQrButton, gbc);

        // Shared Secret
        gbc.gridy = 1;
        inputPanel.add(new JLabel("Shared Secret:"), gbc);

        gbc.gridx = 1;
        sharedSecretField = new JTextField(20);
        inputPanel.add(sharedSecretField, gbc);

        gbc.gridx = 2;
        JButton updateSecretButton = new JButton("Add");
        updateSecretButton.addActionListener(e -> updateSharedSecret());
        inputPanel.add(updateSecretButton, gbc);

        // Regex Pattern
        gbc.gridx = 0;
        gbc.gridy = 2;
        inputPanel.add(new JLabel("Regex Pattern:"), gbc);

        gbc.gridx = 1;
        regexField = new JTextField(20);
        regexField.setText(oktaHandler.getRegex() != null ? oktaHandler.getRegex() : "");
        inputPanel.add(regexField, gbc);

        gbc.gridx = 2;
        JButton updateRegexButton = new JButton("Update Regex");
        updateRegexButton.addActionListener(e -> updateRegex());
        inputPanel.add(updateRegexButton, gbc);

        // ========== TOTP PANEL ==========
        JPanel totpPanel = new JPanel(new BorderLayout());
        totpPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.GRAY), "TOTP Code", TitledBorder.LEFT, TitledBorder.TOP));

        circularProgressBar = new CircularProgressBar();
        circularProgressBar.setPreferredSize(new Dimension(200, 200));

        JPanel donutPanel = new JPanel(new GridBagLayout());
        donutPanel.add(circularProgressBar);

        JPanel centerPanel = new JPanel(new BorderLayout());
        centerPanel.add(donutPanel, BorderLayout.CENTER);

        // Copy Button
        copyTotpButton = new JButton("Copy TOTP");
        copyTotpButton.setEnabled(false);
        copyTotpButton.addActionListener(e -> {
            String totp = circularProgressBar.getTotpCode();
            StringSelection selection = new StringSelection(totp);
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(selection, null);
            api.logging().logToOutput("TOTP code copied to clipboard.");
        });

        JPanel copyButtonPanel = new JPanel();
        copyButtonPanel.setBorder(BorderFactory.createEmptyBorder(10, 0, 10, 0));
        copyButtonPanel.add(copyTotpButton);
        centerPanel.add(copyButtonPanel, BorderLayout.SOUTH);

        totpPanel.add(centerPanel, BorderLayout.CENTER);

        // Combine Panels
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, inputPanel, totpPanel);
        splitPane.setDividerLocation(750);
        add(splitPane, BorderLayout.CENTER);
    }

    private void showQrFileChooser() {
        JFileChooser fileChooser = new JFileChooser();
        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            new QrProcessingWorker(file).execute();
        }
    }

    private class QrProcessingWorker extends SwingWorker<Void, Void> {
        private final File qrFile;
        private String errorMessage = null;

        QrProcessingWorker(File file) {
            this.qrFile = file;
        }

        @Override
        protected Void doInBackground() {
            try {
                String qrCodeData = readQRCode(qrFile);
                OktaHandler.OktaVerifyData verifyData = oktaHandler.extractVerifyData(qrCodeData);
                String[] keys = oktaHandler.getDomainKey(verifyData.domain);
                String sharedSecret = oktaHandler.createOktaAuthenticator("Burp", verifyData, keys[0], keys[1]);

                ByteArray secretBytes = ByteArray.byteArray(sharedSecret.getBytes(StandardCharsets.UTF_8));
                String encodedSecret = base64Utils.encodeToString(secretBytes);

                oktaHandler.setSharedSecret(sharedSecret);

                SwingUtilities.invokeLater(() -> {
                    sharedSecretField.setText(encodedSecret);
                    initializeAuthenticator();
                    api.logging().logToOutput("Shared secret updated.");
                });
            } catch (Exception e) {
                errorMessage = e.getMessage();
                api.logging().logToError("QR code error: " + errorMessage);
            }
            return null;
        }

        @Override
        protected void done() {
            if (errorMessage != null) {
                JOptionPane.showMessageDialog(OktaUIInterface.this,
                        "QR code error: " + errorMessage, "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private String readQRCode(File qrFile) throws Exception {
        BufferedImage bufferedImage = ImageIO.read(qrFile);
        LuminanceSource source = new BufferedImageLuminanceSource(bufferedImage);
        BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));
        return new MultiFormatReader().decode(bitmap).getText();
    }

    private void updateRegex() {
        String regex = regexField.getText();
        oktaHandler.setRegex(regex);
        api.logging().logToOutput("Regex updated.");
    }

    private void updateSharedSecret() {
        String secret = sharedSecretField.getText();
        oktaHandler.setSharedSecret(secret);
        sharedSecretField.setText(oktaHandler.getSharedSecretEncoded());
        initializeAuthenticator();
    }

    private void initializeAuthenticator() {
        if (codeUpdateFuture != null) {
            codeUpdateFuture.cancel(false);
        }

        String sharedSecret = oktaHandler.getSharedSecretEncoded();
        if (sharedSecret == null || sharedSecret.isEmpty()) {
            circularProgressBar.setProgress(0);
            circularProgressBar.repaint();
            copyTotpButton.setEnabled(false);
            return;
        }

        copyTotpButton.setEnabled(true);

        codeUpdateFuture = Executors.newSingleThreadScheduledExecutor().scheduleAtFixedRate(() -> {
            try {
                long currentTimeMillis = System.currentTimeMillis();
                long timeStep = 30;
                long timeSinceEpoch = currentTimeMillis / 1000;
                long remaining = timeStep - (timeSinceEpoch % timeStep);
                int progressPercent = (int) ((timeStep - remaining) * 100 / timeStep);
                String totp = oktaHandler.generateTOTP();

                SwingUtilities.invokeLater(() -> {
                    if (totp != null) {
                        circularProgressBar.setTotpCode(totp);
                    }
                    circularProgressBar.setProgress(progressPercent);
                    circularProgressBar.setSecondsRemaining((int) remaining);
                    circularProgressBar.repaint();
                });

            } catch (Exception e) {
                api.logging().logToError("TOTP Update Error: " + e.getMessage());
            }
        }, 0, 1, TimeUnit.SECONDS);
    }

    public void stopAuthenticator() {
        if (codeUpdateFuture != null) {
            codeUpdateFuture.cancel(false);
            EXECUTOR_SERVICE.shutdown();
        }
    }

    static class CircularProgressBar extends JComponent {
        private int progress = 0;
        private String totpCode = "------";
        private int secondsRemaining = 30;

        public void setProgress(int progress) {
            this.progress = progress;
        }

        public void setTotpCode(String code) {
            this.totpCode = code;
        }

        public void setSecondsRemaining(int seconds) {
            this.secondsRemaining = seconds;
        }

        public String getTotpCode() {
            return this.totpCode;
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            int size = Math.min(getWidth(), getHeight()) - 20;
            int x = (getWidth() - size) / 2;
            int y = (getHeight() - size) / 2;

            Graphics2D g2 = (Graphics2D) g;
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

            g2.setColor(Color.LIGHT_GRAY);
            g2.setStroke(new BasicStroke(14));
            g2.drawOval(x, y, size, size);

            g2.setColor(new Color(0x4285F4));
            g2.setStroke(new BasicStroke(14));
            int angle = (int) (360 * (progress / 100.0));
            g2.drawArc(x, y, size, size, 90, -angle);

            g2.setColor(Color.BLACK);
            g2.setFont(new Font("Arial", Font.BOLD, 36));
            FontMetrics fm = g2.getFontMetrics();
            int codeWidth = fm.stringWidth(totpCode);
            g2.drawString(totpCode, getWidth() / 2 - codeWidth / 2, getHeight() / 2 - 5);

            g2.setColor(Color.GRAY);
            g2.setFont(new Font("Arial", Font.PLAIN, 16));
            String secText = secondsRemaining + " seconds left";
            int secWidth = g2.getFontMetrics().stringWidth(secText);
            g2.drawString(secText, getWidth() / 2 - secWidth / 2, getHeight() / 2 + 25);
        }
    }
}
