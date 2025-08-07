package okta;

import burp.api.montoya.MontoyaApi;
import com.google.zxing.*;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;

import javax.imageio.ImageIO;
import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.util.Base64;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

public class OktaUIInterface extends JPanel {
    private static final ScheduledExecutorService EXECUTOR_SERVICE = Executors.newSingleThreadScheduledExecutor();
    private ScheduledFuture<?> codeUpdateFuture;

    private final OktaHandler oktaHandler;
    private final MontoyaApi api;
    private final JTextField sharedSecretField;
    private final JTextField regexField;
    private final JLabel totpCodeLabel;

    public OktaUIInterface(MontoyaApi api, OktaHandler oktaHandler) {
        this.api = api;
        this.oktaHandler = oktaHandler;

        setLayout(new BorderLayout());

        // Left panel for inputs
        JPanel inputPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.fill = GridBagConstraints.HORIZONTAL;



        gbc.gridx = 0;
        JButton uploadQrButton = new JButton("Import QR");
        uploadQrButton.addActionListener(e -> processQrCode());
        inputPanel.add(uploadQrButton, gbc);

        // Shared Secret Section
        gbc.gridx = 0;
        gbc.gridy = 1;
        inputPanel.add(new JLabel("Shared Secret:"), gbc);

        gbc.gridx = 1;
        sharedSecretField = new JTextField(20);
        sharedSecretField.setEditable(true); // Allow manual update of the shared secret
        inputPanel.add(sharedSecretField, gbc);

        gbc.gridx = 2;
        JButton updateSharedSecretButton = new JButton("Update");
        updateSharedSecretButton.addActionListener(e -> updateSharedSecret());
        inputPanel.add(updateSharedSecretButton, gbc);

        // Regex Pattern Section
        gbc.gridx = 0;
        gbc.gridy = 2;
        inputPanel.add(new JLabel("Regex Pattern:"), gbc);

        gbc.gridx = 1;
        regexField = new JTextField(20);
        regexField.setText(oktaHandler.getRegex() != null ? oktaHandler.getRegex() : ""); // Default regex
        inputPanel.add(regexField, gbc);

        gbc.gridx = 2;
        JButton updateRegexButton = new JButton("Update Regex");
        updateRegexButton.addActionListener(e -> updateRegex());
        inputPanel.add(updateRegexButton, gbc);

        // Right panel for TOTP display
        JPanel totpPanel = new JPanel(new BorderLayout());
        totpPanel.setBorder(BorderFactory.createTitledBorder("TOTP Code"));

        totpCodeLabel = new JLabel("N/A", SwingConstants.CENTER);
        totpCodeLabel.setFont(new Font("Arial", Font.BOLD, 32));
        totpCodeLabel.setForeground(Color.RED);

        totpPanel.add(totpCodeLabel, BorderLayout.CENTER);

        // Add both panels to the split pane
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, inputPanel, totpPanel);
        splitPane.setDividerLocation(1000); // Adjust the divider location as needed
        add(splitPane, BorderLayout.CENTER);

        // Initialize and start the TOTP refresh timer
        initializeAuthenticator();
    }

    private void initializeAuthenticator() {
        if (codeUpdateFuture != null) {
            codeUpdateFuture.cancel(false);
            codeUpdateFuture = null;
        }
        codeUpdateFuture = EXECUTOR_SERVICE.scheduleAtFixedRate(() -> {
            try {
                String totp = oktaHandler.generateTOTP();
                SwingUtilities.invokeLater(() -> {
                    if (totp != null) {
                        totpCodeLabel.setText(totp);
                        totpCodeLabel.setForeground(Color.BLUE);
                    } else {
                        totpCodeLabel.setText("N/A");
                        totpCodeLabel.setForeground(Color.RED);
                    }
                });
            } catch (Exception e) {
                api.logging().logToError("Error updating TOTP: " + e.getMessage());
            }
        }, 0, 30, TimeUnit.SECONDS);
    }

    /**
     * Processes the uploaded QR code and extracts the shared secret.
     */
    private void processQrCode() {
        JFileChooser fileChooser = new JFileChooser();
        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try {
                // Read QR code data
                String qrCodeData = readQRCode(file);

                // Extract verification data
                OktaHandler.OktaVerifyData verifyData = oktaHandler.extractVerifyData(qrCodeData);

                // Fetch domain keys and create Okta authenticator
                String[] keys = oktaHandler.getDomainKey(verifyData.domain);
                String sharedSecret = oktaHandler.createOktaAuthenticator("iPhone15", verifyData, keys[0], keys[1]);
                sharedSecretField.setText(Base64.getEncoder().encodeToString(sharedSecret.getBytes()));

                // Set the shared secret in the handler
                oktaHandler.setSharedSecret(sharedSecret);
                initializeAuthenticator();

                // Log success
                api.logging().logToOutput("Shared secret successfully retrieved and updated.");
            } catch (Exception e) {
                // Handle errors during processing
                JOptionPane.showMessageDialog(this, "Error processing QR code: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                api.logging().logToError("Error processing QR code: " + e.getMessage());
            }
        }
    }

    /**
     * Reads and decodes the QR code from the provided file.
     *
     * @param qrFile The file containing the QR code.
     * @return The decoded text from the QR code.
     * @throws Exception If an error occurs during QR code decoding.
     */
    private String readQRCode(File qrFile) throws Exception {
        BufferedImage bufferedImage = ImageIO.read(qrFile);
        LuminanceSource source = new BufferedImageLuminanceSource(bufferedImage);
        BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));
        return new MultiFormatReader().decode(bitmap).getText();
    }

    /**
     * Updates the regex pattern in OktaHandler based on user input.
     */
    private void updateRegex() {
        String regex = regexField.getText();
        oktaHandler.setRegex(regex);
        api.logging().logToOutput("Regex pattern updated.");
    }

    /**
     * Updates the shared secret manually from the text field.
     */
    private void updateSharedSecret() {
        String secret = sharedSecretField.getText();
        oktaHandler.setSharedSecret(secret);
        sharedSecretField.setText(oktaHandler.getSharedSecretEncoded());
        initializeAuthenticator();
    }


    public void stopAuthenticator() {
        if (codeUpdateFuture != null) {
            codeUpdateFuture.cancel(false);
            EXECUTOR_SERVICE.shutdown();
        }
    }
}