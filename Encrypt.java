import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.sql.*;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.KeySpec;


public class Encrypt extends JFrame {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
    private static final String KEY_STRING = "Key"; 

    private JTextField inputText;
    private JTextArea outputArea;

    public Encrypt() {
        super("Encryption and Decryption");

       
        try {
            UIManager.setLookAndFeel("javax.swing.plaf.nimbus.NimbusLookAndFeel");
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | UnsupportedLookAndFeelException e) {
            e.printStackTrace();
        }

      
        inputText = new JTextField(20);
        JButton encryptButton = new JButton("Encrypt");
        JButton decryptButton = new JButton("Decrypt");
        JButton displayButton = new JButton("Display Encrypted Texts");
        JButton deleteButton = new JButton("Delete Text from Database");
        JButton exitButton = new JButton("Exit");
        outputArea = new JTextArea(10, 30);

        setLayout(new BorderLayout());
        getContentPane().setBackground(Color.LIGHT_GRAY);

     
        JPanel inputPanel = new JPanel();
        inputPanel.setBackground(Color.LIGHT_GRAY);
        inputPanel.add(new JLabel("Enter text or ID:"));
        inputPanel.add(inputText);
        inputPanel.add(encryptButton);
        inputPanel.add(decryptButton);

       
        JPanel outputPanel = new JPanel();
        outputPanel.setBackground(Color.LIGHT_GRAY);
        outputPanel.add(new JScrollPane(outputArea));

        
      
       JPanel buttonPanel = new JPanel();
       buttonPanel.setLayout(new FlowLayout());  
       buttonPanel.setBackground(Color.LIGHT_GRAY);
       buttonPanel.add(displayButton);
       buttonPanel.add(deleteButton);
       buttonPanel.add(decryptButton);  
       buttonPanel.add(exitButton);


      
        add(inputPanel, BorderLayout.NORTH);
        add(outputPanel, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);

        Font font = new Font("Arial", Font.PLAIN, 14);
        inputText.setFont(font);
        encryptButton.setFont(font);
        decryptButton.setFont(font);
        displayButton.setFont(font);
        deleteButton.setFont(font);
        exitButton.setFont(font);
        outputArea.setFont(font);
        inputText.setBackground(Color.pink);
        outputArea.setBackground(Color.black);
        outputArea.setForeground(Color.LIGHT_GRAY);

        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                handleEncrypt();
            }
        });

        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                handleDecrypt();
            }
        });

        displayButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                handleDisplay();
            }
        });

        deleteButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                handleDelete();
            }
        });

        exitButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                System.exit(0);
            }
        });

       
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(500, 400);
        setLocationRelativeTo(null);
        setVisible(true);
    }

    private void handleEncrypt() {
        try {
            String originalText = inputText.getText();
            String encryptedText = encryptText(originalText);
            storeEncryptedTextInDatabase(encryptedText);
            outputArea.setText("Text encrypted and stored successfully");
           
        } catch (Exception ex) {
            ex.printStackTrace();
            outputArea.setText("Error during encryption");
        }
    }

    private void handleDecrypt() {
        try {
            int id = Integer.parseInt(inputText.getText());
            String decryptedText = decryptTextFromDatabase(id);
            outputArea.setText("Decrypted Text: " + decryptedText);
        } catch (Exception ex) {
            ex.printStackTrace();
            outputArea.setText("Error during decryption");
        }
    }

    private void handleDisplay() {
        displayEncryptedTextsFromDatabase(outputArea);
    }

    private void handleDelete() {
        try {
            int deleteId = Integer.parseInt(inputText.getText());
            deleteTextFromDatabase(deleteId);
        } catch (NumberFormatException e) {
            outputArea.setText("Invalid ID format");
        }
    }

    private static String encryptText(String text) throws Exception {
        SecretKey secretKey = generateKey();
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(text.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decryptText(String encryptedText) throws Exception {
        SecretKey secretKey = generateKey();
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedBytes);
    }

    private static SecretKey generateKey() throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(KEY_STRING.toCharArray(), KEY_STRING.getBytes(), 65536, 256);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), ALGORITHM);
    }
    

    private static void storeEncryptedTextInDatabase(String encryptedText) {
        String url = "jdbc:mysql://localhost:3306/miniproj";
        String username = "root";
        String password = "PHW#84#JEOR";

        try (Connection connection = DriverManager.getConnection(url, username, password)) {
            String query = "INSERT INTO encrypted_texts (encrypted_text) VALUES (?)";
            try (PreparedStatement preparedStatement = connection.prepareStatement(query)) {
                preparedStatement.setString(1, encryptedText);
                preparedStatement.executeUpdate();
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private static String decryptTextFromDatabase(int id) {
        try {
            String url = "jdbc:mysql://localhost:3306/miniproj";
            String username = "root";
            String password = "PHW#84#JEOR";

            try (Connection connection = DriverManager.getConnection(url, username, password)) {
                String query = "SELECT encrypted_text FROM encrypted_texts WHERE id = ?";
                try (PreparedStatement preparedStatement = connection.prepareStatement(query)) {
                    preparedStatement.setInt(1, id);
                    ResultSet resultSet = preparedStatement.executeQuery();

                    if (resultSet.next()) {
                        String encryptedText = resultSet.getString("encrypted_text");
                        return decryptText(encryptedText);
                    } else {
                        return "Text not found";
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            return "Error during decryption";
        }
    }

    private static void displayEncryptedTextsFromDatabase(JTextArea outputArea) {
        try {
            String url = "jdbc:mysql://localhost:3306/miniproj";
            String username = "root";
            String password = "PHW#84#JEOR";

            try (Connection connection = DriverManager.getConnection(url, username, password)) {
                String query = "SELECT id, encrypted_text FROM encrypted_texts";
                try (PreparedStatement preparedStatement = connection.prepareStatement(query)) {
                    ResultSet resultSet = preparedStatement.executeQuery();

                    StringBuilder resultText = new StringBuilder("Encrypted Texts in the Database:\n");
                    while (resultSet.next()) {
                        int id = resultSet.getInt("id");
                        String encryptedText = resultSet.getString("encrypted_text");
                        resultText.append("ID: ").append(id).append(", Encrypted Text: ").append(encryptedText).append("\n");
                    }

                    outputArea.setText(resultText.toString());
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private static void deleteTextFromDatabase(int id) {
        try {
            String url = "jdbc:mysql://localhost:3306/miniproj";
            String username = "root";
            String password = "PHW#84#JEOR";

            try (Connection connection = DriverManager.getConnection(url, username, password)) {
                String query = "DELETE FROM encrypted_texts WHERE id = ?";
                try (PreparedStatement preparedStatement = connection.prepareStatement(query)) {
                    preparedStatement.setInt(1, id);
                    int rowsAffected = preparedStatement.executeUpdate();

                    if (rowsAffected > 0) {
                        System.out.println("Text with ID " + id + " deleted successfully.");
                    } else {
                        System.out.println("Text not found with ID: " + id);
                    }
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                new Encrypt();
            }
        });
    }
}
