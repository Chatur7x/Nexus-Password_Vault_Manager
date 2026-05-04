import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.*;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.Timer;
import java.util.TimerTask;

public class VaultApp extends JFrame {
    private String masterPassword;
    private DefaultTableModel tableModel;
    private File pythonScript;
    private Timer lockTimer;
    private static final int LOCK_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

    public VaultApp() {
        super("Pass-Vault-Manager (Advanced)");
        pythonScript = new File("../cli-python/manager.py");
        if (!pythonScript.exists()) {
            JOptionPane.showMessageDialog(this, "Could not locate python CLI script.", "Error", JOptionPane.ERROR_MESSAGE);
            System.exit(1);
        }

        promptMasterPassword();
        initUI();
        refreshTable();
        startAutoLockTimer();
    }

    private void promptMasterPassword() {
        JPasswordField pf = new JPasswordField();
        final long[] lastKeyTime = {0};
        final java.util.List<Long> flightTimes = new java.util.ArrayList<>();
        
        pf.addKeyListener(new KeyAdapter() {
            @Override
            public void keyTyped(KeyEvent e) {
                long now = System.currentTimeMillis();
                if (lastKeyTime[0] != 0) {
                    flightTimes.add(now - lastKeyTime[0]);
                }
                lastKeyTime[0] = now;
            }
        });

        int okCxl = JOptionPane.showConfirmDialog(null, pf, "Enter Master Password:", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (okCxl == JOptionPane.OK_OPTION) {
            // Analyze Keystroke Dynamics
            if (flightTimes.size() > 2) {
                long total = 0;
                for (Long t : flightTimes) total += t;
                long avg = total / flightTimes.size();
                
                // If typed faster than 40ms per key, it's a script/macro!
                if (avg < 40) {
                    JOptionPane.showMessageDialog(null, "🚨 BIO-METRIC REJECTION 🚨\nRobotic typing speed detected! Access Denied.", "Security Alert", JOptionPane.ERROR_MESSAGE);
                    System.exit(1);
                }
            }
            masterPassword = new String(pf.getPassword());
        } else {
            System.exit(0);
        }
    }

    private void startAutoLockTimer() {
        if (lockTimer != null) lockTimer.cancel();
        lockTimer = new Timer(true);
        lockTimer.schedule(new TimerTask() {
            @Override
            public void run() {
                SwingUtilities.invokeLater(() -> {
                    // Lock the vault
                    masterPassword = null;
                    tableModel.setRowCount(0);
                    JOptionPane.showMessageDialog(VaultApp.this, "Vault locked due to inactivity.", "Locked", JOptionPane.WARNING_MESSAGE);
                    promptMasterPassword();
                    refreshTable();
                    startAutoLockTimer();
                });
            }
        }, LOCK_TIMEOUT_MS);
    }

    private void resetTimer() {
        startAutoLockTimer();
    }

    private void initUI() {
        setSize(550, 450);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        // Reset timer on user interaction
        Toolkit.getDefaultToolkit().addAWTEventListener(event -> resetTimer(), 
            AWTEvent.KEY_EVENT_MASK | AWTEvent.MOUSE_EVENT_MASK | AWTEvent.MOUSE_MOTION_EVENT_MASK);

        String[] columnNames = {"Service Title"};
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        JTable table = new JTable(tableModel);
        
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && table.getSelectedRow() != -1) {
                String title = (String) table.getValueAt(table.getSelectedRow(), 0);
                showPasswordDetails(title);
            }
        });

        add(new JScrollPane(table), BorderLayout.CENTER);

        JPanel bottomPanel = new JPanel();
        JButton btnAdd = new JButton("Add Password");
        JButton btnHealth = new JButton("Check Health");
        JButton btnRefresh = new JButton("Refresh");

        btnAdd.addActionListener(this::onAddPassword);
        btnHealth.addActionListener(e -> checkPasswordHealth());
        btnRefresh.addActionListener(e -> refreshTable());

        bottomPanel.add(btnAdd);
        bottomPanel.add(btnHealth);
        bottomPanel.add(btnRefresh);

        add(bottomPanel, BorderLayout.SOUTH);
    }

    private void refreshTable() {
        if (masterPassword == null) return;
        tableModel.setRowCount(0);
        try {
            ProcessBuilder pb = new ProcessBuilder("python", pythonScript.getAbsolutePath(), "list");
            pb.environment().put("MASTER_PASS", masterPassword);
            Process p = pb.start();
            
            BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            boolean startParsing = false;
            while ((line = in.readLine()) != null) {
                if (line.startsWith("Error decrypting") || line.contains("MAC Verification Failed")) {
                    masterPassword = null;
                    JOptionPane.showMessageDialog(this, "Incorrect Password or Data is Tampered!", "Error", JOptionPane.ERROR_MESSAGE);
                    System.exit(1);
                }
                if (startParsing && line.startsWith(" - ")) {
                    tableModel.addRow(new Object[]{line.substring(3).trim()});
                }
                if (line.equals("Saved services:")) {
                    startParsing = true;
                }
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private void showPasswordDetails(String title) {
        if (masterPassword == null) return;
        try {
            ProcessBuilder pb = new ProcessBuilder("python", pythonScript.getAbsolutePath(), "get", title);
            pb.environment().put("MASTER_PASS", masterPassword);
            Process p = pb.start();
            
            BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            StringBuilder sb = new StringBuilder();
            String rawPass = "";
            while ((line = in.readLine()) != null) {
                sb.append(line).append("\n");
                if (line.startsWith("Pass:  ")) rawPass = line.substring(7);
            }
            
            Object[] options = {"Copy Password", "Close"};
            int choice = JOptionPane.showOptionDialog(this, sb.toString(), "Details: " + title,
                    JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE,
                    null, options, options[0]);
                    
            if (choice == 0 && !rawPass.isEmpty()) {
                copyToClipboard(rawPass);
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
    
    private void copyToClipboard(String text) {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        JOptionPane.showMessageDialog(this, "Copied! Clipboard will clear in 30 seconds.");
        
        new Timer(true).schedule(new TimerTask() {
            @Override
            public void run() {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(""), null);
            }
        }, 30 * 1000);
    }

    private void checkPasswordHealth() {
        if (masterPassword == null) return;
        try {
            ProcessBuilder pb = new ProcessBuilder("python", pythonScript.getAbsolutePath(), "health");
            pb.environment().put("MASTER_PASS", masterPassword);
            Process p = pb.start();
            
            BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = in.readLine()) != null) {
                sb.append(line).append("\n");
            }
            JOptionPane.showMessageDialog(this, sb.toString(), "Health Check (HIBP)", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private void onAddPassword(ActionEvent e) {
        JTextField titleField = new JTextField();
        JTextField userField = new JTextField();
        JPasswordField passField = new JPasswordField();
        JTextField totpField = new JTextField();
        
        Object[] message = {
            "Title:", titleField,
            "Username:", userField,
            "Password:", passField,
            "TOTP Secret (Optional):", totpField
        };

        int option = JOptionPane.showConfirmDialog(null, message, "Add New Password", JOptionPane.OK_CANCEL_OPTION);
        if (option == JOptionPane.OK_OPTION) {
            try {
                ProcessBuilder pb = new ProcessBuilder("python", pythonScript.getAbsolutePath(), "add", 
                    "--title", titleField.getText(), 
                    "--user", userField.getText(), 
                    "--password", new String(passField.getPassword()),
                    "--totp", totpField.getText()
                );
                pb.environment().put("MASTER_PASS", masterPassword);
                pb.start().waitFor();
                refreshTable();
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new VaultApp().setVisible(true);
        });
    }
}
