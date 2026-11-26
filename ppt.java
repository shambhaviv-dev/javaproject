import javax.swing.*;
import javax.swing.border.*;
import javax.swing.table.*;
import javax.swing.text.*;
import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.regex.*;
import java.util.stream.Collectors;

public final class ppt extends JFrame {
    private static final long serialVersionUID = 1L;

    // UI Components
    private JTextPane reportTextPane;
    private transient StyledDocument reportDoc;
    private JTable techniquesTable;
    private DefaultTableModel techTableModel;
    private JTable iocTable;
    private DefaultTableModel iocTableModel;
    private JPanel matrixPanel;
    private JTextArea jsonPreviewArea;
    private JTextField searchFilterField;
    private transient TableRowSorter<DefaultTableModel> tableSorter;
    private JLabel statusLabel;
    private JProgressBar analysisProgressBar;

    // Enterprise Tactics Order
    private static final String[] ENTERPRISE_TACTICS = {
            "Reconnaissance", "Initial Access", "Execution", "Persistence",
            "Privilege Escalation", "Defense Evasion", "Credential Access",
            "Discovery", "Lateral Movement", "Collection", "Command and Control",
            "Exfiltration", "Impact"
    };

    // Knowledge Base: Technique ID -> Technique Object
    private static final Map<String, MitreTechnique> MITRE_KB = new LinkedHashMap<>();

    // Current Session Results
    private final transient List<ExtractionResult> currentExtractions = new ArrayList<>();
    private final transient List<IoCResult> currentIoCs = new ArrayList<>();

    static {
        // Rich MITRE ATT&CK Knowledge Base with weighted behavioral indicators
        addTech("T1595", "Active Scanning", "Reconnaissance",
                Map.of("port scan", 3.0, "nmap", 3.5, "vulnerability scan", 3.0, "network enumeration", 2.5, "masscan", 3.5),
                "Deploy network intrusion detection systems (NIDS) to detect scanning anomalies.");
        addTech("T1566", "Phishing", "Initial Access",
                Map.of("spearphishing", 4.0, "phishing", 3.0, "malicious attachment", 3.5, "lure document", 3.0, "macro-enabled", 3.0, "spoofed sender", 2.5),
                "Implement DMARC/DKIM/SPF, disable Office macros, and conduct phishing simulations.");
        addTech("T1190", "Exploit Public-Facing Application", "Initial Access",
                Map.of("sql injection", 3.5, "remote code execution", 4.0, "rce", 3.0, "web shell", 3.5, "cve-", 2.5, "unpatched server", 2.5),
                "Apply virtual patching via WAF and prioritize patching internet-facing assets.");
        addTech("T1059", "Command and Scripting Interpreter", "Execution",
                Map.of("powershell", 3.5, "cmd.exe", 3.0, "bash", 2.5, "vbscript", 3.0, "wscript", 3.0, "encodedcommand", 4.0, "python script", 2.0),
                "Enable PowerShell Script Block Logging and Constrained Language Mode.");
        addTech("T1053", "Scheduled Task/Job", "Persistence",
                Map.of("scheduled task", 3.5, "schtasks", 4.0, "cron job", 3.5, "at.exe", 3.0, "task scheduler", 3.0),
                "Audit task creation events (Windows Event ID 4698) and restrict task privileges.");
        addTech("T1547", "Boot or Logon Autostart Execution", "Persistence",
                Map.of("run key", 3.5, "currentversion\\run", 4.0, "startup folder", 3.0, "registry persistence", 3.5, "winlogon", 3.0),
                "Monitor registry modifications under HKLM/HKCU Run keys via Sysmon Event ID 13.");
        addTech("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation",
                Map.of("uac bypass", 4.0, "privilege escalation", 3.5, "sudo", 2.5, "fodhelper", 4.0, "eventvwr", 3.5),
                "Set User Account Control (UAC) to 'Always Notify' and audit sudoers configurations.");
        addTech("T1027", "Obfuscated Files or Information", "Defense Evasion",
                Map.of("base64", 3.0, "obfuscated", 3.5, "xor encrypted", 3.5, "packed binary", 3.0, "steganography", 4.0, "amsi bypass", 4.0),
                "Use behavioral EDR heuristics and inspect decoded script blocks.");
        addTech("T1070", "Indicator Removal", "Defense Evasion",
                Map.of("clear event log", 4.0, "wevtutil", 4.0, "timestomp", 3.5, "delete logs", 3.5, "anti-forensics", 3.0),
                "Forward Windows Event Logs in real-time to an immutable SIEM collector.");
        addTech("T1003", "OS Credential Dumping", "Credential Access",
                Map.of("mimikatz", 4.5, "lsass", 4.0, "credential dumping", 4.0, "sam database", 3.5, "ntds.dit", 4.0, "sekurlsa", 4.5),
                "Enable Credential Guard, RunAsPPL on LSASS, and monitor process access to lsass.exe.");
        addTech("T1082", "System Information Discovery", "Discovery",
                Map.of("systeminfo", 3.5, "hostname", 2.0, "uname -a", 3.0, "os version", 2.0, "environment enumeration", 2.5),
                "Monitor execution of built-in discovery binaries in rapid succession.");
        addTech("T1021", "Remote Services", "Lateral Movement",
                Map.of("rdp", 3.0, "remote desktop", 3.0, "psexec", 4.0, "smb", 2.5, "winrm", 3.5, "lateral movement", 3.5, "pass-the-hash", 4.0),
                "Restrict lateral RDP/SMB traffic via host firewalls and enforce MFA.");
        addTech("T1560", "Archive Collected Data", "Collection",
                Map.of("7-zip", 3.0, "rar archive", 3.0, "compress data", 2.5, "staging directory", 3.0, "tar.gz", 2.5),
                "Alert on archiving tools executed from non-standard directories like Temp or AppData.");
        addTech("T1071", "Application Layer Protocol", "Command and Control",
                Map.of("c2", 3.5, "command and control", 4.0, "http beacon", 4.0, "dns tunneling", 4.0, "cobalt strike", 4.5, "user-agent", 2.5),
                "Inspect outbound TLS/HTTP traffic with SSL inspection and DNS sinkholing.");
        addTech("T1041", "Exfiltration Over C2 Channel", "Exfiltration",
                Map.of("exfiltrate", 4.0, "exfiltration", 4.0, "data theft", 3.5, "outbound transfer", 3.0, "stolen data", 3.0),
                "Enforce Data Loss Prevention (DLP) policies and monitor anomalous upload volumes.");
        addTech("T1486", "Data Encrypted for Impact", "Impact",
                Map.of("ransomware", 4.5, "encrypt files", 4.0, "ransom note", 4.0, "vssadmin", 4.0, "delete shadows", 4.0, ".locked", 3.5),
                "Maintain offline immutable backups and block unauthorized volume shadow copy deletion.");
    }

    private static void addTech(String id, String name, String tactic, Map<String, Double> weights, String mitigation) {
        MITRE_KB.put(id, new MitreTechnique(id, name, tactic, weights, mitigation));
    }

    public ppt() {
        setTitle("Enterprise CTI Workstation \u2014 Automated MITRE ATT&CK & IoC Extraction Engine");
        setSize(1280, 820);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLocationRelativeTo(null);

        initMenuBar();
        initUI();
        runDeepAnalysis();
    }

    private void initMenuBar() {
        JMenuBar menuBar = new JMenuBar();

        JMenu fileMenu = new JMenu("File");
        JMenuItem openItem = new JMenuItem("Open Threat Report (.txt, .log, .md)");
        JMenuItem exportJsonItem = new JMenuItem("Export MITRE ATT&CK Navigator Layer (.json)");
        JMenuItem exportCsvItem = new JMenuItem("Export Full Report (.csv)");
        JMenuItem exitItem = new JMenuItem("Exit");

        openItem.addActionListener(e -> loadReportFromFile());
        exportJsonItem.addActionListener(e -> exportNavigatorJson());
        exportCsvItem.addActionListener(e -> exportTableToCSV());
        exitItem.addActionListener(e -> System.exit(0));

        fileMenu.add(openItem);
        fileMenu.addSeparator();
        fileMenu.add(exportJsonItem);
        fileMenu.add(exportCsvItem);
        fileMenu.addSeparator();
        fileMenu.add(exitItem);

        JMenu kbMenu = new JMenu("Knowledge Base");
        JMenuItem addRuleItem = new JMenuItem("Add Custom ATT&CK Detection Rule...");
        JMenuItem viewKbItem = new JMenuItem("View Loaded ATT&CK Signatures (" + MITRE_KB.size() + ")");

        addRuleItem.addActionListener(e -> showAddRuleDialog());
        viewKbItem.addActionListener(e -> JOptionPane.showMessageDialog(this,
                "Loaded Enterprise Techniques: " + MITRE_KB.size() + "\nTactics Covered: " + ENTERPRISE_TACTICS.length,
                "MITRE ATT&CK KB Info", JOptionPane.INFORMATION_MESSAGE));

        kbMenu.add(addRuleItem);
        kbMenu.add(viewKbItem);

        menuBar.add(fileMenu);
        menuBar.add(kbMenu);
        setJMenuBar(menuBar);
    }

    private void initUI() {
        JPanel root = new JPanel(new BorderLayout(8, 8));
        root.setBorder(new EmptyBorder(10, 10, 10, 10));

        // Top Banner
        JPanel topBanner = new JPanel(new BorderLayout());
        topBanner.setBackground(new Color(18, 38, 73));
        topBanner.setBorder(new EmptyBorder(10, 15, 10, 15));

        JLabel titleLbl = new JLabel("MITRE ATT&CK\u00AE Automated Threat Intelligence Extractor");
        titleLbl.setForeground(Color.WHITE);
        titleLbl.setFont(new Font("SansSerif", Font.BOLD, 18));

        JLabel subTitleLbl = new JLabel("NLP Weighted Behavioral Scoring \u2022 Regex Sub-Technique Parser \u2022 IoC Extractor \u2022 Kill-Chain Matrix");
        subTitleLbl.setForeground(new Color(180, 205, 240));
        subTitleLbl.setFont(new Font("SansSerif", Font.PLAIN, 12));

        JPanel titleStack = new JPanel(new GridLayout(2, 1));
        titleStack.setOpaque(false);
        titleStack.add(titleLbl);
        titleStack.add(subTitleLbl);
        topBanner.add(titleStack, BorderLayout.WEST);

        JButton runAnalysisBtn = new JButton("\u25B6 RUN DEEP EXTRACTION");
        runAnalysisBtn.setUI(new javax.swing.plaf.basic.BasicButtonUI());
        runAnalysisBtn.setBackground(new Color(46, 160, 67));
        runAnalysisBtn.setForeground(Color.WHITE);
        runAnalysisBtn.setFont(new Font("SansSerif", Font.BOLD, 13));
        runAnalysisBtn.setBorder(new EmptyBorder(8, 16, 8, 16));
        runAnalysisBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        runAnalysisBtn.setOpaque(true);
        runAnalysisBtn.setFocusPainted(false);
        runAnalysisBtn.addActionListener(e -> runDeepAnalysis());
        topBanner.add(runAnalysisBtn, BorderLayout.EAST);

        root.add(topBanner, BorderLayout.NORTH);

        // Main Horizontal Split Pane (Left: Threat Report Editor, Right: Multi-Tab Analytics)
        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplit.setResizeWeight(0.42);

        // --- LEFT PANEL: Threat Report Input with Syntax Highlighting ---
        JPanel leftPanel = new JPanel(new BorderLayout(5, 5));
        leftPanel.setBorder(BorderFactory.createTitledBorder("1. Unstructured Threat Intelligence Report (Auto-Highlighted)"));

        reportTextPane = new JTextPane();
        reportTextPane.setFont(new Font("Consolas", Font.PLAIN, 13));
        reportDoc = reportTextPane.getStyledDocument();
        reportTextPane.setText(getComplexThreatReport());

        JScrollPane editorScroll = new JScrollPane(reportTextPane);
        leftPanel.add(editorScroll, BorderLayout.CENTER);

        // Left Control Toolbar
        JPanel leftToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        JButton loadBtn = new JButton("Load File");
        JButton sampleBtn = new JButton("Reset Sample");
        JButton addRuleBtn = new JButton("+ Custom Rule");
        JButton clearBtn = new JButton("Clear");

        loadBtn.addActionListener(e -> loadReportFromFile());
        sampleBtn.addActionListener(e -> {
            reportTextPane.setText(getComplexThreatReport());
            clearHighlights();
            statusLabel.setText("Loaded sample APT-41 / Ransomware hybrid threat report.");
        });
        addRuleBtn.addActionListener(e -> showAddRuleDialog());
        clearBtn.addActionListener(e -> {
            reportTextPane.setText("");
            clearHighlights();
            techTableModel.setRowCount(0);
            iocTableModel.setRowCount(0);
            jsonPreviewArea.setText("");
            analysisProgressBar.setValue(0);
            buildMatrixView(Collections.emptyList());
            statusLabel.setText("Workspace cleared.");
        });

        leftToolbar.add(loadBtn);
        leftToolbar.add(sampleBtn);
        leftToolbar.add(addRuleBtn);
        leftToolbar.add(clearBtn);
        leftPanel.add(leftToolbar, BorderLayout.SOUTH);

        // --- RIGHT PANEL: Tabbed Analytics Dashboard ---
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setFont(new Font("SansSerif", Font.BOLD, 12));

        // Tab 1: Extracted Techniques Table + Filter
        tabbedPane.addTab("Extracted ATT&CK Techniques", createTechniquesTab());

        // Tab 2: Visual Kill-Chain Matrix
        matrixPanel = new JPanel();
        JScrollPane matrixScroll = new JScrollPane(matrixPanel);
        matrixScroll.getHorizontalScrollBar().setUnitIncrement(16);
        buildMatrixView(Collections.emptyList());
        tabbedPane.addTab("Kill-Chain Matrix View", matrixScroll);

        // Tab 3: Extracted IoCs (IPs, Hashes, Domains, CVEs)
        tabbedPane.addTab("Extracted IoCs & Artifacts", createIoCTab());

        // Tab 4: ATT&CK Navigator JSON / STIX Output
        jsonPreviewArea = new JTextArea();
        jsonPreviewArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        jsonPreviewArea.setEditable(false);
        JPanel jsonPanel = new JPanel(new BorderLayout(5, 5));
        jsonPanel.add(new JScrollPane(jsonPreviewArea), BorderLayout.CENTER);
        JButton exportNavBtn = new JButton("Save ATT&CK Navigator Layer (.json)");
        exportNavBtn.addActionListener(e -> exportNavigatorJson());
        jsonPanel.add(exportNavBtn, BorderLayout.SOUTH);
        tabbedPane.addTab("Navigator JSON Layer", jsonPanel);

        mainSplit.setLeftComponent(leftPanel);
        mainSplit.setRightComponent(tabbedPane);
        root.add(mainSplit, BorderLayout.CENTER);

        // Bottom Status Bar with Progress Bar
        JPanel statusBar = new JPanel(new BorderLayout(10, 0));
        statusBar.setBorder(new EmptyBorder(4, 2, 0, 2));
        statusLabel = new JLabel("Ready. Press 'RUN DEEP EXTRACTION' to analyze report.");
        analysisProgressBar = new JProgressBar(0, 100);
        analysisProgressBar.setPreferredSize(new Dimension(180, 16));
        analysisProgressBar.setStringPainted(true);

        statusBar.add(statusLabel, BorderLayout.CENTER);
        statusBar.add(analysisProgressBar, BorderLayout.EAST);
        root.add(statusBar, BorderLayout.SOUTH);

        add(root);
    }

    private JPanel createTechniquesTab() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(new EmptyBorder(5, 5, 5, 5));

        // Search/Filter Bar
        JPanel filterBar = new JPanel(new BorderLayout(8, 0));
        filterBar.add(new JLabel("Filter by ID, Tactic, or Keyword:"), BorderLayout.WEST);
        searchFilterField = new JTextField();
        filterBar.add(searchFilterField, BorderLayout.CENTER);

        JButton exportCsvBtn = new JButton("Export CSV");
        exportCsvBtn.addActionListener(e -> exportTableToCSV());
        filterBar.add(exportCsvBtn, BorderLayout.EAST);

        panel.add(filterBar, BorderLayout.NORTH);

        String[] cols = {"ID", "Technique Name", "Tactic", "Method", "Confidence", "Matched Evidence"};
        techTableModel = new DefaultTableModel(cols, 0) {
            private static final long serialVersionUID = 1L;
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        techniquesTable = new JTable(techTableModel);
        techniquesTable.setRowHeight(26);
        techniquesTable.getTableHeader().setFont(new Font("SansSerif", Font.BOLD, 12));
        tableSorter = new TableRowSorter<>(techTableModel);
        tableSorter.setComparator(4, (Object a, Object b) -> Integer.compare(
                parseConfidence(a), parseConfidence(b)));
        techniquesTable.setRowSorter(tableSorter);

        // Custom Confidence Color Renderer
        techniquesTable.getColumnModel().getColumn(4).setCellRenderer(new DefaultTableCellRenderer() {
            private static final long serialVersionUID = 1L;
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                JLabel c = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                c.setHorizontalAlignment(SwingConstants.CENTER);
                int score = parseConfidence(value);
                if (!isSelected) {
                    if (score >= 85) {
                        c.setBackground(new Color(212, 237, 218));
                        c.setForeground(new Color(21, 87, 36));
                    } else if (score >= 65) {
                        c.setBackground(new Color(255, 243, 205));
                        c.setForeground(new Color(133, 100, 4));
                    } else {
                        c.setBackground(Color.WHITE);
                        c.setForeground(Color.BLACK);
                    }
                }
                return c;
            }
        });

        // Double-click row to view Mitigation Details
        techniquesTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                if (evt.getClickCount() == 2) {
                    int viewRow = techniquesTable.getSelectedRow();
                    if (viewRow >= 0) {
                        int modelRow = techniquesTable.convertRowIndexToModel(viewRow);
                        String id = techTableModel.getValueAt(modelRow, 0).toString();
                        String baseId = id.contains(".") ? id.split("\\.")[0] : id;
                        MitreTechnique tech = MITRE_KB.get(baseId);
                        String mitigation = (tech != null) ? tech.mitigation : "Refer to MITRE ATT&CK Enterprise Matrix for standard mitigations.";
                        JOptionPane.showMessageDialog(ppt.this,
                                "Technique: " + id + " - " + techTableModel.getValueAt(modelRow, 1) +
                                "\nTactic: " + techTableModel.getValueAt(modelRow, 2) +
                                "\n\nRecommended Mitigation:\n" + mitigation +
                                "\n\nContext:\n" + techTableModel.getValueAt(modelRow, 5),
                                "Technique Intelligence & Mitigation", JOptionPane.INFORMATION_MESSAGE);
                    }
                }
            }
        });

        // Live Filter Listener
        searchFilterField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { filter(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { filter(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { filter(); }
            private void filter() {
                String text = searchFilterField.getText().trim();
                tableSorter.setRowFilter(text.isEmpty() ? null : RowFilter.regexFilter("(?i)" + Pattern.quote(text)));
            }
        });

        techniquesTable.getColumnModel().getColumn(0).setPreferredWidth(75);
        techniquesTable.getColumnModel().getColumn(1).setPreferredWidth(185);
        techniquesTable.getColumnModel().getColumn(2).setPreferredWidth(130);
        techniquesTable.getColumnModel().getColumn(3).setPreferredWidth(105);
        techniquesTable.getColumnModel().getColumn(4).setPreferredWidth(85);
        techniquesTable.getColumnModel().getColumn(5).setPreferredWidth(260);

        panel.add(new JScrollPane(techniquesTable), BorderLayout.CENTER);
        JLabel tipLabel = new JLabel("Tip: Double-click any extracted technique row to inspect recommended blue-team mitigations.");
        tipLabel.setFont(new Font("SansSerif", Font.ITALIC, 11));
        panel.add(tipLabel, BorderLayout.SOUTH);

        return panel;
    }

    private JPanel createIoCTab() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(new EmptyBorder(5, 5, 5, 5));

        String[] cols = {"Artifact Type", "Extracted Indicator (Defanged/Raw)", "Context Snippet"};
        iocTableModel = new DefaultTableModel(cols, 0) {
            private static final long serialVersionUID = 1L;
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        iocTable = new JTable(iocTableModel);
        iocTable.setRowHeight(24);
        iocTable.getTableHeader().setFont(new Font("SansSerif", Font.BOLD, 12));
        iocTable.getColumnModel().getColumn(0).setPreferredWidth(130);
        iocTable.getColumnModel().getColumn(1).setPreferredWidth(250);
        iocTable.getColumnModel().getColumn(2).setPreferredWidth(420);

        panel.add(new JScrollPane(iocTable), BorderLayout.CENTER);
        return panel;
    }

    private void buildMatrixView(List<ExtractionResult> extractions) {
        matrixPanel.removeAll();
        matrixPanel.setLayout(new GridLayout(1, ENTERPRISE_TACTICS.length, 6, 0));
        matrixPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        matrixPanel.setBackground(new Color(240, 242, 245));

        Map<String, List<ExtractionResult>> groupedByTactic = extractions.stream()
                .collect(Collectors.groupingBy(r -> r.tactic));

        for (String tactic : ENTERPRISE_TACTICS) {
            JPanel colPanel = new JPanel();
            colPanel.setLayout(new BoxLayout(colPanel, BoxLayout.Y_AXIS));
            colPanel.setPreferredSize(new Dimension(165, 500));
            colPanel.setBackground(Color.WHITE);
            colPanel.setBorder(BorderFactory.createLineBorder(new Color(200, 205, 215)));

            List<ExtractionResult> hits = groupedByTactic.getOrDefault(tactic, Collections.emptyList());

            JLabel header = new JLabel("<html><center><b>" + escapeHtml(tactic) + "</b><br>(" + hits.size() + ")</center></html>", SwingConstants.CENTER);
            header.setOpaque(true);
            header.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
            header.setAlignmentX(Component.CENTER_ALIGNMENT);
            header.setBackground(hits.isEmpty() ? new Color(230, 234, 240) : new Color(180, 35, 35));
            header.setForeground(hits.isEmpty() ? Color.DARK_GRAY : Color.WHITE);
            header.setBorder(new EmptyBorder(5, 4, 5, 4));
            colPanel.add(header);
            colPanel.add(Box.createVerticalStrut(6));

            for (ExtractionResult hit : hits) {
                JPanel card = new JPanel(new BorderLayout());
                card.setAlignmentX(Component.CENTER_ALIGNMENT);
                card.setMaximumSize(new Dimension(155, 62));
                card.setBackground(new Color(255, 235, 235));
                card.setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createLineBorder(new Color(220, 80, 80)),
                        new EmptyBorder(4, 5, 4, 5)
                ));
                JLabel cardLbl = new JLabel("<html><b>" + escapeHtml(hit.id) + "</b><br><font size='2'>" + escapeHtml(hit.name) + "</font></html>");
                card.add(cardLbl, BorderLayout.CENTER);
                colPanel.add(card);
                colPanel.add(Box.createVerticalStrut(5));
            }
            colPanel.add(Box.createVerticalGlue());

            matrixPanel.add(colPanel);
        }

        matrixPanel.revalidate();
        matrixPanel.repaint();
    }

    private void runDeepAnalysis() {
        String rawText;
        try {
            rawText = reportDoc.getText(0, reportDoc.getLength());
        } catch (BadLocationException e) {
            rawText = reportTextPane.getText();
        }
        if (rawText.trim().isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please provide a threat report to analyze.", "Empty Report", JOptionPane.WARNING_MESSAGE);
            return;
        }

        analysisProgressBar.setValue(15);
        clearHighlights();
        currentExtractions.clear();
        currentIoCs.clear();
        techTableModel.setRowCount(0);
        iocTableModel.setRowCount(0);

        Map<String, ExtractionResult> detectedMap = new LinkedHashMap<>();
        String[] sentences = rawText.split("(?<=[.!?])\\s+|\\n+");

        // Step 1: Regex Explicit ATT&CK Technique IDs (e.g., T1059, T1059.001)
        Pattern idPattern = Pattern.compile("\\b(T1\\d{3}(?:\\.\\d{3})?)\\b", Pattern.CASE_INSENSITIVE);
        for (String sentence : sentences) {
            String trimmed = sentence.trim();
            if (trimmed.isEmpty()) continue;

            Matcher m = idPattern.matcher(trimmed);
            while (m.find()) {
                String fullId = m.group(1).toUpperCase(Locale.ROOT);
                String baseId = fullId.contains(".") ? fullId.split("\\.")[0] : fullId;
                MitreTechnique kbTech = MITRE_KB.get(baseId);

                String name = (kbTech != null) ? kbTech.name : "Sub-Technique / Explicit ATT&CK ID";
                String tactic = (kbTech != null) ? kbTech.tactic : "Execution";

                detectedMap.put(fullId, new ExtractionResult(
                        fullId, name, tactic, "Explicit ID Regex", "100%", trimmed
                ));
                highlightTermInEditor(fullId, new Color(173, 232, 244), true);
            }
        }
        analysisProgressBar.setValue(45);

        // Step 2: Weighted NLP Keyword & N-Gram Scoring (word-boundary aware)
        for (String sentence : sentences) {
            String trimmed = sentence.trim();
            if (trimmed.isEmpty()) continue;

            for (MitreTechnique tech : MITRE_KB.values()) {
                double totalWeight = 0.0;
                List<String> matchedIndicators = new ArrayList<>();

                for (Map.Entry<String, Double> entry : tech.weightedIndicators.entrySet()) {
                    String indicator = entry.getKey();
                    Pattern indPattern = buildIndicatorPattern(indicator);
                    if (indPattern.matcher(trimmed).find()) {
                        totalWeight += entry.getValue();
                        matchedIndicators.add(indicator);
                        highlightPatternInEditor(indPattern, new Color(255, 243, 176));
                    }
                }

                if (totalWeight > 0) {
                    int confScore = (int) Math.min(98, Math.round(55 + (totalWeight * 6.5)));
                    String confString = confScore + "%";
                    String evidence = "Indicators [" + String.join(", ", matchedIndicators) + "] -> \"" + trimmed + "\"";

                    boolean subTechPresent = detectedMap.keySet().stream()
                            .anyMatch(k -> k.equals(tech.id) || k.startsWith(tech.id + "."));
                    if (!subTechPresent) {
                        detectedMap.put(tech.id, new ExtractionResult(
                                tech.id, tech.name, tech.tactic, "Weighted NLP", confString, evidence
                        ));
                    }
                }
            }
        }
        analysisProgressBar.setValue(75);

        // Step 3: Extract IoCs (IPv4, SHA-256, MD5, CVEs, Domains)
        extractIoCs(sentences);

        // Populate Tables & Matrix
        currentExtractions.addAll(detectedMap.values());
        for (ExtractionResult res : currentExtractions) {
            techTableModel.addRow(new Object[]{
                    res.id, res.name, res.tactic, res.method, res.confidence, res.evidence
            });
        }

        buildMatrixView(currentExtractions);
        jsonPreviewArea.setText(generateNavigatorLayerJson(currentExtractions));

        analysisProgressBar.setValue(100);
        statusLabel.setText(String.format("Deep Extraction Complete: %d ATT&CK Techniques & %d IoCs identified.",
                currentExtractions.size(), currentIoCs.size()));
    }

    private void extractIoCs(String[] sentences) {
        Map<String, Pattern> iocPatterns = new LinkedHashMap<>();
        iocPatterns.put("CVE Vulnerability", Pattern.compile("\\bCVE-\\d{4}-\\d{4,7}\\b", Pattern.CASE_INSENSITIVE));
        iocPatterns.put("IPv4 Address", Pattern.compile("\\b(?:\\d{1,3}(?:\\[\\.\\]|\\.)){3}\\d{1,3}\\b"));
        iocPatterns.put("SHA-256 Hash", Pattern.compile("\\b[a-fA-F0-9]{64}\\b"));
        iocPatterns.put("MD5 Hash", Pattern.compile("\\b[a-fA-F0-9]{32}\\b"));
        iocPatterns.put("Malicious Domain / URL", Pattern.compile("\\b(?:hxxps?://|https?://)?[a-zA-Z0-9-]+(?:(?:\\[\\.\\]|\\.)[a-zA-Z0-9-]+)*(?:\\[\\.\\]|\\.)(?:com|net|org|io|ru|cn|xyz|top|biz)(?:/[^\\s,;)\"]*)?", Pattern.CASE_INSENSITIVE));
        iocPatterns.put("Windows Registry Key", Pattern.compile("\\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\\\[^\\s,;)\"]+", Pattern.CASE_INSENSITIVE));

        Set<String> seen = new HashSet<>();
        for (String sentence : sentences) {
            String trimmed = sentence.trim();
            for (Map.Entry<String, Pattern> entry : iocPatterns.entrySet()) {
                Matcher m = entry.getValue().matcher(trimmed);
                while (m.find()) {
                    String val = m.group().replaceAll("[.,;:]+$", "");
                    if (seen.add(val.toLowerCase(Locale.ROOT))) {
                        IoCResult ioc = new IoCResult(entry.getKey(), val, trimmed);
                        currentIoCs.add(ioc);
                        iocTableModel.addRow(new Object[]{ioc.type, ioc.value, ioc.context});
                        highlightTermInEditor(val, new Color(255, 205, 210), false);
                    }
                }
            }
        }
    }

    private static Pattern buildIndicatorPattern(String indicator) {
        String quoted = Pattern.quote(indicator);
        boolean startsWord = !indicator.isEmpty() && Character.isLetterOrDigit(indicator.charAt(0));
        boolean endsWord = !indicator.isEmpty() && Character.isLetterOrDigit(indicator.charAt(indicator.length() - 1));
        String regex = (startsWord ? "\\b" : "") + quoted + (endsWord ? "\\b" : "");
        return Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
    }

    private void clearHighlights() {
        reportTextPane.getHighlighter().removeAllHighlights();
    }

    private void highlightTermInEditor(String term, Color bgColor, boolean wordBoundary) {
        if (term == null || term.isEmpty()) return;
        Pattern p = wordBoundary ? buildIndicatorPattern(term)
                : Pattern.compile(Pattern.quote(term), Pattern.CASE_INSENSITIVE);
        highlightPatternInEditor(p, bgColor);
    }

    private void highlightPatternInEditor(Pattern pattern, Color bgColor) {
        try {
            String text = reportDoc.getText(0, reportDoc.getLength());
            Highlighter highlighter = reportTextPane.getHighlighter();
            Highlighter.HighlightPainter painter = new DefaultHighlighter.DefaultHighlightPainter(bgColor);
            Matcher m = pattern.matcher(text);
            while (m.find()) {
                highlighter.addHighlight(m.start(), m.end(), painter);
            }
        } catch (BadLocationException ignored) {
        }
    }

    private static int parseConfidence(Object value) {
        if (value == null) return 0;
        String digits = value.toString().replaceAll("[^0-9]", "");
        if (digits.isEmpty()) return 0;
        try {
            return Integer.parseInt(digits);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private String generateNavigatorLayerJson(List<ExtractionResult> results) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"name\": \"Extracted Threat Intelligence Layer\",\n");
        sb.append("  \"versions\": { \"attack\": \"15\", \"navigator\": \"5.0\", \"layer\": \"4.5\" },\n");
        sb.append("  \"domain\": \"enterprise-attack\",\n");
        sb.append("  \"description\": \"Generated on ").append(LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)).append("\",\n");
        sb.append("  \"techniques\": [\n");

        for (int i = 0; i < results.size(); i++) {
            ExtractionResult r = results.get(i);
            int score = parseConfidence(r.confidence);
            String tacticSlug = r.tactic.toLowerCase(Locale.ROOT).replace("&", "and").replace(" ", "-");
            sb.append("    {\n");
            sb.append("      \"techniqueID\": \"").append(escapeJson(r.id)).append("\",\n");
            sb.append("      \"tactic\": \"").append(escapeJson(tacticSlug)).append("\",\n");
            sb.append("      \"score\": ").append(score).append(",\n");
            sb.append("      \"color\": \"#e60d0d\",\n");
            sb.append("      \"comment\": \"").append(escapeJson(r.method + " (Confidence: " + r.confidence + ")")).append("\",\n");
            sb.append("      \"enabled\": true\n");
            sb.append("    }").append(i < results.size() - 1 ? "," : "").append("\n");
        }
        sb.append("  ]\n");
        sb.append("}");
        return sb.toString();
    }

    private void showAddRuleDialog() {
        JTextField idField = new JTextField("T1105");
        JTextField nameField = new JTextField("Ingress Tool Transfer");
        JComboBox<String> tacticBox = new JComboBox<>(ENTERPRISE_TACTICS);
        tacticBox.setSelectedItem("Command and Control");
        JTextField keywordsField = new JTextField("certutil, bitsadmin, curl, wget, download payload");
        JTextField mitigationField = new JTextField("Block outbound connections from living-off-the-land binaries (LOLBins).");

        JPanel panel = new JPanel(new GridLayout(0, 1, 4, 4));
        panel.add(new JLabel("Technique ID (e.g., T1105):"));
        panel.add(idField);
        panel.add(new JLabel("Technique Name:"));
        panel.add(nameField);
        panel.add(new JLabel("MITRE ATT&CK Tactic:"));
        panel.add(tacticBox);
        panel.add(new JLabel("Behavioral Keywords (comma-separated):"));
        panel.add(keywordsField);
        panel.add(new JLabel("Recommended Mitigation:"));
        panel.add(mitigationField);

        int res = JOptionPane.showConfirmDialog(this, panel, "Add Custom MITRE ATT&CK Detection Rule", JOptionPane.OK_CANCEL_OPTION);
        if (res == JOptionPane.OK_OPTION) {
            String id = idField.getText().trim().toUpperCase(Locale.ROOT);
            String name = nameField.getText().trim();
            String tactic = Objects.requireNonNull(tacticBox.getSelectedItem()).toString();
            Map<String, Double> weights = new LinkedHashMap<>();
            for (String kw : keywordsField.getText().split(",")) {
                if (!kw.trim().isEmpty()) {
                    weights.put(kw.trim().toLowerCase(Locale.ROOT), 3.5);
                }
            }
            if (!id.isEmpty() && !weights.isEmpty()) {
                MITRE_KB.put(id, new MitreTechnique(id, name, tactic, weights, mitigationField.getText().trim()));
                runDeepAnalysis();
                statusLabel.setText("Added custom rule for " + id + " (" + name + ") and refreshed extraction.");
            }
        }
    }

    private void loadReportFromFile() {
        JFileChooser fc = new JFileChooser();
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                String content = Files.readString(fc.getSelectedFile().toPath(), StandardCharsets.UTF_8);
                reportTextPane.setText(content);
                runDeepAnalysis();
                statusLabel.setText("Loaded & analyzed threat report: " + fc.getSelectedFile().getName());
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "Failed to read file: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void exportTableToCSV() {
        if (techTableModel.getRowCount() == 0) {
            JOptionPane.showMessageDialog(this, "Run extraction first before exporting.", "No Data", JOptionPane.WARNING_MESSAGE);
            return;
        }
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new File("mitre_attack_report.csv"));
        if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            StringBuilder csv = new StringBuilder();
            for (int i = 0; i < techTableModel.getColumnCount(); i++) {
                csv.append('"').append(techTableModel.getColumnName(i).replace("\"", "\"\"")).append('"');
                if (i < techTableModel.getColumnCount() - 1) csv.append(',');
            }
            csv.append('\n');
            for (int r = 0; r < techTableModel.getRowCount(); r++) {
                for (int c = 0; c < techTableModel.getColumnCount(); c++) {
                    csv.append('"').append(techTableModel.getValueAt(r, c).toString().replace("\"", "\"\"")).append('"');
                    if (c < techTableModel.getColumnCount() - 1) csv.append(',');
                }
                csv.append('\n');
            }
            try {
                Files.writeString(fc.getSelectedFile().toPath(), csv.toString(), StandardCharsets.UTF_8);
                statusLabel.setText("Exported CSV to " + fc.getSelectedFile().getAbsolutePath());
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "CSV Export Error: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void exportNavigatorJson() {
        if (currentExtractions.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Run extraction first to generate a Navigator Layer.", "No Data", JOptionPane.WARNING_MESSAGE);
            return;
        }
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new File("attack_navigator_layer.json"));
        if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                Files.writeString(fc.getSelectedFile().toPath(), generateNavigatorLayerJson(currentExtractions), StandardCharsets.UTF_8);
                statusLabel.setText("Exported ATT&CK Navigator JSON to " + fc.getSelectedFile().getAbsolutePath());
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "JSON Export Error: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private String getComplexThreatReport() {
        return "CTI ADVISORY #2026-089: MULTI-STAGE INTRUSION & RANSOMWARE DEPLOYMENT\n\n" +
               "1. RECONNAISSANCE & INITIAL ACCESS:\n" +
               "Threat actors initiated external vulnerability scan probes before exploiting an unpatched public-facing web server via CVE-2024-3400 to drop a web shell. " +
               "Concurrently, finance personnel received a spearphishing email with a macro-enabled lure document.\n\n" +
               "2. EXECUTION, PERSISTENCE & EVASION:\n" +
               "Upon execution, an obfuscated Base64 PowerShell payload (T1059.001) bypassed AMSI and established persistence by creating a scheduled task via schtasks and modifying HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run. " +
               "To evade forensics, the operators used wevtutil to clear event logs.\n\n" +
               "3. CREDENTIAL ACCESS, DISCOVERY & LATERAL MOVEMENT:\n" +
               "The adversary executed systeminfo to enumerate the host, followed by running Mimikatz to dump credentials and NTLM hashes from LSASS memory. " +
               "Using harvested domain admin credentials, the threat actor moved laterally across internal subnets via RDP and PsExec.\n\n" +
               "4. C2, EXFILTRATION & IMPACT:\n" +
               "Sensitive financial databases were staged in a staging directory using 7-Zip and exfiltrated over an encrypted Cobalt Strike HTTP beacon to 185.220.101[.]45 and cdn-update-service[.]xyz (SHA256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08). " +
               "Finally, the attackers ran vssadmin to delete shadows and deployed ransomware to encrypt files across critical servers.";
    }

    // Data Models
    static class MitreTechnique {
        String id, name, tactic, mitigation;
        Map<String, Double> weightedIndicators;

        MitreTechnique(String id, String name, String tactic, Map<String, Double> weightedIndicators, String mitigation) {
            this.id = id;
            this.name = name;
            this.tactic = tactic;
            this.weightedIndicators = weightedIndicators;
            this.mitigation = mitigation;
        }
    }

    static class ExtractionResult {
        String id, name, tactic, method, confidence, evidence;

        ExtractionResult(String id, String name, String tactic, String method, String confidence, String evidence) {
            this.id = id;
            this.name = name;
            this.tactic = tactic;
            this.method = method;
            this.confidence = confidence;
            this.evidence = evidence;
        }
    }

    static class IoCResult {
        String type, value, context;

        IoCResult(String type, String value, String context) {
            this.type = type;
            this.value = value;
            this.context = context;
        }
    }

    public static void main(String[] args) {
        if (args != null && args.length > 0 && "--self-test".equals(args[0])) {
            runSelfTests();
            return;
        }
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {
        }

        SwingUtilities.invokeLater(() -> new ppt().setVisible(true));
    }

    private static void runSelfTests() {
        try {
            SwingUtilities.invokeAndWait(() -> {
                ppt frame = new ppt();
                if (frame.techTableModel.getRowCount() == 0) {
                    throw new AssertionError("Expected extracted MITRE techniques on startup");
                }
                if (frame.iocTableModel.getRowCount() == 0) {
                    throw new AssertionError("Expected extracted IOCs on startup");
                }
                if (frame.reportTextPane.getHighlighter().getHighlights().length == 0) {
                    throw new AssertionError("Expected inline highlights in report pane");
                }
                String navJson = frame.generateNavigatorLayerJson(frame.currentExtractions);
                if (!navJson.contains("\"enterprise-attack\"") || !navJson.contains("T1059.001")) {
                    throw new AssertionError("Navigator JSON output missing expected fields");
                }
                System.out.println("PPT GUI SELF-TEST PASSED (" + frame.techTableModel.getRowCount()
                        + " techniques, " + frame.iocTableModel.getRowCount() + " IOCs).");
                frame.dispose();
            });
        } catch (Exception e) {
            throw new AssertionError("PPT GUI self-test failed", e);
        }
    }
}