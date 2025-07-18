import java.io.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Bot Traffic Detection Analysis
 * Music Media Startup - Traffic Analysis Tool
 *
 * This program analyzes web server logs to identify potential bot traffic
 * and provides recommendations for handling increased traffic load.
 */
public class BotDetectionAnalyzer {

    private final String logFilePath;
    private final List<LogEntry> logs;
    private final Map<String, IPStats> ipStatsMap;
    private static final Pattern LOG_PATTERN = Pattern.compile(
            "(\\S+) - (\\S+) - \\[([^\\]]+)\\] \"([^\"]*)\" (\\d+) (\\S+) \"([^\"]*)\" \"([^\"]*)\" (\\d+)"
    );

    public BotDetectionAnalyzer(String logFilePath) {
        this.logFilePath = logFilePath;
        this.logs = new ArrayList<>();
        this.ipStatsMap = new HashMap<>();
    }

    /**
     * Represents a single log entry
     */
    public static class LogEntry {
        public final String ip;
        public final String country;
        public final String timestamp;
        public final String method;
        public final String url;
        public final int status;
        public final int size;
        public final String referer;
        public final String userAgent;
        public final int responseTime;

        public LogEntry(String ip, String country, String timestamp, String method, String url,
                        int status, int size, String referer, String userAgent, int responseTime) {
            this.ip = ip;
            this.country = country;
            this.timestamp = timestamp;
            this.method = method;
            this.url = url;
            this.status = status;
            this.size = size;
            this.referer = referer;
            this.userAgent = userAgent;
            this.responseTime = responseTime;
        }
    }

    /**
     * Statistics for each IP address
     */
    public static class IPStats {
        public int requests = 0;
        public Set<String> pages = new HashSet<>();
        public Set<String> userAgents = new HashSet<>();
        public Set<String> countries = new HashSet<>();
        public List<Integer> statusCodes = new ArrayList<>();
        public List<String> timestamps = new ArrayList<>();
        public List<Integer> responseTimes = new ArrayList<>();
        public long bytesTransferred = 0;

        public void addRequest(LogEntry entry) {
            requests++;
            pages.add(entry.url);
            userAgents.add(entry.userAgent);
            countries.add(entry.country);
            statusCodes.add(entry.status);
            timestamps.add(entry.timestamp);
            responseTimes.add(entry.responseTime);
            bytesTransferred += entry.size;
        }

        public double getAverageResponseTime() {
            return responseTimes.stream().mapToInt(Integer::intValue).average().orElse(0.0);
        }
    }

    /**
     * Represents a suspicious IP with analysis results
     */
    public static class SuspiciousIP {
        public final String ip;
        public final int score;
        public final List<String> reasons;
        public final IPStats stats;

        public SuspiciousIP(String ip, int score, List<String> reasons, IPStats stats) {
            this.ip = ip;
            this.score = score;
            this.reasons = reasons;
            this.stats = stats;
        }
    }

    /**
     * Parse a single log line using the custom log format
     * Format: IP - COUNTRY - [TIMESTAMP] "REQUEST" STATUS SIZE "REFERER" "USER_AGENT" RESPONSE_TIME
     */
    private LogEntry parseLogLine(String line) {
        Matcher matcher = LOG_PATTERN.matcher(line.trim());

        if (matcher.matches()) {
            String ip = matcher.group(1);
            String country = matcher.group(2);
            String timestamp = matcher.group(3);
            String request = matcher.group(4);
            int status = Integer.parseInt(matcher.group(5));
            String sizeStr = matcher.group(6);
            String referer = matcher.group(7);
            String userAgent = matcher.group(8);
            int responseTime = Integer.parseInt(matcher.group(9));

            // Parse request method and URL
            String[] requestParts = request.split("\\s+");
            String method = requestParts.length > 0 ? requestParts[0] : "";
            String url = requestParts.length > 1 ? requestParts[1] : "";

            int size = sizeStr.matches("\\d+") ? Integer.parseInt(sizeStr) : 0;

            return new LogEntry(ip, country, timestamp, method, url, status, size, referer, userAgent, responseTime);
        }

        return null;
    }

    /**
     * Load and parse the log file
     */
    public void loadLogs() throws IOException {
        System.out.println("Loading logs from " + logFilePath + "...");

        try (BufferedReader reader = new BufferedReader(new FileReader(logFilePath))) {
            String line;
            int lineNumber = 0;

            while ((line = reader.readLine()) != null) {
                lineNumber++;
                LogEntry entry = parseLogLine(line);

                if (entry != null) {
                    logs.add(entry);
                    updateIPStats(entry);
                }

                if (lineNumber % 10000 == 0) {
                    System.out.println("Processed " + lineNumber + " lines...");
                }
            }
        }

        System.out.println("Successfully loaded " + logs.size() + " log entries");
    }

    /**
     * Update statistics for each IP address
     */
    private void updateIPStats(LogEntry entry) {
        IPStats stats = ipStatsMap.computeIfAbsent(entry.ip, k -> new IPStats());
        stats.addRequest(entry);
    }

    /**
     * Identify potentially suspicious IP addresses
     */
    public List<SuspiciousIP> detectSuspiciousIPs() {
        List<SuspiciousIP> suspiciousIPs = new ArrayList<>();

        for (Map.Entry<String, IPStats> entry : ipStatsMap.entrySet()) {
            String ip = entry.getKey();
            IPStats stats = entry.getValue();

            int suspicionScore = 0;
            List<String> reasons = new ArrayList<>();

            // High request volume (>500 requests might be suspicious)
            if (stats.requests > 500) {
                suspicionScore += 3;
                reasons.add("High request count: " + stats.requests);
            }

            // Very few unique pages visited
            double pagesPerRequest = (double) stats.pages.size() / stats.requests;
            if (pagesPerRequest < 0.1 && stats.requests > 50) {
                suspicionScore += 2;
                reasons.add(String.format("Low page diversity: %d pages for %d requests",
                        stats.pages.size(), stats.requests));
            }

            // Suspicious user agents
            for (String ua : stats.userAgents) {
                if (isSuspiciousUserAgent(ua)) {
                    suspicionScore += 2;
                    reasons.add("Suspicious user agent: " +
                            (ua.length() > 50 ? ua.substring(0, 50) + "..." : ua));
                    break;
                }
            }

            // High error rate
            long errorCount = stats.statusCodes.stream()
                    .filter(code -> code >= 400)
                    .count();
            double errorRate = (double) errorCount / stats.statusCodes.size();
            if (errorRate > 0.3 && stats.requests > 20) {
                suspicionScore += 1;
                reasons.add(String.format("High error rate: %.1f%%", errorRate * 100));
            }

            // High API usage (bots often hit API endpoints repeatedly)
            long apiRequests = stats.pages.stream().filter(page -> page.contains("/api/")).count();
            if (apiRequests > 0 && (double) apiRequests / stats.pages.size() > 0.7) {
                suspicionScore += 2;
                reasons.add("Heavy API usage: " + apiRequests + " API endpoints accessed");
            }

            // Requests to non-existent endpoints (scanning behavior)
            long notFoundRequests = stats.statusCodes.stream().filter(code -> code == 404).count();
            if (notFoundRequests > 5) {
                suspicionScore += 1;
                reasons.add("Multiple 404 errors: " + notFoundRequests + " not found requests");
            }

            // Check for unusually fast response times (might indicate cached/automated requests)
            double avgResponseTime = stats.getAverageResponseTime();
            if (stats.requests > 20 && avgResponseTime < 50) { // Less than 50ms average
                suspicionScore += 1;
                reasons.add(String.format("Very fast response times: %.1fms average", avgResponseTime));
            }

            // Private IP ranges (internal networks, possible development/testing)
            if (isPrivateIP(ip) && stats.requests > 100) {
                suspicionScore += 1;
                reasons.add("High traffic from private IP range");
            }

            if (suspicionScore >= 4) { // Threshold for suspicious behavior
                suspiciousIPs.add(new SuspiciousIP(ip, suspicionScore, reasons, stats));
            }
        }

        // Sort by score (descending)
        suspiciousIPs.sort((a, b) -> Integer.compare(b.score, a.score));
        return suspiciousIPs;
    }

    /**
     * Check if IP is in private range (RFC 1918)
     */
    private boolean isPrivateIP(String ip) {
        return ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("172.");
    }

    /**
     * Check if user agent suggests bot behavior
     */
    private boolean isSuspiciousUserAgent(String userAgent) {
        String[] botIndicators = {
                "bot", "crawler", "spider", "scraper", "curl", "wget", "python",
                "java", "automated", "monitor", "check", "test"
        };

        String uaLower = userAgent.toLowerCase();

        // Check for missing or minimal user agent (just "-")
        if (userAgent.equals("-") || userAgent.trim().isEmpty()) {
            return true;
        }

        return Arrays.stream(botIndicators).anyMatch(uaLower::contains);
    }

    /**
     * Find most requested pages
     */
    public List<Map.Entry<String, Long>> analyzePopularPages() {
        Map<String, Long> pageCounts = logs.stream()
                .collect(Collectors.groupingBy(
                        entry -> entry.url,
                        Collectors.counting()
                ));

        return pageCounts.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(20)
                .collect(Collectors.toList());
    }

    /**
     * Generate comprehensive analysis report
     */
    public AnalysisResults generateReport() {
        List<SuspiciousIP> suspiciousIPs = detectSuspiciousIPs();
        List<Map.Entry<String, Long>> popularPages = analyzePopularPages();

        int totalRequests = logs.size();
        int uniqueIPs = ipStatsMap.size();
        int suspiciousRequests = suspiciousIPs.stream()
                .mapToInt(ip -> ip.stats.requests)
                .sum();

        System.out.println("\n" + "=".repeat(60));
        System.out.println("BOT TRAFFIC DETECTION REPORT");
        System.out.println("=".repeat(60));

        System.out.printf("\n📊 OVERVIEW:\n");
        System.out.printf("Total requests analyzed: %,d\n", totalRequests);
        System.out.printf("Unique IP addresses: %,d\n", uniqueIPs);
        System.out.printf("Suspicious IPs identified: %d\n", suspiciousIPs.size());
        System.out.printf("Requests from suspicious IPs: %,d (%.1f%%)\n",
                suspiciousRequests, (double) suspiciousRequests / totalRequests * 100);

        System.out.println("\n🚨 TOP SUSPICIOUS IPs:");
        for (int i = 0; i < Math.min(10, suspiciousIPs.size()); i++) {
            SuspiciousIP ip = suspiciousIPs.get(i);
            System.out.printf("\n%d. IP: %s (Score: %d)\n", i + 1, ip.ip, ip.score);
            System.out.printf("   Requests: %,d\n", ip.stats.requests);
            System.out.printf("   Reasons: %s\n", String.join("; ", ip.reasons));
        }

        System.out.println("\n🌍 TRAFFIC BY COUNTRY:");
        Map<String, Long> countryTraffic = logs.stream()
                .collect(Collectors.groupingBy(
                        entry -> entry.country,
                        Collectors.counting()
                ));

        countryTraffic.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(10)
                .forEach(entry -> System.out.printf("   %s: %,d requests\n", entry.getKey(), entry.getValue()));

        System.out.println("\n📈 MOST POPULAR PAGES:");
        for (int i = 0; i < Math.min(10, popularPages.size()); i++) {
            Map.Entry<String, Long> page = popularPages.get(i);
            System.out.printf("%2d. %s - %,d requests\n", i + 1, page.getKey(), page.getValue());
        }

        // Recommendations
        System.out.println("\n💡 RECOMMENDATIONS:");

        if (!suspiciousIPs.isEmpty()) {
            System.out.println("1. IMMEDIATE ACTIONS:");
            System.out.println("   - Implement rate limiting (e.g., max 100 requests/hour per IP)");
            System.out.println("   - Block or throttle the top suspicious IPs temporarily");
            System.out.println("   - Add CAPTCHA for high-traffic pages");

            System.out.println("\n2. COST-EFFECTIVE SOLUTIONS:");
            System.out.println("   - Use Cloudflare free tier for basic DDoS protection");
            System.out.println("   - Implement simple rate limiting in your web server config");
            System.out.println("   - Add monitoring alerts for traffic spikes");

            System.out.println("\n3. MONITORING:");
            System.out.println("   - Set up automated log analysis (run this program daily)");
            System.out.println("   - Monitor server resources during traffic spikes");
            System.out.println("   - Track conversion rates to distinguish good vs bad traffic");
        } else {
            System.out.println("   - No clear bot patterns detected");
            System.out.println("   - Consider investigating server capacity and optimization");
            System.out.println("   - Monitor for sudden traffic pattern changes");
        }

        return new AnalysisResults(totalRequests, uniqueIPs, suspiciousIPs.size(),
                suspiciousRequests, suspiciousIPs, popularPages);
    }

    /**
     * Results container for JSON export
     */
    public static class AnalysisResults {
        public final int totalRequests;
        public final int uniqueIPs;
        public final int suspiciousIPs;
        public final int suspiciousRequests;
        public final List<SuspiciousIP> suspiciousIPDetails;
        public final List<Map.Entry<String, Long>> popularPages;

        public AnalysisResults(int totalRequests, int uniqueIPs, int suspiciousIPs,
                               int suspiciousRequests, List<SuspiciousIP> suspiciousIPDetails,
                               List<Map.Entry<String, Long>> popularPages) {
            this.totalRequests = totalRequests;
            this.uniqueIPs = uniqueIPs;
            this.suspiciousIPs = suspiciousIPs;
            this.suspiciousRequests = suspiciousRequests;
            this.suspiciousIPDetails = suspiciousIPDetails;
            this.popularPages = popularPages;
        }
    }

    /**
     * Main method - entry point for the application
     */
    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: java BotDetectionAnalyzer <log_file_path>");
            System.exit(1);
        }

        String logFilePath = args[0];

        try {
            // Initialize analyzer
            BotDetectionAnalyzer analyzer = new BotDetectionAnalyzer(logFilePath);

            // Load and analyze logs
            analyzer.loadLogs();
            AnalysisResults results = analyzer.generateReport();

        } catch (IOException e) {
            System.err.println("Error processing log file: " + e.getMessage());
            System.exit(1);
        } catch (Exception e) {
            System.err.println("Unexpected error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}

/*
 * COMPILATION AND USAGE INSTRUCTIONS:

 * 1. DEPENDENCIES:
     - Java 8 or higher

 * 2. COMPILATION:

    javac BotDetectionAnalyzer.java

 * 3. EXECUTION:

       Basic analysis:
       java BotDetectionAnalyzer /path/to/server/logs/access.log

 * Bot Detection Analyzer - Setup Instructions:

    Open terminal/command prompt in that folder
    Run: docker build -t bot-analyzer .
    Run: docker run --rm bot-analyzer

    That's it! The analyzer will run with the sample data and show the results.
 *
 * REQUIRED SOFTWARE:
   - Java Development Kit (JDK) 8 or higher
   - Access to web server log files in Apache/Nginx common log format
 */