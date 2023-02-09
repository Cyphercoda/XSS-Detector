import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import burp.*;

public class BurpExtension implements IBurpExtender, IScannerCheck {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private List<String> xssKeywords = new ArrayList<String>();

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        // Load the list of XSS keywords from a file
        try {
            File file = new File("xss_keywords.txt");
            BufferedReader reader = new BufferedReader(new FileReader(file));
            String line;
            while ((line = reader.readLine()) != null) {
                xssKeywords.add(line);
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

        // Register this extension as a scanner check
        callbacks.registerScannerCheck(this);
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<IScanIssue>();

        // Get the request and response as byte arrays
        byte[] request = baseRequestResponse.getRequest();
        byte[] response = baseRequestResponse.getResponse();

        // Convert the response to a string
        String responseString = helpers.bytesToString(response);

        // Check for the presence of XSS keywords in the response
        for (String keyword : xssKeywords) {
            Pattern pattern = Pattern.compile(keyword);
            Matcher matcher = pattern.matcher(responseString);
            if (matcher.find()) {
                issues.add(new CustomScanIssue(baseRequestResponse,
                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    "Potential XSS vulnerability detected",
                    "The response contains the keyword " + keyword + " which may indicate a potential XSS vulnerability.",
                    "High"));
            }
        }

        return issues;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,
                                          IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue,
                                        IScanIssue newIssue) {
        return 0;
    }
}
