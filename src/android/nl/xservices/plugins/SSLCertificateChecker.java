package nl.xservices.plugins;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONException;

import javax.net.ssl.HttpsURLConnection;
import javax.security.cert.CertificateException;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

public class SSLCertificateChecker extends CordovaPlugin {

  private static final String ACTION_CHECK_EVENT = "check";
  private static char[] HEX_CHARS = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

  @Override
  public boolean execute(final String action, final JSONArray args, final CallbackContext callbackContext) throws JSONException {
    if (ACTION_CHECK_EVENT.equals(action)) {
      cordova.getThreadPool().execute(new Runnable() {
        public void run() {
          try {
            final String serverURL = args.getString(0);

			String joinedFingerPrints = args.getString(1);
            final String [] allowedFingerprint = joinedFingerPrints.split(",");

            final ArrayList<String> serverCertFingerprints = getFingerprints(serverURL);

            android.util.Log.w("Certificate", "Checking " + serverCertFingerprints.size() + " certificates against known fingerprints:" );

            for(int j=0; j<allowedFingerprint.length; j++) {
                android.util.Log.w("Certificate", "Known fingerprint: " + allowedFingerprint[j] );
            }

			boolean valid = false;
			for(int i=0; i<serverCertFingerprints.size(); i++) {
				for(int j=0; j<allowedFingerprint.length; j++) {
					if(serverCertFingerprints.get(i).equalsIgnoreCase(allowedFingerprint[j])) {
						valid = true;
						break;
					}
				}

				if(valid) {
					break;
				}
			}

            if (valid) {
                android.util.Log.w("Certificate", "Connection is secure." );
                callbackContext.success("CONNECTION_SECURE");
            } else {
                android.util.Log.e("Certificate", "Connection is not secure." );
                callbackContext.success("CONNECTION_NOT_SECURE");
            }
          } catch (Exception e) {
            android.util.Log.e("Certificate", "Error checking thumbprints: " + e.getMessage());
            callbackContext.error("CONNECTION_FAILED. Details: " + e.getMessage());
          }
        }
      });
      return true;
    } else {
      callbackContext.error("sslCertificateChecker." + action + " is not a supported function. Did you mean '" + ACTION_CHECK_EVENT + "'?");
      return false;
    }
  }

  private static ArrayList<String> getFingerprints(String httpsURL) throws IOException, NoSuchAlgorithmException, CertificateException, CertificateEncodingException {

	ArrayList<String> result = new ArrayList<String>();
	boolean urlValid = false;

    Certificate[] certs = new Certificate[0];
    URL targetUrl;
    String host;
    final HttpsURLConnection con;

    try
    {
        // create connection
        targetUrl = new URL(httpsURL);
        host = targetUrl.getHost();
        android.util.Log.w("Certificate", "Creating connection to host: " + host);
        con = (HttpsURLConnection) targetUrl.openConnection();

    }
    catch(Exception e)
    {
        android.util.Log.e("Certificate", "Error creating connection to " + httpsURL + ": " + e.getMessage());
        return result;
    }

    try
    {
        // open connection
        android.util.Log.w("Certificate", "Opening connection to host: " + host);
        con.setConnectTimeout(5000);
        con.setReadTimeout(10000);
        con.connect();
    }
    catch(Exception e)
    {
        android.util.Log.e("Certificate", "Error opening connection to " + httpsURL + ": " + e.getMessage());
        return result;
    }

    try
    {
	    // get certificates
	    android.util.Log.w("Certificate", "Getting certificates from host: " + host);
        certs = con.getServerCertificates();
    }
    catch(Exception e)
    {
        android.util.Log.e("Certificate", "Error getting certificates from " + httpsURL + ": " + e.getMessage());
        return result;
    }

	// check certificates
    android.util.Log.w("Certificate", "Certificate count: " + certs.length);
    for(int i=0; i<certs.length; i++)
    {
        android.util.Log.w("Certificate", "Certificate " + i + " type: " + certs[i].getClass().getName());

		// extract thumbprint
        MessageDigest d = MessageDigest.getInstance("SHA1");
        d.update(certs[i].getEncoded());
        String fingerPrint = dumpHex(d.digest());

		// add thumbprint to list
		result.add(fingerPrint);
        android.util.Log.w("Certificate", "Certificate " + i + " thumbprint: " + fingerPrint);

		// check url
		if(!urlValid && certs[i] instanceof java.security.cert.X509Certificate)
		{
			String subject = ((java.security.cert.X509Certificate)certs[i]).getSubjectDN().toString();
			android.util.Log.w("Certificate", "Certificate " + i + " subject: " + subject);

			// split subject into parts
			String [] subjectParts = subject.split(",");
			for(int j=0; j<subjectParts.length; j++)
			{
				if(subjectParts[j].startsWith("CN="))
				{
					String certificateHost = subjectParts[j].substring(3);
					if(certificateHost.startsWith("*."))
					{
						certificateHost = certificateHost.substring(2);
					}

					android.util.Log.w("Certificate", "Certificate " + i + " domain: " + certificateHost);

					if(host.endsWith(certificateHost))
					{
						urlValid = true;
						android.util.Log.w("Certificate", "Certificate  domain match");
					}
					else
					{
					    android.util.Log.w("Certificate", "Certificate  domain does not match");
					}
				}
			}
		}
    }

	if(!urlValid)
	{
		return new ArrayList<String>();
	}

	return result;
  }

  private static String dumpHex(byte[] data) {
    final int n = data.length;
    final StringBuilder sb = new StringBuilder(n * 3 - 1);
    for (int i = 0; i < n; i++) {
      if (i > 0) {
        sb.append(' ');
      }
      sb.append(HEX_CHARS[(data[i] >> 4) & 0x0F]);
      sb.append(HEX_CHARS[data[i] & 0x0F]);
    }
    return sb.toString();
  }
}
