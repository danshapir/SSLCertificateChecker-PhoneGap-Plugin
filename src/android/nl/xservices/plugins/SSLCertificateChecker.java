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
              callbackContext.success("CONNECTION_SECURE");
            } else {
              callbackContext.success("CONNECTION_NOT_SECURE");
            }
          } catch (Exception e) {
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

	// open connection
	URL targetUrl = new URL(httpsURL);
	String host = targetUrl.getHost();
	android.util.Log.w("Certificate", "Connecting to host: " + host);
	final HttpsURLConnection con = (HttpsURLConnection) targetUrl.openConnection();
    con.connect();

	// get certificates
    Certificate[] certs = con.getServerCertificates();

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