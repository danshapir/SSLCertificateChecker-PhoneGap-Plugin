#import "SSLCertificateChecker.h"
#import <Cordova/CDV.h>
#import <Cordova/CDVPluginResult.h>
#import <CommonCrypto/CommonDigest.h>


@interface CustomURLConnectionDelegate : NSObject <NSURLConnectionDelegate>;

@property (strong, nonatomic) CDVPlugin *_plugin;
@property (strong, nonatomic) NSString *_callbackId;
@property (strong, nonatomic) NSString *_allowedFingerprint;
@property (strong, nonatomic) NSString *_allowedFingerprintAlt;
@property (strong, nonatomic) NSString *_serverUrl;
@property (nonatomic, assign) BOOL sentResponse;

- (id)initWithPlugin:(CDVPlugin*)plugin callbackId:(NSString*)callbackId allowedFingerprint:(NSString*)allowedFingerprint allowedFingerprintAlt:(NSString*)allowedFingerprintAlt url:(NSString*)url;

@end

@implementation CustomURLConnectionDelegate

- (id)initWithPlugin:(CDVPlugin*)plugin callbackId:(NSString*)callbackId allowedFingerprint:(NSString*)allowedFingerprint allowedFingerprintAlt:(NSString*)allowedFingerprintAlt url:(NSString*)url
{
	self.sentResponse = FALSE;
	self._plugin = plugin;
	self._callbackId = callbackId;
	self._allowedFingerprint = allowedFingerprint;
	self._allowedFingerprintAlt = allowedFingerprintAlt;
    self._serverUrl = url;
    return self;
}

// Delegate method, called from connectionWithRequest
- (void) connection: (NSURLConnection*)connection willSendRequestForAuthenticationChallenge: (NSURLAuthenticationChallenge*)challenge {
    
    // sanity check on parameter
    if([[NSNull null] isEqual:self._allowedFingerprint]) {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_JSON_EXCEPTION messageAsString:@"CONNECTION_NOT_SECURE"];
        [self._plugin writeJavascript:[pluginResult toErrorCallbackString:self._callbackId]];
    }
    
    BOOL fingerprintMatch = FALSE;
    BOOL domainMatch = FALSE;
    
    CFIndex count = SecTrustGetCertificateCount (challenge.protectionSpace.serverTrust);
    NSLog(@"Certificate: Certificate count: %ld", count);
    
    NSArray *allowedThumprints = [self._allowedFingerprint componentsSeparatedByString:@","];
    for(int j=0; j<allowedThumprints.count; j++) {
        NSLog(@"Certificate: allowed thumbprint %d: %@", j, allowedThumprints[j]);
    }
    
    NSURL *url = [NSURL URLWithString:self._serverUrl];
    NSString *host = [url host];
    NSLog(@"Certificate: expected host: %@", host);
    
    NSString *domainPrefix = @"*.";
    
    for(CFIndex i=0; i<count; i++) {
        
        // extract thumbprint
        SecCertificateRef cert = SecTrustGetCertificateAtIndex(challenge.protectionSpace.serverTrust, i);
        NSString* fingerprint = [self getFingerprint: cert];
        NSLog(@"Certificate: Certificate %ld thumbprint: %@", i, fingerprint);
        
        // check thumbprint if not matched yet
        if(!fingerprintMatch) {
            for(int j=0; j<allowedThumprints.count; j++) {
                if([fingerprint caseInsensitiveCompare: allowedThumprints[j]] == NSOrderedSame) {
                    fingerprintMatch = TRUE;
                    NSLog(@"Certificate: Certificate %ld thumbprint match", i);
                }
            }
        }
        
        CFStringRef summaryRef = SecCertificateCopySubjectSummary(cert);
        if(summaryRef != NULL) {
            NSString *subject = (__bridge NSString *)summaryRef;
            NSLog(@"Certificate: Certificate %ld subject: %@", i, subject);
            
            if([subject hasPrefix:domainPrefix]) {
                subject = [subject substringFromIndex:2];
            }
            
            NSLog(@"Certificate: Certificate %ld normalized subject: %@", i, subject);
            
            if([host hasSuffix:subject]) {
                domainMatch = TRUE;
            }
            
            CFRelease(summaryRef);
        }
        
    }
    
    self.sentResponse = TRUE;
    if (fingerprintMatch && domainMatch) {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:@"CONNECTION_SECURE"];
        [self._plugin writeJavascript:[pluginResult toSuccessCallbackString:self._callbackId]];
    } else {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_JSON_EXCEPTION messageAsString:@"CONNECTION_NOT_SECURE"];
        [self._plugin writeJavascript:[pluginResult toErrorCallbackString:self._callbackId]];
    }
}

// Delegate method, called from connectionWithRequest
- (void) connection: (NSURLConnection*)connection didFailWithError: (NSError*)error {
    NSString *resultCode = @"CONNECTION_FAILED. Details:";
    NSString *errStr = [NSString stringWithFormat:@"%@ %@", resultCode, [error localizedDescription]];
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_JSON_EXCEPTION messageAsString:errStr];
    [self._plugin writeJavascript:[pluginResult toErrorCallbackString:self._callbackId]];
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection
{
    if (![self sentResponse]) {
        NSLog(@"Connection was not checked because it was cached. Considering it secure to not break your app.");
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:@"CONNECTION_SECURE"];
        [self._plugin writeJavascript:[pluginResult toSuccessCallbackString:self._callbackId]];
    }
}

- (NSString*) getFingerprint: (SecCertificateRef) cert {
    NSData* certData = (__bridge NSData*) SecCertificateCopyData(cert);
    unsigned char sha1Bytes[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(certData.bytes, certData.length, sha1Bytes);
    NSMutableString *fingerprint = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 3];
    for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; ++i) {
        [fingerprint appendFormat:@"%02x ", sha1Bytes[i]];
    }
    return [fingerprint stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
}

- (BOOL) isFingerprintTrusted: (NSString*)fingerprint {
    return ((![[NSNull null] isEqual:self._allowedFingerprint] && [fingerprint caseInsensitiveCompare: self._allowedFingerprint]    == NSOrderedSame) ||
            (![[NSNull null] isEqual:self._allowedFingerprintAlt] && [fingerprint caseInsensitiveCompare: self._allowedFingerprintAlt] == NSOrderedSame));
}

@end


@interface SSLCertificateChecker ()

@property (strong, nonatomic) NSString *_callbackId;
@property (strong, nonatomic) NSMutableData *_connections;

@end

@implementation SSLCertificateChecker

- (void)check:(CDVInvokedUrlCommand*)command {
    NSString *serverURL = [command.arguments objectAtIndex:0];
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:serverURL]];
    
    CustomURLConnectionDelegate *delegate =
    [[CustomURLConnectionDelegate alloc] initWithPlugin:self callbackId:command.callbackId allowedFingerprint:[command.arguments objectAtIndex:1] allowedFingerprintAlt:[command.arguments objectAtIndex:2] url:serverURL];
    
    if (![NSURLConnection connectionWithRequest:request delegate:delegate]) {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_JSON_EXCEPTION messageAsString:@"CONNECTION_FAILED"];
        [self writeJavascript:[pluginResult toErrorCallbackString:command.callbackId]];
    }
}

@end