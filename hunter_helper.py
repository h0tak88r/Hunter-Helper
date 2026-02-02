"""
Burp Suite Extension: Hunter Helper
A suite of tools to help bug hunters: Request conversion, POC generation, and beautiful sharing.
"""

from burp import IBurpExtender, IContextMenuFactory, IContextMenuInvocation
from javax.swing import JMenuItem
from java.awt import Toolkit, Color, Font, Graphics2D, RenderingHints
from java.awt.datatransfer import StringSelection, Clipboard, Transferable, DataFlavor, UnsupportedFlavorException
from java.awt.image import BufferedImage
from javax.swing import JTextPane
from javax.swing.border import EmptyBorder
import json
import urllib
import sys
import re
import base64
import xml.etree.ElementTree as ET
from xml.dom import minidom
from java.io import File, FileWriter

class BurpExtender(IBurpExtender, IContextMenuFactory):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("Hunter Helper")
        callbacks.registerContextMenuFactory(self)
        
        print("\n" + "="*50)
        print("    Hunter Helper - Loaded Successfully")
        print("="*50)
        print("\n[+] Features Ready:")
        print("    1. Content-Type Conversion")
        print("       - XML <-> JSON <-> URL-Encoded")
        print("       - JSON POST -> GET Request")
        print("\n    2. POC Generation")
        print("       - Copy as JavaScript fetch() POC")
        print("\n    3. Smart Sharing (New!)")
        print("       - Copy as Image (Syntax Highlighted)")
        print("       - Side-by-Side Request/Response View")
        print("       - Auto-Censoring (Cookies/Auth)")
        print("       - Noise Header Filtering")
        print("\n[+] Usage: Right-click on any request to access 'Hunter Helper' menu.")
        print("="*50 + "\n")
    
    def createMenuItems(self, invocation):
        menu_items = []
        
        # Only show menu in appropriate contexts
        if invocation.getInvocationContext() not in [
            IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
            IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST
        ]:
            return menu_items
        
        # Create menu items
        menu_items.append(JMenuItem("Convert to XML", actionPerformed=lambda x: self.convert_to_xml(invocation)))
        menu_items.append(JMenuItem("Convert to JSON", actionPerformed=lambda x: self.convert_to_json(invocation)))
        menu_items.append(JMenuItem("Convert JSON to URL-encoded", actionPerformed=lambda x: self.convert_to_urlencoded(invocation)))
        menu_items.append(JMenuItem("Convert JSON to GET Request", actionPerformed=lambda x: self.convert_to_get(invocation)))
        menu_items.append(JMenuItem("Copy as fetch POC", actionPerformed=lambda x: self.copy_as_fetch_poc(invocation)))
        menu_items.append(JMenuItem("Copy as image", actionPerformed=lambda x: self.copy_as_image(invocation)))
        menu_items.append(JMenuItem("Copy Session Headers", actionPerformed=lambda x: self.copy_session_headers(invocation)))
        menu_items.append(JMenuItem("Decode JWT", actionPerformed=lambda x: self.decode_jwt(invocation)))
        menu_items.append(JMenuItem("Copy as Markdown", actionPerformed=lambda x: self.copy_as_markdown(invocation)))
        menu_items.append(JMenuItem("Copy as CSRF HTML POC", actionPerformed=lambda x: self.copy_as_csrf_poc(invocation)))
        menu_items.append(JMenuItem("Test CSRF POC in Browser", actionPerformed=lambda x: self.test_csrf_in_browser(invocation)))
        
        return menu_items

    def copy_session_headers(self, invocation):
        """Extract and copy session-related headers to clipboard"""
        try:
            request_response = invocation.getSelectedMessages()[0]
            request = request_response.getRequest()
            request_info = self._helpers.analyzeRequest(request)
            headers = request_info.getHeaders()
            
            # List of session/auth/csrf headers to look for (lowercase for matching)
            target_headers = [
                'authorization', 'proxy-authorization', 'cookie', 'set-cookie',
                'x-auth-token', 'session-id', 'x-session-id',
                'x-csrf-token', 'x-xsrf-token', 'x-csrftoken', 'x-xsrftoken',
                'x-request-verification-token', 'request-verification-token',
                'anti-forgery-token', 'x-anti-forgery-token'
            ]
            
            extracted_headers = []
            
            # Iterate and find matches
            for header in headers:
                if ':' in header:
                    name, value = header.split(':', 1)
                    name_clean = name.strip().lower()
                    
                    if name_clean in target_headers:
                        extracted_headers.append(header)
            
            if not extracted_headers:
                print("[-] No session headers found in the selected request.")
                return

            # Join with newlines
            clipboard_content = '\n'.join(extracted_headers)
            
            # Copy to clipboard
            toolkit = Toolkit.getDefaultToolkit()
            clipboard = toolkit.getSystemClipboard()
            selection = StringSelection(clipboard_content)
            clipboard.setContents(selection, selection)
            
            print("[+] Copied {} session headers to clipboard!".format(len(extracted_headers)))
            
        except Exception as e:
            print("[-] Error copying session headers: " + str(e))
            import traceback
            traceback.print_exc()

    def decode_jwt(self, invocation):
        """Decode JWT tokens and provide security recommendations"""
        try:
            request_response = invocation.getSelectedMessages()[0]
            request = request_response.getRequest()
            response = request_response.getResponse()
            
            request_info = self._helpers.analyzeRequest(request)
            headers = request_info.getHeaders()
            body_offset = request_info.getBodyOffset()
            req_body_bytes = request[body_offset:].tostring()
            # Decode with error handling for non-ASCII characters
            try:
                req_body = req_body_bytes.decode('utf-8', 'replace')
            except:
                req_body = req_body_bytes
            
            # Also check response if present
            resp_body = ""
            if response:
                resp_info = self._helpers.analyzeResponse(response)
                resp_body_offset = resp_info.getBodyOffset()
                resp_body_bytes = response[resp_body_offset:].tostring()
                # Decode with error handling for non-ASCII characters
                try:
                    resp_body = resp_body_bytes.decode('utf-8', 'replace')
                except:
                    resp_body = resp_body_bytes
            
            # JWT pattern: xxx.yyy.zzz (base64url segments)
            jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
            
            found_jwts = []
            
            # Search in headers
            for header in headers:
                if ':' in header:
                    name, value = header.split(':', 1)
                    matches = re.findall(jwt_pattern, value)
                    for match in matches:
                        found_jwts.append(('Header: ' + name.strip(), match))
            
            # Search in request body
            req_matches = re.findall(jwt_pattern, req_body)
            for match in req_matches:
                found_jwts.append(('Request Body', match))
            
            # Search in response body
            resp_matches = re.findall(jwt_pattern, resp_body)
            for match in resp_matches:
                found_jwts.append(('Response Body', match))
            
            if not found_jwts:
                print("[-] No JWT tokens found in the request/response.")
                return
            
            print("\n" + "="*60)
            print("JWT DECODER - Security Analysis")
            print("="*60 + "\n")
            
            for idx, (location, jwt_token) in enumerate(found_jwts):
                print("[+] JWT #{} found in: {}".format(idx + 1, location))
                print("-" * 60)
                
                try:
                    # Decode JWT
                    parts = jwt_token.split('.')
                    if len(parts) < 2:
                        print("[-] Invalid JWT format\n")
                        continue
                    
                    # Decode header
                    header_decoded = self._base64url_decode(parts[0])
                    header_json = json.loads(header_decoded)
                    
                    # Decode payload
                    payload_decoded = self._base64url_decode(parts[1])
                    payload_json = json.loads(payload_decoded)
                    
                    # Print decoded values
                    print("\nHeader:")
                    print(json.dumps(header_json, indent=2))
                    
                    print("\nPayload:")
                    print(json.dumps(payload_json, indent=2))
                    
                    # Security Analysis
                    print("\n" + "="*60)
                    print("SECURITY RECOMMENDATIONS:")
                    print("="*60)
                    
                    alg = header_json.get('alg', 'unknown').upper()
                    
                    if alg == 'NONE':
                        print("\n[!!! CRITICAL !!!]")
                        print("Algorithm: 'none' detected!")
                        print("Attack: Try removing the signature portion of the JWT.")
                        print("Example: Just send 'header.payload.' (keep the trailing dot)")
                        
                    elif alg in ['HS256', 'HS384', 'HS512']:
                        print("\n[!! WARNING !!]")
                        print("Algorithm: {} (Symmetric HMAC)".format(alg))
                        print("Attack 1: Brute force the secret key using a wordlist.")
                        print("Tools: hashcat, jwt_tool, john the ripper")
                        print("Attack 2: Try weak secrets like 'secret', 'password', etc.")
                        
                    elif alg in ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512']:
                        print("\n[! INFO !]")
                        print("Algorithm: {} (Asymmetric RSA/PSS)".format(alg))
                        print("Attack: Algorithm confusion (RS256 -> HS256)")
                        print("Description: Try changing 'alg' to 'HS256' and sign with the")
                        print("             public key (treated as symmetric secret).")
                        
                    elif alg in ['ES256', 'ES384', 'ES512']:
                        print("\n[! INFO !]")
                        print("Algorithm: {} (Asymmetric ECDSA)".format(alg))
                        print("Attack: Algorithm confusion or key confusion attacks may apply.")
                    
                    else:
                        print("\n[! INFO !]")
                        print("Algorithm: {} (Unknown/Custom)".format(alg))
                        print("Manual analysis recommended.")
                    
                    # Check expiration
                    if 'exp' in payload_json:
                        import time
                        exp_time = payload_json['exp']
                        current_time = int(time.time())
                        
                        if exp_time < current_time:
                            print("\n[! EXPIRED !]")
                            print("Token expired at: {}".format(exp_time))
                        else:
                            print("\n[OK] Token valid until: {}".format(exp_time))
                    else:
                        print("\n[! WARNING !] No expiration claim (exp) found.")
                        print("Token might be valid indefinitely!")
                    
                    # Check standard claims
                    print("\n" + "-"*60)
                    print("Standard Claims:")
                    for claim in ['sub', 'iss', 'aud', 'iat', 'nbf']:
                        if claim in payload_json:
                            print("  {}: {}".format(claim, payload_json[claim]))
                    
                    print("\n" + "="*60 + "\n")
                    
                except Exception as decode_error:
                    print("[-] Error decoding JWT: " + str(decode_error))
                    print("\n")
            
        except Exception as e:
            print("[-] Error in JWT decoder: " + str(e))
            import traceback
            traceback.print_exc()
    
    def copy_as_markdown(self, invocation):
        """Copy request/response as markdown with smart header filtering"""
        print("[DEBUG] copy_as_markdown called")
        try:
            request_response = invocation.getSelectedMessages()[0]
            request = request_response.getRequest()
            response = request_response.getResponse()
            
            # Analyze request
            request_info = self._helpers.analyzeRequest(request)
            req_body_offset = request_info.getBodyOffset()
            req_body_bytes = request[req_body_offset:].tostring()
            # Decode with error handling for non-ASCII characters
            try:
                req_body = req_body_bytes.decode('utf-8', 'replace')
            except:
                req_body = req_body_bytes
            req_headers = request_info.getHeaders()
            
            # Analyze response (if present)
            resp_headers = []
            resp_body = ""
            if response:
                resp_info = self._helpers.analyzeResponse(response)
                resp_body_offset = resp_info.getBodyOffset()
                resp_body_bytes = response[resp_body_offset:].tostring()
                # Decode with error handling for non-ASCII characters
                try:
                    resp_body = resp_body_bytes.decode('utf-8', 'replace')
                except:
                    resp_body = resp_body_bytes
                resp_headers = resp_info.getHeaders()
            
            # Sensitive headers to censor
            SENSITIVE_HEADERS = ['cookie', 'authorization', 'set-cookie', 'x-auth-token', 'session-id', 'sessionid']
            
            # Noise headers to filter out
            NOISE_HEADERS = [
                'connection', 'content-length', 'date', 'keep-alive', 'vary', 'server', 'etag', 
                'cache-control', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 
                'upgrade-insecure-requests', 'accept-language', 'accept-encoding', 
                'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'sec-fetch-user',
                'pragma', 'expires', 'last-modified', 'x-powered-by', 'x-aspnet-version',
                'content-security-policy', 'x-xss-protection', 'x-ua-compatible', 'referrer-policy',
                'strict-transport-security', 'x-content-type-options',
                'via', 'cf-cache-status', 'cf-ray'
            ]
            
            markdown_lines = []
            markdown_lines.append("Request")
            markdown_lines.append("```http")
            
            # Request first line
            if req_headers and len(req_headers) > 0:
                markdown_lines.append(req_headers[0])
                
                # Request headers (filtered)
                for h in req_headers[1:]:
                    if ':' in h:
                        k, v = h.split(':', 1)
                        k_clean = k.strip()
                        v_clean = v.strip()
                        k_lower = k_clean.lower()
                        
                        # Skip noise headers
                        if k_lower in NOISE_HEADERS:
                            continue
                        
                        # Censor sensitive headers
                        if k_lower in SENSITIVE_HEADERS:
                            v_clean = "********"
                        
                        markdown_lines.append("{}: {}".format(k_clean, v_clean))
            
            # Request body
            if req_body:
                markdown_lines.append("")
                markdown_lines.append(req_body)
            
            markdown_lines.append("```")
            markdown_lines.append("")
            
            # Response section
            if resp_headers:
                markdown_lines.append("Response")
                markdown_lines.append("```http")
                
                # Response status line
                if len(resp_headers) > 0:
                    markdown_lines.append(resp_headers[0])
                    
                    # Response headers (filtered)
                    for h in resp_headers[1:]:
                        if ':' in h:
                            k, v = h.split(':', 1)
                            k_clean = k.strip()
                            v_clean = v.strip()
                            k_lower = k_clean.lower()
                            
                            # Skip noise headers
                            if k_lower in NOISE_HEADERS:
                                continue
                            
                            # Censor sensitive headers
                            if k_lower in SENSITIVE_HEADERS:
                                v_clean = "********"
                            
                            markdown_lines.append("{}: {}".format(k_clean, v_clean))
                
                # Response body
                if resp_body:
                    markdown_lines.append("")
                    markdown_lines.append(resp_body)
                
                markdown_lines.append("```")
            
            # Join and copy to clipboard
            markdown_content = '\n'.join(markdown_lines)
            
            # Print Markdown to output for easy copying
            print("\n" + "="*60)
            print("Markdown Output - Copy the content below:")
            print("="*60)
            print(markdown_content)
            print("="*60 + "\n")
            
            # Try to copy to clipboard (may fail on some systems)
            try:
                toolkit = Toolkit.getDefaultToolkit()
                clipboard = toolkit.getSystemClipboard()
                selection = StringSelection(markdown_content)
                clipboard.setContents(selection, selection)
                print("[+] Also copied to clipboard!")
            except Exception as clipboard_error:
                print("[-] Clipboard copy failed: " + str(clipboard_error))
                print("[+] Please copy the Markdown from the output above")
            
        except Exception as e:
            print("[-] Error copying as markdown: " + str(e))
            import traceback
            traceback.print_exc()

    def copy_as_csrf_poc(self, invocation):
        """Generate CSRF HTML POC and copy to clipboard"""
        print("[DEBUG] copy_as_csrf_poc called")
        try:
            print("[DEBUG] Getting request...")
            request_response = invocation.getSelectedMessages()[0]
            request = request_response.getRequest()
            http_service = request_response.getHttpService()
            request_info = self._helpers.analyzeRequest(http_service, request)
            
            print("[DEBUG] Extracting method and URL...")
            # Get method and URL
            method = request_info.getMethod()
            url = request_info.getUrl().toString()
            
            print("[DEBUG] Method: " + method + ", URL: " + url)
            
            # Get parameters
            parameters = request_info.getParameters()
            print("[DEBUG] Found " + str(len(parameters)) + " parameters")
            
            # Determine encoding type
            content_type = request_info.getContentType()
            enctype = ""
            if content_type == 2:  # MULTIPART
                enctype = ' enctype="multipart/form-data"'
            
            print("[DEBUG] Building HTML POC...")
            # Build HTML POC
            html_lines = []
            html_lines.append("<!DOCTYPE html>")
            html_lines.append("<html>")
            html_lines.append("  <!-- CSRF PoC - Hunter Helper -->")
            html_lines.append("  <body>")
            html_lines.append('    <form method="{}" action="{}"{}>'.format(method, self._escape_html(url), enctype))
            
            # Add input fields for parameters
            for param in parameters:
                try:
                    param_type = param.getType()
                    
                    # Skip URL parameters if method is POST (they're already in the action URL)
                    if method.upper() == "POST" and param_type == 0:  # URL parameter
                        continue
                    
                    # Skip cookies - browsers send them automatically
                    if param_type == 2:  # Cookie parameter
                        continue
                    
                    # Get parameter name and value, handle unicode properly
                    param_name = param.getName()
                    param_value = param.getValue()
                    
                    # Convert to string and handle unicode
                    if isinstance(param_name, unicode):
                        name = param_name.encode('utf-8', 'replace')
                    else:
                        name = str(param_name)
                    
                    if isinstance(param_value, unicode):
                        value = param_value.encode('utf-8', 'replace')
                    else:
                        value = str(param_value)
                    
                    # Escape HTML entities
                    name = self._escape_html(name)
                    value = self._escape_html(value)
                    
                    html_lines.append('      <input type="text" name="{}" value="{}">'.format(name, value))
                except Exception as param_error:
                    # Skip problematic parameters
                    print("[-] Warning: Skipped parameter due to encoding issue: " + str(param_error))
                    continue
            
            html_lines.append('      <input type="submit" value="Submit Request">')
            html_lines.append('    </form>')
            html_lines.append('    <script>')
            html_lines.append('      document.forms[0].submit();')
            html_lines.append('    </script>')
            html_lines.append('  </body>')
            html_lines.append('</html>')
            
            print("[DEBUG] Joining HTML lines...")
            # Join and copy to clipboard
            html_poc = '\n'.join(html_lines)
            
            print("[DEBUG] HTML POC generated, length: " + str(len(html_poc)))
            
            # Print POC to output for easy copying
            print("\n" + "="*60)
            print("CSRF HTML POC - Copy the content below:")
            print("="*60)
            print(html_poc)
            print("="*60 + "\n")
            
            # Try to copy to clipboard (may fail on some systems)
            try:
                print("[DEBUG] Copying to clipboard...")
                toolkit = Toolkit.getDefaultToolkit()
                clipboard = toolkit.getSystemClipboard()
                selection = StringSelection(html_poc)
                clipboard.setContents(selection, selection)
                print("[+] Also copied to clipboard!")
            except Exception as clipboard_error:
                print("[-] Clipboard copy failed: " + str(clipboard_error))
                print("[+] Please copy the POC from the output above")
            
            print("[+] Save as .html file and open in browser to test")
            
        except Exception as e:
            print("[-] Error generating CSRF POC: " + str(e))
            import traceback
            traceback.print_exc()

    def test_csrf_in_browser(self, invocation):
        """Generate CSRF HTML POC, save to temp file, and copy file:/// URL to clipboard"""
        print("[DEBUG] test_csrf_in_browser called")
        try:
            request_response = invocation.getSelectedMessages()[0]
            request = request_response.getRequest()
            http_service = request_response.getHttpService()
            request_info = self._helpers.analyzeRequest(http_service, request)
            
            # Get method and URL
            method = request_info.getMethod()
            url = request_info.getUrl().toString()
            
            # Get parameters
            parameters = request_info.getParameters()
            
            # Determine encoding type
            content_type = request_info.getContentType()
            enctype = ""
            if content_type == 2:  # MULTIPART
                enctype = ' enctype="multipart/form-data"'
            
            # Build HTML POC (same as copy_as_csrf_poc)
            html_lines = []
            html_lines.append("<!DOCTYPE html>")
            html_lines.append("<html>")
            html_lines.append("  <!-- CSRF PoC - Hunter Helper -->")
            html_lines.append("  <body>")
            html_lines.append('    <form method="{}" action="{}"{}>'.format(method, self._escape_html(url), enctype))
            
            # Add input fields for parameters
            for param in parameters:
                try:
                    param_type = param.getType()
                    
                    # Skip URL parameters if method is POST (they're already in the action URL)
                    if method.upper() == "POST" and param_type == 0:  # URL parameter
                        continue
                    
                    # Skip cookies - browsers send them automatically
                    if param_type == 2:  # Cookie parameter
                        continue
                    
                    # Get parameter name and value, handle unicode properly
                    param_name = param.getName()
                    param_value = param.getValue()
                    
                    # Convert to string and handle unicode
                    if isinstance(param_name, unicode):
                        name = param_name.encode('utf-8', 'replace')
                    else:
                        name = str(param_name)
                    
                    if isinstance(param_value, unicode):
                        value = param_value.encode('utf-8', 'replace')
                    else:
                        value = str(param_value)
                    
                    # Escape HTML entities
                    name = self._escape_html(name)
                    value = self._escape_html(value)
                    
                    html_lines.append('      <input type="text" name="{}" value="{}">'.format(name, value))
                except Exception as param_error:
                    # Skip problematic parameters
                    print("[-] Warning: Skipped parameter due to encoding issue: " + str(param_error))
                    continue
            
            html_lines.append('      <input type="submit" value="Submit Request">')
            html_lines.append('    </form>')
            html_lines.append('    <script>')
            html_lines.append('      document.forms[0].submit();')
            html_lines.append('    </script>')
            html_lines.append('  </body>')
            html_lines.append('</html>')
            
            # Join HTML
            html_poc = '\n'.join(html_lines)
            
            # Create temporary file
            temp_file = File.createTempFile("csrf_poc_", ".html")
            temp_file.deleteOnExit()  # Auto-cleanup when JVM exits
            
            # Write HTML to file using Java FileWriter for better compatibility
            writer = None
            try:
                writer = FileWriter(temp_file)
                writer.write(html_poc)
                writer.flush()
            finally:
                if writer:
                    writer.close()
            
            # Create file:/// URL
            file_url = "file://" + temp_file.getAbsolutePath()
            
            # Copy file URL to clipboard
            toolkit = Toolkit.getDefaultToolkit()
            clipboard = toolkit.getSystemClipboard()
            selection = StringSelection(file_url)
            clipboard.setContents(selection, selection)
            
            print("[+] CSRF POC saved to: " + temp_file.getAbsolutePath())
            print("[+] file:/// URL copied to clipboard!")
            print("[+] Paste the URL into any browser to test the CSRF attack")
            
        except Exception as e:
            print("[-] Error testing CSRF POC: " + str(e))
            import traceback
            traceback.print_exc()

    def convert_to_xml(self, invocation):
        """Convert request body to XML format"""
        try:
            request_response = invocation.getSelectedMessages()[0]
            request = request_response.getRequest()
            request_info = self._helpers.analyzeRequest(request)
            
            # Get body
            body_offset = request_info.getBodyOffset()
            body = request[body_offset:].tostring()
            
            # Parse based on content type
            content_type = request_info.getContentType()
            
            if content_type in [0, 1]:  # URL-encoded or multipart
                params = self._parse_urlencoded(body)
                xml_str = self._dict_to_xml(params)
            else:
                # Try parsing as JSON
                try:
                    data = json.loads(body)
                    xml_str = self._dict_to_xml(data)
                except:
                    print("[-] Failed to parse body as JSON")
                    return
            
            # Update headers
            headers = list(request_info.getHeaders())
            headers = [h for h in headers if not h.lower().startswith("content-type")]
            headers.append("Content-Type: application/xml")
            
            # Build new request
            new_request = self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(xml_str))
            request_response.setRequest(new_request)
            
            print("[+] Converted to XML successfully")
        except Exception as e:
            print("[-] Error converting to XML: " + str(e))
    
    def convert_to_json(self, invocation):
        """Convert request body to JSON format"""
        try:
            request_response = invocation.getSelectedMessages()[0]
            request = request_response.getRequest()
            request_info = self._helpers.analyzeRequest(request)
            
            # Get body
            body_offset = request_info.getBodyOffset()
            body = request[body_offset:].tostring()
            
            # Parse based on content type
            content_type = request_info.getContentType()
            
            if content_type in [0, 1]:  # URL-encoded or multipart
                params = self._parse_urlencoded(body)
                json_str = json.dumps(params, indent=2)
            elif content_type == 3:  # XML
                try:
                    data = self._xml_to_dict(body)
                    json_str = json.dumps(data, indent=2)
                except:
                    print("[-] Failed to parse body as XML")
                    return
            else:
                json_str = body
            
            # Update headers
            headers = list(request_info.getHeaders())
            headers = [h for h in headers if not h.lower().startswith("content-type")]
            headers.append("Content-Type: application/json")
            
            # Build new request
            new_request = self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(json_str))
            request_response.setRequest(new_request)
            
            print("[+] Converted to JSON successfully")
        except Exception as e:
            print("[-] Error converting to JSON: " + str(e))
    
    def convert_to_urlencoded(self, invocation):
        """Convert JSON POST to URL-encoded format"""
        try:
            request_response = invocation.getSelectedMessages()[0]
            request = request_response.getRequest()
            request_info = self._helpers.analyzeRequest(request)
            
            # Get body
            body_offset = request_info.getBodyOffset()
            body = request[body_offset:].tostring()
            
            # Parse JSON
            try:
                data = json.loads(body)
            except:
                print("[-] Body is not valid JSON")
                return
            
            # Convert to URL-encoded
            urlencoded = self._json_to_urlencoded(data)
            
            # Update headers
            headers = list(request_info.getHeaders())
            headers = [h for h in headers if not h.lower().startswith("content-type") and not h.lower().startswith("content-length")]
            headers.append("Content-Type: application/x-www-form-urlencoded")
            
            # Build new request
            new_request = self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(urlencoded))
            request_response.setRequest(new_request)
            
            print("[+] Converted to URL-encoded successfully")
        except Exception as e:
            print("[-] Error converting to URL-encoded: " + str(e))
    
    def convert_to_get(self, invocation):
        """Convert JSON POST to GET request"""
        try:
            request_response = invocation.getSelectedMessages()[0]
            request = request_response.getRequest()
            request_info = self._helpers.analyzeRequest(request)
            
            # Get body
            body_offset = request_info.getBodyOffset()
            body = request[body_offset:].tostring()
            
            # Parse JSON
            try:
                data = json.loads(body)
            except:
                print("[-] Body is not valid JSON")
                return
            
            # Convert to URL parameters
            params = self._json_to_urlencoded(data)
            
            # Update first line to GET
            headers = list(request_info.getHeaders())
            first_line = headers[0]
            parts = first_line.split(' ', 2)
            
            # Add parameters to URL
            url = parts[1]
            separator = '&' if '?' in url else '?'
            new_first_line = 'GET ' + url + separator + params
            if len(parts) > 2:
                new_first_line += ' ' + parts[2]
            
            headers[0] = new_first_line
            
            # Remove content-type and content-length
            headers = [h for h in headers if not h.lower().startswith("content-type") and not h.lower().startswith("content-length")]
            
            # Build new request with empty body
            new_request = self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(''))
            request_response.setRequest(new_request)
            
            print("[+] Converted to GET request successfully")
        except Exception as e:
            print("[-] Error converting to GET: " + str(e))
    
    def copy_as_fetch_poc(self, invocation):
        """Generate JavaScript fetch POC code and copy to clipboard"""
        try:
            request_response = invocation.getSelectedMessages()[0]
            request = request_response.getRequest()
            request_info = self._helpers.analyzeRequest(request)
            
            # Extract request components
            method = request_info.getMethod()
            headers = request_info.getHeaders()
            
            # Get body
            body_offset = request_info.getBodyOffset()
            body = request[body_offset:].tostring() if body_offset < len(request) else ""
            
            # Extract URL from request headers
            # First line format: "METHOD /path?query HTTP/1.1"
            first_line = headers[0]
            parts = first_line.split(' ')
            if len(parts) >= 2:
                relative_url = parts[1]  # This is already the relative path
            else:
                relative_url = "/"
            
            # Filter headers - remove browser-managed ones
            ignore_headers = ['host', 'connection', 'content-length', 'cookie', 'referer',
                            'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'te']
            
            filtered_headers = {}
            for header in headers[1:]:  # Skip first line
                if ':' in header:
                    name, value = header.split(':', 1)
                    name = name.strip().lower()
                    value = value.strip()
                    if name not in ignore_headers:
                        filtered_headers[name] = value
            
            # Build JavaScript fetch code
            poc_lines = []
            poc_lines.append('fetch("' + self._escape_js(relative_url) + '", {')
            poc_lines.append('  method: "' + method + '",')
            
            # Add headers
            if filtered_headers:
                poc_lines.append('  headers: {')
                header_items = list(filtered_headers.items())
                for i, (name, value) in enumerate(header_items):
                    comma = ',' if i < len(header_items) - 1 else ''
                    poc_lines.append('    "' + self._escape_js(name) + '": "' + self._escape_js(value) + '"' + comma)
                poc_lines.append('  },')
            
            # Add body for POST/PUT/PATCH/DELETE
            if body and method.upper() in ['POST', 'PUT', 'PATCH', 'DELETE']:
                content_type = filtered_headers.get('content-type', '')
                if 'application/json' in content_type.lower():
                    # Try to parse and format as JSON
                    try:
                        obj = json.loads(body)
                        poc_lines.append('  body: JSON.stringify(' + json.dumps(obj) + '),')
                    except:
                        poc_lines.append('  body: ' + json.dumps(body) + ',')
                else:
                    poc_lines.append('  body: ' + json.dumps(body) + ',')
            
            # Add credentials to include cookies
            poc_lines.append('  credentials: "include"')
            poc_lines.append('})')
            poc_lines.append('.then(r => r.json())')
            poc_lines.append('.then(data => console.log(data))')
            poc_lines.append('.catch(err => console.error(err));')
            
            # Join and copy to clipboard
            poc_code = '\n'.join(poc_lines)
            
            # Copy to clipboard with multiple attempts
            try:
                toolkit = Toolkit.getDefaultToolkit()
                clipboard = toolkit.getSystemClipboard()
                selection = StringSelection(poc_code)
                clipboard.setContents(selection, selection)
                print("[+] POC code copied to clipboard successfully!")
            except Exception as clipboard_error:
                print("[-] Clipboard error: " + str(clipboard_error))
                print("[!] POC code generated but clipboard copy failed. Code shown below:")
            
            # Always print the code so user can copy manually if clipboard fails
            print("\n" + "="*60)
            print("GENERATED FETCH POC CODE:")
            print("="*60)
            print(poc_code)
            print("="*60 + "\n")
            
        except Exception as e:
            print("[-] Error generating POC: " + str(e))
            import traceback
            traceback.print_exc()
    
    def copy_as_image(self, invocation):
        """Generate a colorful image of the request/response and copy to clipboard"""
        try:
            request_response = invocation.getSelectedMessages()[0]
            request = request_response.getRequest()
            response = request_response.getResponse()
            
            # Analyze request
            request_info = self._helpers.analyzeRequest(request)
            req_body_offset = request_info.getBodyOffset()
            req_body = request[req_body_offset:].tostring()
            req_headers = request_info.getHeaders()
            
            # Analyze response (if present)
            resp_info = None
            resp_body = ""
            resp_headers = []
            if response:
                resp_info = self._helpers.analyzeResponse(response)
                resp_body_offset = resp_info.getBodyOffset()
                resp_body = response[resp_body_offset:].tostring()
                resp_headers = resp_info.getHeaders()
            
            # Generate HTML representation
            html_content = self._get_colored_html(req_headers, req_body, resp_headers, resp_body)
            
            # Convert to Image
            image = self._create_image_from_html(html_content)
            
            # Copy to Clipboard
            self._copy_image_to_clipboard(image)
            
            print("[+] Image copied to clipboard successfully!")
            
        except Exception as e:
            print("[-] Error converting to image: " + str(e))
            import traceback
            traceback.print_exc()

    def _get_colored_html(self, req_headers, req_body, resp_headers, resp_body):
        """Generate HTML with syntax highlighting for request/response (Side-by-Side)"""
        # Style constants
        STYLE = """
        <style>
            body { font-family: 'Courier New', monospace; font-size: 11px; background-color: #1e1e1e; color: #d4d4d4; }
            table { width: 100%; border-collapse: collapse; }
            td { vertical-align: top; padding: 10px; }
            .divider { border-right: 1px solid #3e3e3e; }
            .method { color: #569cd6; font-weight: bold; }
            .url { color: #ce9178; }
            .version { color: #b5cea8; }
            .header-name { color: #9cdcfe; font-weight: bold; }
            .header-value { color: #ce9178; }
            .body { color: #d4d4d4; white-space: pre-wrap; word-wrap: break-word; } 
            .section-header { color: #c586c0; font-weight: bold; padding-bottom: 5px; border-bottom: 1px solid #333; margin-bottom: 10px; display: block; }
            .status { color: #b5cea8; font-weight: bold; }
        </style>
        """
        
        # Sensitive headers to censor
        SENSITIVE_HEADERS = ['cookie', 'authorization', 'set-cookie', 'x-auth-token', 'session-id', 'sessionid']
        
        # Useless/Noise headers to filter out
        NOISE_HEADERS = [
            'connection', 'content-length', 'date', 'keep-alive', 'vary', 'server', 'etag', 
            'cache-control', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 
            'upgrade-insecure-requests', 'accept-language', 'accept-encoding', 
            'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'sec-fetch-user',
            'pragma', 'expires', 'last-modified', 'x-powered-by', 'x-aspnet-version',
            # Security headers (often noise for sharing POCs unless the vulnerability is about them)
            'content-security-policy', 'x-xss-protection', 'x-ua-compatible', 'referrer-policy',
            'strict-transport-security', 'x-content-type-options',
            # Proxy/CDN headers
            'via', 'cf-cache-status', 'cf-ray'
        ]
        
        html = ["<html><head>" + STYLE + "</head><body>"]
        html.append("<table><tr>")
        
        # --- LEFT COLUMN: REQUEST ---
        html.append("<td width='50%' class='divider'>")
        html.append("<div class='section-header'>REQUEST</div>")
        
        # Request Line
        if req_headers and len(req_headers) > 0:
            parts = req_headers[0].split(' ', 2)
            if len(parts) == 3:
                html.append("<div><span class='method'>{}</span> <span class='url'>{}</span> <span class='version'>{}</span></div>".format(
                    self._escape_html(parts[0]), self._escape_html(parts[1]), self._escape_html(parts[2])))
            else:
                html.append("<div>{}</div>".format(self._escape_html(req_headers[0])))
            
            # Request Headers
            for h in req_headers[1:]:
                if ':' in h:
                    k, v = h.split(':', 1)
                    k_clean = k.strip()
                    v_clean = v.strip()
                    k_lower = k_clean.lower()
                    
                    # Filter noise headers
                    if k_lower in NOISE_HEADERS:
                        continue
                        
                    # Censor sensitive headers
                    if k_lower in SENSITIVE_HEADERS:
                        v_clean = "********"
                    
                    html.append("<div><span class='header-name'>{}</span>: <span class='header-value'>{}</span></div>".format(
                        self._escape_html(k_clean), self._escape_html(v_clean)))
                else:
                    html.append("<div>{}</div>".format(self._escape_html(h)))
        
        # Request Body
        if req_body:
            pretty_body = self._pretty_print_body(req_body, req_headers)
            formatted_body = self._format_body_to_html(pretty_body)
            html.append("<br/><div class='body'>{}</div>".format(formatted_body))
            
        html.append("</td>")

        # --- RIGHT COLUMN: RESPONSE ---
        html.append("<td width='50%'>")
        if resp_headers:
            html.append("<div class='section-header'>RESPONSE</div>")
            
            # Response Status Line
            if len(resp_headers) > 0:
                parts = resp_headers[0].split(' ', 2)
                if len(parts) >= 2:
                    html.append("<div><span class='version'>{}</span> <span class='status'>{}</span></div>".format(
                        self._escape_html(parts[0]), self._escape_html(resp_headers[0][len(parts[0])+1:])))
                else:
                     html.append("<div>{}</div>".format(self._escape_html(resp_headers[0])))

            # Response Headers
            for h in resp_headers[1:]:
               if ':' in h:
                    k, v = h.split(':', 1)
                    k_clean = k.strip()
                    v_clean = v.strip()
                    k_lower = k_clean.lower()
                    
                    # Filter noise headers
                    if k_lower in NOISE_HEADERS:
                        continue
                    
                    # Censor sensitive headers
                    if k_lower in SENSITIVE_HEADERS:
                        v_clean = "********"
                        
                    html.append("<div><span class='header-name'>{}</span>: <span class='header-value'>{}</span></div>".format(
                        self._escape_html(k_clean), self._escape_html(self._break_long_words(v_clean))))
               else:
                    html.append("<div>{}</div>".format(self._escape_html(h)))
            
            # Response Body
            if resp_body:
                 # user requested raw body but with wrapping
                 formatted_body = self._format_body_to_html(resp_body)
                 html.append("<br/><div class='body'>{}</div>".format(formatted_body))
        
        html.append("</td>")
        html.append("</tr></table>")
        html.append("</body></html>")
        return "".join(html)

    def _format_body_to_html(self, text):
        """Format text for HTML display: wrap long words, preserve whitespace"""
        if not text:
            return ""
        
        # 1. Escape HTML first
        escaped = self._escape_html(text)
        
        # 2. Break very long contiguous words (like tokens) so they don't widen the table
        # We process line by line to respect existing structure
        lines = escaped.split('\n')
        wrapped_lines = []
        for line in lines:
            words = line.split(' ')
            wrapped_words = []
            for word in words:
                wrapped_words.append(self._break_long_words(word))
            wrapped_lines.append(' '.join(wrapped_words))
            
        final_text = '\n'.join(wrapped_lines)
        
        # 3. Convert whitespace to HTML entities
        # Note: We use &nbsp; for space preservation in this simplified renderer
        return final_text.replace('\n', '<br>').replace('  ', '&nbsp;&nbsp;').replace('\t', '&nbsp;&nbsp;&nbsp;&nbsp;')

    def _break_long_words(self, text, limit=50):
        """Insert zero-width space or break after Limit chars"""
        if not text: 
            return ""
        if len(text) <= limit:
            return text
            
        # Insert a space (or <wbr> if supported, but simpler to use space/break for Swing) 
        # to ensure wrapping. Swing HTML is old.
        chunks = []
        for i in range(0, len(text), limit):
            chunks.append(text[i:i+limit])
        return ' '.join(chunks)

    def _create_image_from_html(self, html_content):
        """Render HTML content to a BufferedImage"""
        pane = JTextPane()
        pane.setContentType("text/html")
        pane.setText(html_content)
        pane.setBorder(EmptyBorder(20, 20, 20, 20))
        pane.setBackground(Color(30, 30, 30)) # Match body bg
        
        # Force a reasonable width to make text wrap (fix for very wide images)
        fixed_width = 1200
        pane.setSize(fixed_width, 20000) # Set huge height initially
        
        # Calculate preferred height based on the fixed width
        pane_size = pane.getPreferredSize()
        h = int(pane_size.getHeight())
        
        # Resize to final dimensions
        pane.setSize(fixed_width, h)
        
        img = BufferedImage(fixed_width, h, BufferedImage.TYPE_INT_ARGB)
        g2d = img.createGraphics()
        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        
        # Fill background
        g2d.setColor(Color(30, 30, 30))
        g2d.fillRect(0, 0, fixed_width, h)
        
        # Paint
        pane.paint(g2d)
        g2d.dispose()
        
        return img
    
    def _pretty_print_body(self, body, headers):
        """Attempt to pretty-print JSON or XML bodies"""
        try:
            # Check content type if possible, or just guess
            is_json = False
            for h in headers:
                if 'content-type' in h.lower() and 'json' in h.lower():
                    is_json = True
                    break
            
            if is_json:
                try:
                    obj = json.loads(body)
                    return json.dumps(obj, indent=2)
                except:
                    pass # Not valid JSON
            
            # Try formatting as XML if it looks like XML
            if body.strip().startswith('<') and body.strip().endswith('>'):
                 try:
                    reparsed = minidom.parseString(body)
                    return reparsed.toprettyxml(indent="  ")
                 except:
                    pass
                    
            return body
        except:
             return body

    def _copy_image_to_clipboard(self, image):
        """Copy BufferedImage to system clipboard"""
        toolkit = Toolkit.getDefaultToolkit()
        clipboard = toolkit.getSystemClipboard()
        clipboard.setContents(ImageTransferable(image), None)


    def _escape_html(self, text):
        return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def _base64url_decode(self, data):
        """Decode base64url encoded string (JWT uses this instead of standard base64)"""
        # Add padding if needed
        padding = 4 - (len(data) % 4)
        if padding != 4:
            data += '=' * padding
        
        # Replace URL-safe characters with standard base64
        data = data.replace('-', '+').replace('_', '/')
        
        return base64.b64decode(data)

    # Helper methods
    
    def _parse_urlencoded(self, body):
        """Parse URL-encoded body into dict"""
        params = {}
        if not body:
            return params
        
        for pair in body.split('&'):
            if '=' in pair:
                key, value = pair.split('=', 1)
                params[urllib.unquote(key)] = urllib.unquote(value)
            else:
                params[urllib.unquote(pair)] = ''
        return params
    
    def _json_to_urlencoded(self, data, prefix=''):
        """Convert JSON object to URL-encoded format"""
        parts = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                new_key = prefix + '[' + key + ']' if prefix else key
                if isinstance(value, (dict, list)):
                    parts.append(self._json_to_urlencoded(value, new_key))
                else:
                    parts.append(urllib.quote(str(new_key)) + '=' + urllib.quote(str(value)))
        elif isinstance(data, list):
            for i, value in enumerate(data):
                new_key = prefix + '[' + str(i) + ']'
                if isinstance(value, (dict, list)):
                    parts.append(self._json_to_urlencoded(value, new_key))
                else:
                    parts.append(urllib.quote(str(new_key)) + '=' + urllib.quote(str(value)))
        else:
            parts.append(urllib.quote(str(prefix)) + '=' + urllib.quote(str(data)))
        
        return '&'.join(parts)
    
    def _dict_to_xml(self, data, root_name='root'):
        """Convert dict to XML string"""
        root = ET.Element(root_name)
        self._build_xml_tree(root, data)
        rough_string = ET.tostring(root, encoding='UTF-8')
        reparsed = minidom.parseString(rough_string)
        return reparsed.toprettyxml(indent="  ", encoding='UTF-8')
    
    def _build_xml_tree(self, parent, data):
        """Recursively build XML tree from dict"""
        if isinstance(data, dict):
            for key, value in data.items():
                child = ET.SubElement(parent, str(key))
                self._build_xml_tree(child, value)
        elif isinstance(data, list):
            for item in data:
                child = ET.SubElement(parent, 'item')
                self._build_xml_tree(child, item)
        else:
            parent.text = str(data)
    
    def _xml_to_dict(self, xml_str):
        """Convert XML string to dict"""
        root = ET.fromstring(xml_str)
        return self._xml_element_to_dict(root)
    
    def _xml_element_to_dict(self, element):
        """Recursively convert XML element to dict"""
        result = {}
        for child in element:
            if len(child) == 0:
                result[child.tag] = child.text
            else:
                result[child.tag] = self._xml_element_to_dict(child)
        return result
    
    def _escape_js(self, text):
        """Escape text for JavaScript string"""
        if text is None:
            return ''
        return str(text).replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')

class ImageTransferable(Transferable):
    def __init__(self, image):
        self.image = image

    def getTransferDataFlavors(self):
        return [DataFlavor.imageFlavor]

    def isDataFlavorSupported(self, flavor):
        return DataFlavor.imageFlavor.equals(flavor)

    def getTransferData(self, flavor):
        if not DataFlavor.imageFlavor.equals(flavor):
            raise UnsupportedFlavorException(flavor)
        return self.image
