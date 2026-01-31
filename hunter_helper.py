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
import xml.etree.ElementTree as ET
from xml.dom import minidom

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
        
        return menu_items
    
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
            'pragma', 'expires', 'last-modified', 'x-powered-by', 'x-aspnet-version'
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
