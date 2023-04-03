import random
import re
import socket
import threading
import time
import traceback
from hashlib import md5

sserver_ip = "X.X.X.X" # Sip Server IP
server_port = "5060" # UDP PORT

suser_name = "username" # User ID
suser_password = "password" # User Password


class HeaderFactory:
    caller_id = None
    ceq_for_register = None

    @staticmethod
    def caller_id_creator():
        if HeaderFactory.caller_id is None:
            HeaderFactory.caller_id = HeaderFactory.branch_creator(length=20)

    @staticmethod
    def cqe_handler():
        if HeaderFactory.ceq_for_register is None:
            HeaderFactory.ceq_for_register = 1
        else:
            HeaderFactory.ceq_for_register = HeaderFactory.ceq_for_register + 1

    @staticmethod
    def branch_creator(length=8):
        choices = 'ABCDEFGHIJKLMNabcdefghijklm123456789nopqrstuvwxyzOPQRSTUVWXYZ'
        random_string = "".join((random.choice(choices) for i in range(length)))
        return random_string

    @staticmethod
    def registration_header_creator(client, realm, nonce, opaque, branch=None):
        """When type is auth"""

        HeaderFactory.cqe_handler()
        HeaderFactory.caller_id_creator()
        if branch is None:
            branch = HeaderFactory.branch_creator()
            HeaderFactory.ceq_for_register = None
        HeaderFactory.cqe_handler()
        uri = f"sip:{client.user_name}@{client.server_ip}:{server_port}"
        a1 = md5(f"{client.user_name}:{realm}:{client.user_password}".encode())
        a2 = md5(f"REGISTER:{uri}".encode())

        response = md5(f"{a1.hexdigest()}:{nonce}:{a2.hexdigest()}".encode()).hexdigest()
        registration_header_with_auth = [
            f'REGISTER sip:{client.user_name}@{client.server_ip} SIP/2.0\r\n',
            f'Via: SIP/2.0/UDP {client.user_ip}:{client.user_port};branch={branch}\r\n',
            f'Max-Forwards: 70\r\n',
            f'To: {client.user_name} <sip:{client.user_name}@{client.server_ip}>\r\n',
            # f'From: {user_name} <sip:{user_name}@{server_ip}>;tag={tag_value}\r\n',
            f'From: {client.user_name} <sip:{client.user_name}@{client.server_ip}>\r\n',
            f'Call-ID: {HeaderFactory.caller_id}\r\n',
            f'CSeq: {HeaderFactory.ceq_for_register} REGISTER\r\n',
            f'Expires: 60\r\n',
            f'Contact: <sip:{client.user_name}@{client.user_ip}:{client.user_port}>\r\n',
            f'Authorization: Digest username="{client.user_name}", realm="{realm}", nonce="{nonce}", opaque="{opaque}",uri="{uri}",response={response}\r\n',
            f'Content-Length: 0\r\n',
        ]
        final_registration_header = ""

        for i in registration_header_with_auth:
            final_registration_header += i
        return final_registration_header

    @staticmethod
    def notify_response_creator(client, branch, ceq):
        ceq += 1
        notify_header = [
            'SIP/2.0 200 OK\r\n',
            f'Via: SIP/2.0/UDP {client.user_ip}:{client.user_port};branch={branch}\r\n',
            f'Max-Forwards: 70\r\n',
            f'To: {client.user_name} <sip:{client.user_name}@{client.server_ip}>\r\n',
            f'From: {client.user_name} <sip:{client.user_name}@{client.server_ip}>\r\n',
            f'Call-ID: {HeaderFactory.caller_id}\r\n',
            f'CSeq: {ceq} NOTIFY\r\n',
            f'Event: message-summary\r\n',
            f'Subscription-State: active;expires=60\r\n',
            f'Content-Length: 0\r\n'
        ]

        final_notify_header_header = ""

        for i in notify_header:
            final_notify_header_header += i

        return final_notify_header_header

    @staticmethod
    def option_response_creator(client, branch, ceq, tag):
        ceq += 1
        option_header = [
            f'SIP/2.0 200 OK\r\n',
            f'Via: SIP/2.0/UDP {client.server_ip}:{client.server_port};branch={branch}\r\n',
            f'To: {client.user_name} <sip:{client.user_name}@{client.server_ip}>\r\n',
            f'From: {client.user_name} <sip:{client.user_name}@{client.server_ip}>;tag={tag}\r\n',
            f'Call-ID: {HeaderFactory.caller_id}\r\n',
            f'CSeq: {ceq} OPTIONS\r\n',
            f'Content-Length: 0\r\n'
        ]

        final_option_header_header = ""

        for i in option_header:
            final_option_header_header += i

        return final_option_header_header


class SipClient(threading.Thread):
    class FailedToCreateBinding(Exception):
        """Most probably certain port is used by another application"""
        pass

    @staticmethod
    def get_this_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        this_ip = s.getsockname()[0]
        s.close()
        return this_ip

    def create_and_bind_socket(self, max_try=5, port=None):
        if max_try == 0:
            raise SipClient.FailedToCreateBinding()
        try:
            ip = SipClient.get_this_ip()
            sip_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            selected_port = port
            if port is None:
                selected_port = int(random.randint(40000, 50000))

            sip_socket.bind((ip, selected_port))
            self.sip_socket = sip_socket
            self.user_ip = ip
            self.user_port = selected_port
        except Exception:
            print("Trying to Create a Binding")
            self.create_and_bind_socke(max_try=max_try - 1, port=port)

    def __init__(self, user_name, user_password, pbx_ip, call_callback, pbx_port=5060):
        super().__init__()
        self.user_name = user_name
        self.user_password = user_password
        self.user_port = None
        self.user_ip = None
        self.sip_socket = None
        self.server_ip = pbx_ip
        self.server_port = pbx_port
        self.create_and_bind_socket(port=45890)
        self.is_registered = False
        self.register_timeout = None
        self.registration_renewal_started = False
        self.call_callback = call_callback

    def run(self):
        branch_with_value = []
        threading.Thread(target=self.register_fake).start()
        while True:
            data, address = self.sip_socket.recvfrom(80048)
            """For debugging/ tracing header data"""
            # print(address, data)
            try:
                data = str(data.decode())
                branch = SipClient.finder('branch=(.*?)\r\n', data)
                if 'SIP/2.0 401 Unauthorized' in data:
                    opaque = SipClient.finder('opaque="(.*?)"', data)
                    nonce = SipClient.finder('nonce="(.*?)"', data)
                    realm = SipClient.finder('realm="(.*?)"', data)
                    # print(branch,opaque,nonce,realm)
                    self.register_with_auth(branch=branch, opaque=opaque, nonce=nonce, realm=realm)
                    branch_with_value.append({
                        "type": "register_pending",
                        "branch": branch,
                        "opaque": opaque,
                        "nonce": nonce,
                        "realm": realm
                    })
                elif 'SIP/2.0 200 OK' in data:
                    for i in branch_with_value:
                        if i["branch"] == branch and i["type"] == "register_pending":
                            self.is_registered = True
                            branch_with_value.clear()
                            threading.Thread(target=self.registration_renewal).start()
                            self.registration_renewal_started = True
                            break
                elif 'NOTIFY sip:' in data:
                    ceq = self.finder("CSeq: (.*?) ", data)
                    self.notify_response(ceq=int(ceq), branch=branch)
                elif 'OPTIONS sip:' in data:
                    ceq = self.finder("CSeq: (.*?) ", data)
                    tag = self.finder("tag=(.*?)\r\n", data)
                    self.option_response(ceq=int(ceq), branch=branch, tag=tag)
                elif 'INVITE sip:' in data:
                    """Note: if any of below parameter is not in header, adjust according to your need"""
                    invite_username = self.finder("""From: "(.*?)" """, data)
                    invite_extension = self.finder(f"""From: "{invite_username}" <sip:(.*?)@""", data)
                    self.call_callback(invite_username, invite_extension)
                    threading.Thread(target=self.call_callback, args=[invite_username, invite_extension]).start()

            except Exception:
                traceback.print_exc()
                pass

    def register_fake(self):
        while not self.is_registered:
            self.sip_socket.sendto(
                HeaderFactory.registration_header_creator(client=self, realm="", nonce="", opaque="").encode(),
                (self.server_ip, self.server_port))
            time.sleep(60)
        # print("Exited from fake register creator")

    def register_with_auth(self, realm, nonce, opaque, branch):
        self.sip_socket.sendto(
            HeaderFactory.registration_header_creator(client=self, realm=realm, nonce=nonce, opaque=opaque,
                                                      branch=branch).encode(), (self.server_ip, self.server_port))

    def registration_renewal(self):
        if self.registration_renewal_started: return

        print("Started Registration Auto Renewal")
        while True:
            print("Trying for Auto renewal. . .")
            time.sleep(60)
            self.is_registered = False
            self.register_fake()

    def notify_response(self, ceq, branch):
        self.sip_socket.sendto(HeaderFactory.notify_response_creator(client=self, branch=branch, ceq=ceq).encode(),
                               (self.server_ip, self.server_port))

    def option_response(self, ceq, branch, tag):
        self.sip_socket.sendto(
            HeaderFactory.option_response_creator(client=self, branch=branch, ceq=ceq, tag=tag).encode(),
            (self.server_ip, self.server_port))

    @staticmethod
    def finder(pattern, target):
        return re.search(pattern, target).group(1)


def call_back(user_name, user_id):
    """Define callback according to your need """
    """Callback is always executed on different thread"""
    print("Info:", user_name, user_id)


client = SipClient(user_name=suser_name, user_password=suser_password, call_callback=call_back, pbx_ip=sserver_ip)

client.start()
