from ldap3 import Server, Connection, NTLM, ALL
from ldap3.core.exceptions import LDAPException

class ADAuthenticator:
    def __init__(self, username=None, password=None, domain=None, 
                 dc_host=None, ntlm_hash=None):
        # Initialize ADAuthenticator with credentials and domain information
        self.username = username
        self.password = password
        self.domain = domain
        self.dc_host = dc_host
        self.ntlm_hash = ntlm_hash
        self.conn = None
        
    def connect(self):
        """Establish connection to Active Directory"""
        try:
            server = Server(self.dc_host, get_info=ALL, use_ssl=False)
            user_domain = f"{self.domain}\\{self.username}"
            self.conn = self.get_ldap_client(
                self.domain, self.ntlm_hash, server, user_domain, self.username, self.password
            )
            
            if not self.conn.bind():
                raise LDAPException(f"Authentication error: {self.conn.result}")
                
            return True
            
        except Exception as e:
            print(f"[!] Connection error: {str(e)}")
            return False
            
    def get_ldap_client(self, domain, hashes, server, user_domain, username, password):
        """Get LDAP client connection"""
        try:
            if hashes is not None:
                formatted_hashes = f"aad3b435b51404eeaad3b435b51404ee:{hashes}"
                connection = Connection(server, user=user_domain, password=formatted_hashes, authentication=NTLM)
                bind_result = connection.bind()
                if not bind_result:
                    raise LDAPException(f"Failed to perform LDAP bind to {server} with user {user_domain}")
            else:
                connection = Connection(server, user=user_domain, password=password, authentication=NTLM)
                bind_result = connection.bind()
                if not bind_result:
                    raise LDAPException(f"Failed to perform LDAP bind with user {user_domain}")

            return connection
        except Exception as e:
            raise

    def disconnect(self):
        """Close connection"""
        if self.conn:
            self.conn.unbind()
            
    def get_connection(self):
        """Get current connection"""
        return self.conn