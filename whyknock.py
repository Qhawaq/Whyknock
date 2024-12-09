#!/usr/bin/python3

""" whyknock.py 

    A knocker program :)
"""
# pylint: disable=invalid-name
# pylint: disable=global-variable-not-assigned
# pylint: disable=line-too-long

import socket
import time
import sys
import os
import random
import argparse
import configparser
from base64 import urlsafe_b64encode

from prompt_toolkit import prompt
from prompt_toolkit.validation import Validator, ValidationError

from cryptography.fernet import Fernet

# !!!!! CHANGE ME  !!!!!
DFL_PWD = '01234567890123456789012345678901'

CFG_DIRPATH = '.'
CFG_FILE = 'whyknock.ini'

NFT_DIRPATH = '.'
NFT_DIR = 'nft_scripts'
NFT_FILE = 'nft_skeleton.txt'

TIME_BETWEEN_PACKETS = 0.5

# il pacchetto UDP è 8 bytes headers + 256 bytes payload = 264 bytes totali


cfg_full_path = CFG_DIRPATH

nft_full_path = NFT_DIRPATH+'/'+NFT_DIR
nft_skel_path = nft_full_path+'/'+NFT_FILE

m_keys = []

class YesNoValidator(Validator):
    """ Validator Class fo YES or NO answers """
    def validate(self, document):
        text = document.text.upper()

        if text and text not in ('Y','N'):
            raise ValidationError(message="Plese type only 'Y' or 'N' ")


class NumberValidator(Validator):
    """ Validator Class for integer numbers answers """
    def validate(self, document):
        text = document.text

        if text and not text.isdigit():
            i = 0
            for i, c in enumerate(text):
                if not c.isdigit():
                    break

            raise ValidationError(message='This input contains non-numeric characters',
                                  cursor_position=i)


def read_profile(host, pwd):
    """ read_profile
        The function try to read an host profile from the ini file.
        If the profile exists this function load and decrypt all its 
        values in memory then load the global m_keys array .
        If there is no profile for the host, function propmt user to create it

    Args:
        host ( str ): Host name IP or DNS to be searched
        pwd  ( str ): Password to decrypt values in ini file
    """

    global m_keys

    cipher_suite = Fernet(urlsafe_b64encode(pwd.encode()))

    if not os.path.exists( cfg_full_path):
        print('Configuration file doesn\'t exists. Quitting.')
        sys.exit(0)

    config = configparser.ConfigParser()
    config.read( cfg_full_path )

    if config.has_section(host):
        num_keys = int(config[host]['num_keys'])
        for idx in range(0, num_keys):
            dec_text = cipher_suite.decrypt(config[host][f'key{idx}'].encode()).decode()
            key, pos, lun = dec_text.split(';')
            m_keys.append( ( bytes.fromhex(key[2:]), int(pos), int(lun) ) )

        send_data( host, num_keys )
    else:
        print(f'There is no profile for: {host} in config file')
        res = prompt(f'Do you want to create a profile for {host} ? [Y/n] ',
                     validator=YesNoValidator(), default='Y')
        if 'Y' in res:
            num_k = prompt('Please input the max nmber of packets to knock target machine : ',
                         validator=NumberValidator(), default='4')
            create_profile(host, int(num_k), pwd )

        res = prompt(f'Do you want to create an nft table script for {host} ? [Y/n] ',
                validator=YesNoValidator(), default='Y')
        if 'Y' in res:
            create_nftable_rules(host)

        sys.exit(0)


def create_profile( host, num_keys, pwd): # pylint: disable=too-many-locals
    """ create_profile 

    Args:
        host (str): Host name (IP or DNS) to create a profile
        num_keys (int): Numeber of key to create
        pwd (str): Password to encrypt data
    """

    global m_keys

    cipher_suite = Fernet(urlsafe_b64encode(pwd.encode()))

    config = configparser.ConfigParser()
    config[host]={}
    config[host]['num_keys'] = f'{num_keys}'

    for k in range(0,num_keys):

        pos_key = random.randint(0,230)
        len_key = random.randint(4,16)
        new_key_name  = f'key{k}'
        new_key_value = os.urandom(len_key)

        str_to_enc = f'0x{new_key_value.hex()};{pos_key};{len_key}'

        cipher_text = cipher_suite.encrypt(str_to_enc.encode())
        config[host][new_key_name] = cipher_text.decode()

    with open( cfg_full_path , 'a', encoding='UTF-8') as configfile:
        config.write(configfile)

    if config.has_section(host):
        num_keys = int(config[host]['num_keys'])
        for idx in range(0, num_keys):
            dec_text = cipher_suite.decrypt(config[host][f'key{idx}'].encode()).decode()
            key, pos, lun = dec_text.split(';')
            m_keys.append( ( bytes.fromhex(key[2:]), int(pos), int(lun) ) )


def create_nftable_rules(host):
    """ create_nftable_rules:
        This function create a nft script file to be copied and used as 
        'knock engine' in remote machines. The blueprint of script can be 
        modified editing the 'skeleton.txt' file found in nft_scripts direcotry

    Args:
        host ( str ): Host name (IP or DNS). 
                      This name will be used to create a specific .nft file in nft_scripts 
                      directory 
    """
    last_key = len(m_keys)
    my_file = nft_full_path+'/'+host+'.nft'

    with open(nft_skel_path, 'r', encoding='UTF-8') as skeleton:
        nft_skeleton = skeleton.read()

    with open( my_file , 'w', encoding='UTF-8') as nftfile:

        nftfile.write( nft_skeleton )

        for idx in enumerate(m_keys):
            key_num = idx[0]
            key_val = idx[1][0]
            key_pos = idx[1][1] * 8
            key_len = idx[1][2] * 8

            rec=f"udp length 264 @ih,{key_pos},{key_len} 0x{key_val.hex()} "
            if key_num == 0:
                rec+="add @knockers_ipv4 {ip saddr . udp sport   timeout 10s}"
            else:
                if key_num == last_key - 1:
                    rec += "ip saddr . udp dport @knockers_ipv4  add @approvati_ipv4 {ip saddr timeout 5m}"
                else:
                    rec+="ip saddr . udp dport  @knockers_ipv4 add @knockers_ipv4 {ip saddr . udp sport timeout 10s}"

            nftfile.write('\t'+rec+'\n')

        nftfile.write('     }\n}\n')


def make_keyed_pkt ( key_index ):
    """ make_keyed_pkt:
        Marks an UDP Packet with a key provided by global array m_keys    
    Args:
        key_index (): Index of selected key in m_keys array
    Returns:
        bytearray: Full payload (256 bytes) marked by key
    """
    kk = 0
    key_bytes,key_pos,key_len = m_keys[key_index]

    payload = bytearray(os.urandom(256))

    while kk < key_len:
        payload[key_pos+kk] = key_bytes[kk]
        kk += 1

    return payload


def send_data(target, num_pkts):
    """ send_data:
        Send a series of UDP keyed packets to target host

    Args:
        target ( str ): Host name (IP or DNS) of the target
        num_pkts (int): Numbers of packets to send target
    """
    port = random.randint(1025,65000)

    for pkt_idx in range(0,num_pkts):

        pkt_to_send = bytes(make_keyed_pkt (pkt_idx))
        nxt_port = random.randint(1025,65000)

        sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        sock.bind(("",nxt_port))
        sock.sendto(pkt_to_send, (target, port))
        print ('port: ',port )
        sock.close()
        port = nxt_port
        time.sleep(TIME_BETWEEN_PACKETS)


if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument('hostname',
                         help='Hostname IP or DNS to knock')
    parser.add_argument('-P', '--password', default = DFL_PWD,
                        help='Password to protect keys ( 32 chars, default: DFL_PWD in code )')
    parser.add_argument('-v','--verbose',
                        type=int,  help='Hostname IP or DNS to knock')
    parser.add_argument('-c','--config',
                        help=f"Path where to store config file (default: '{CFG_DIRPATH}/{CFG_FILE}')",
                        default=CFG_DIRPATH+'/'+CFG_FILE)
    parser.add_argument('-nft','--nftdir',
                        help=f"Full path to store nft tables script (default: '{NFT_DIRPATH}/{NFT_DIR}')",
                        default=NFT_DIRPATH+'/'+NFT_DIR)

    args = parser.parse_args()

    target_host = args.hostname
    passwd = args.password
    cfg_full_path = args.config
    nft_full_path = args.nftdir

    if len(passwd) != 32:
        print('ERROR: Password MUST BE EXACTLY 32 chars long. Quitting\n')
        sys.exit(0)

    read_profile( target_host, passwd)
    sys.exit(0)
