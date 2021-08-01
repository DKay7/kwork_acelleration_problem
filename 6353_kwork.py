#!/usr/bin/python3
import datetime
import sys
import ecdsa
import hashlib
from binascii import hexlify, unhexlify
from base58 import b58encode


def get_public_key_uncompressed(private_key_bytes):
    k = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    return b'\04' + k.get_verifying_key().to_string()  

def get_bitcoin_address(public_key_bytes, prefix=b'\x00'):
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(public_key_bytes).digest())
    r = prefix + ripemd160.digest()
    checksum = hashlib.sha256(hashlib.sha256(r).digest()).digest()[:4]
    
    return b58encode(r + checksum)


if __name__ == "__main__":

	with open('6353s.txt') as f6353s:
		text_line1 = f6353s.readline()
	
	with open('6353s3.txt') as f6353s3:
		text_line1s3 = f6353s3.readline()
	
	
	count_str = 0
	while True:

		private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1).to_string()
		public_key = get_public_key_uncompressed(private_key)
		address = get_bitcoin_address(public_key)

		private_key_static = hexlify(private_key).decode()  
		extended_key = "80" + private_key_static
		first_sha256 = hashlib.sha256(unhexlify(extended_key)).hexdigest()
		second_sha256 = hashlib.sha256(unhexlify(first_sha256)).hexdigest()
		final_key = extended_key+second_sha256[:8]
		
		WIF = b58encode(unhexlify(final_key))

		addr = address.decode()
		addrs3 = addr[:11]
		address22 = WIF.decode()
		addr_indx = 0
		addr_indxs3 = 0
		addr_indxs3 = text_line1s3.find(addrs3)
		
		if addr_indxs3 != -1:
		    addr_indx = text_line1.find(addr)
		    if addr_indx != -1:
		        today = datetime.datetime.today()
		        time_stamp = today.strftime("20%y-%m-%d-%H-%M-%S")
		        output_file = 'result.txt'
		        
		        with open(output_file, 'a') as fres:
		        	fres.write(time_stamp + ' ' + addr + ' ' + address2 + '\n')


		count_str += 1
		if count_str == 1 or (count_str % 100000 == 0) :
		    today = datetime.datetime.today()
		    time_stamp = today.strftime("20%y-%m-%d--%H-%M-%S")
		    print(' .  ' + str(count_str / 100000) + 'x 100`000' + ' ' + time_stamp + ' ' + addr + ' ' + address22 + ' ')

