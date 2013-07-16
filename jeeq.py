#!/usr/bin/env python
# *-* coding: utf-8 *-*

# jeeq 0.0.3
# https://github.com/jackjack-jj/jeeq
# Licensed under GPLv3

import random,base64,hashlib,sys

_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2FL
_r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L
_b = 0x0000000000000000000000000000000000000000000000000000000000000007L
_a = 0x0000000000000000000000000000000000000000000000000000000000000000L
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798L
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8L

curvedicBtc={'p':_p, 'r':_r, 'a':_a, 'b':_b, 'Gx':_Gx, 'Gy':_Gy}
jeeqversion='0.0.3'

def str_to_long(b):
	res = 0
	pos = 1
	for a in reversed(b):
		res += ord(a) * pos
		pos *= 256
	return res

def contains_point(x,y, curved=curvedicBtc):
	_p = curved['p']
	return y * y % _p == ( ( ( x + curved['a'] %_p ) * x * x % _p ) + curved['b'] ) % _p

class Point( object ):
	def __init__( self, curve, x, y, order = None ):
		self.__curve = curve
		self.__x = x
		self.__y = y
		self.__order = order
		if self.__curve: assert contains_point( x, y, self.__curve )
		if order: assert self * order == INFINITY

	def __add__( self, other ):
		if other == INFINITY: return self
		if self == INFINITY: return other
		assert self.__curve == other.__curve
		if self.__x == other.__x:
			if ( self.__y + other.__y ) % self.__curve.p() == 0:
				return INFINITY
			else:
				return self.double()

		p = self.__curve['p']
		l = ( ( other.__y - self.__y ) * \
					inverse_mod( other.__x - self.__x, p ) ) % p
		x3 = ( l * l - self.__x - other.__x ) % p
		y3 = ( l * ( self.__x - x3 ) - self.__y ) % p
		return Point( self.__curve, x3, y3 )

	def __mul__( self, other ):
		def leftmost_bit( x ):
			assert x > 0
			result = 1L
			while result <= x: result = 2 * result
			return result / 2

		e = other
		if self.__order: e = e % self.__order
		if e == 0: return INFINITY
		if self == INFINITY: return INFINITY
		assert e > 0
		e3 = 3 * e
		negative_self = Point( self.__curve, self.__x, -self.__y, self.__order )
		i = leftmost_bit( e3 ) / 2
		result = self
		while i > 1:
			result = result.double()
			if ( e3 & i ) != 0 and ( e & i ) == 0: result = result + self
			if ( e3 & i ) == 0 and ( e & i ) != 0: result = result + negative_self
			i = i / 2
		return result

	def negative_self(self):
		return Point( self.__curve, self.__x, -self.__y, self.__order )

	def __rmul__( self, other ):
		return self * other

	def __str__( self ):
		if self == INFINITY: return "infinity"
		return "(%d,%d)" % ( self.__x, self.__y )

	def double( self ):
		if self == INFINITY:
			return INFINITY

		p = self.__curve['p']
		a = self.__curve['a']
		l = ( ( 3 * self.__x * self.__x + a ) * \
					inverse_mod( 2 * self.__y, p ) ) % p
		x3 = ( l * l - 2 * self.__x ) % p
		y3 = ( l * ( self.__x - x3 ) - self.__y ) % p
		return Point( self.__curve, x3, y3 )

	def x( self ):
		return self.__x

	def y( self ):
		return self.__y

	def curve( self ):
		return self.__curve
	
	def order( self ):
		return self.__order
	
	def ser( self, comp=True ):
		if comp:
			return ( ('%02x'%(2+(self.__y&1)))+('%064x'%self.__x) ).decode('hex')
		return ( '04'+('%064x'%self.__x)+('%064x'%self.__y) ).decode('hex')
		
INFINITY = Point( None, None, None )

def inverse_mod( a, m ):
	if a < 0 or m <= a: a = a % m
	c, d = a, m
	uc, vc, ud, vd = 1, 0, 0, 1
	while c != 0:
		q, c, d = divmod( d, c ) + ( c, )
		uc, vc, ud, vd = ud - q*uc, vd - q*vc, uc, vc
	assert d == 1
	if ud > 0: return ud
	else: return ud + m

def hash_160(public_key):
 	md = hashlib.new('ripemd160')
	md.update(hashlib.sha256(public_key).digest())
	return md.digest()

def public_key_to_bc_address(public_key, addrtype=0):
	h160 = hash_160(public_key)
	return hash_160_to_bc_address(h160, addrtype)

def hash_160_to_bc_address(h160,addrtype=0):
	vh160 = chr(addrtype) + h160
	h = Hash(vh160)
	addr = vh160 + h[0:4]
	return b58encode(addr)

__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)

def b58encode(v):
	""" encode v, which is a string of bytes, to base58.		
	"""

	long_value = 0L
	for (i, c) in enumerate(v[::-1]):
		long_value += (256**i) * ord(c)

	result = ''
	while long_value >= __b58base:
		div, mod = divmod(long_value, __b58base)
		result = __b58chars[mod] + result
		long_value = div
	result = __b58chars[long_value] + result

	# Bitcoin does a little leading-zero-compression:
	# leading 0-bytes in the input become leading-1s
	nPad = 0
	for c in v:
		if c == '\0': nPad += 1
		else: break

	return (__b58chars[0]*nPad) + result

def b58decode(v, length=None):
	""" decode v into a string of len bytes
	"""
	long_value = 0L
	for (i, c) in enumerate(v[::-1]):
		long_value += __b58chars.find(c) * (__b58base**i)

	result = ''
	while long_value >= 256:
		div, mod = divmod(long_value, 256)
		result = chr(mod) + result
		long_value = div
	result = chr(long_value) + result

	nPad = 0
	for c in v:
		if c == __b58chars[0]: nPad += 1
		else: break

	result = chr(0)*nPad + result
	if length is not None and len(result) != length:
		return None

	return result

def Hash(data):
	return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def EncodeBase58Check(vchIn):
	hash = Hash(vchIn)
	return b58encode(vchIn + hash[0:4])

def DecodeBase58Check(psz):
	vchRet = b58decode(psz, None)
	key = vchRet[0:-4]
	csum = vchRet[-4:]
	hash = Hash(key)
	cs32 = hash[0:4]
	if cs32 != csum:
		return None
	else:
		return key

def sha256(a):
	return hashlib.sha256(a).digest()

def chunks(l, n):
    return [l[i:i+n] for i in xrange(0, len(l), n)]

def ECC_YfromX(x,curved=curvedicBtc, odd=True):
	_p = curved['p']
	for offset in range(128):
		Mx=x+offset
		My2 = pow(Mx, 3, _p) + curved['a'] * pow(Mx, 2, _p) + curved['b'] % _p
		My = pow(My2, (_p+1)/4, _p )

		if contains_point(Mx,My,curved):
			if odd == bool(My&1):
				return [My,offset]
			return [curved['p']-My,offset]
	raise Exception('ECC_YfromX: No Y found')

def private_header(msg,v):
	assert v<1, "Can't write version %d private header"%v
	r=''
	if v==0:
		r+=('%08x'%len(msg)).decode('hex')
		r+=sha256(msg)[:2]
	return ('%02x'%v).decode('hex') + ('%04x'%len(r)).decode('hex') + r

def public_header(pubkey,v):
	assert v<1, "Can't write version %d public header"%v
	r=''
	if v==0:
		r=sha256(pubkey)[:2]
	return '\x6a\x6a' + ('%02x'%v).decode('hex') + ('%04x'%len(r)).decode('hex') + r

def encrypt_message(pubkey,m,curved=curvedicBtc):
	r=''
	msg = private_header(m,0)+m
	msg = msg+('\x00'*( 32-(len(msg)%32) ))
	msgs = chunks(msg,32)

	P = Point( curved, curved['Gx'], curved['Gy'], curved['r'] )
	if len(pubkey)==33: #compressed
		pk = Point( curved, str_to_long(pubkey[1:33]), ECC_YfromX(str_to_long(pubkey[1:33]), curved, pubkey[0]=='\x03')[0], curved['r'] )
	else:
		pk = Point( curved, str_to_long(pubkey[1:33]), str_to_long(pubkey[33:65]), curved['r'] )

	for i in range(len(msgs)):
		rand=( ( '%013x' % long(random.random() * 0xfffffffffffff) )*5 )

		n = long(rand,16) >> 4
		Mx = str_to_long(msgs[i])
		My,xoffset=ECC_YfromX(Mx, curved)
		M = Point( curved, Mx+xoffset, My, curved['r'] )

		T = P*n
		U = pk*n + M

		toadd = T.ser() + U.ser()
		toadd = chr(ord(toadd[0])-2+2*xoffset)+toadd[1:]
		r+=toadd

	return base64.b64encode(public_header(pubkey,0) + r)

def pointSerToPoint(Aser, curved=curvedicBtc):
	assert Aser[0] in ['\x02','\x03','\x04']
	if Aser[0] == '\x04':
		return Point( curved, str_to_long(Aser[1:33]), str_to_long(Aser[33:]), curved['r'] )
	Mx = str_to_long(Aser[1:])
	return Point( curved, Mx, ECC_YfromX(Mx, curved, Aser[0]=='\x03')[0], curved['r'] )

def decrypt_message(pvk, enc, curved=curvedicBtc, verbose=False):
	P = Point( curved, curved['Gx'], curved['Gy'], curved['r'] )
	pvk=str_to_long(pvk)
	pubkeys = [(P*pvk).ser(True), (P*pvk).ser(False)]
	enc = base64.b64decode(enc)

	assert enc[:2]=='\x6a\x6a'		

	phv = str_to_long(enc[2])
	assert phv==0, "Can't read version %d public header"%phv
	hs = str_to_long(enc[3:5])
	public_header=enc[5:5+hs]
	if verbose: print 'Public header (size:%d)%s%s'%(hs, ': 0x'*int(bool(hs>0)), public_header.encode('hex'))
	if verbose: print '  Version: %d'%phv
	checksum_pubkey=public_header[:2]
	if verbose: print '  Checksum of pubkey: %s'%checksum_pubkey.encode('hex')
	assert checksum_pubkey in map(lambda x:sha256(x)[:2], pubkeys), 'Bad private key'
	enc=enc[5+hs:]


	r = ''
	for Tser,User in map(lambda x:[x[:33],x[33:]], chunks(enc,66)):
		ots = ord(Tser[0])
		xoffset = ots>>1
		Tser = chr(2+(ots&1))+Tser[1:]
		T = pointSerToPoint(Tser,curved)
		U = pointSerToPoint(User,curved)

		V = T*pvk
		Mcalc = U+(V.negative_self())
		r += ('%064x'%(Mcalc.x()-xoffset)).decode('hex')


	pvhv = str_to_long(r[0])
	assert pvhv==0, "Can't read version %d private header"%pvhv
	phs = str_to_long(r[1:3])
	private_header = r[3:3+phs]
	if verbose: print 'Private header (size:%d): 0x%s'%(phs, private_header.encode('hex'))
	size = str_to_long(private_header[:4])
	checksum = private_header[4:6]
	if verbose: print '  Message size: %d'%size
	if verbose: print '  Checksum: %04x'%str_to_long(checksum)
	r = r[3+phs:]

	msg = r[:size]
	hashmsg = sha256(msg)[:2]
	checksumok = hashmsg==checksum
	if verbose: print 'Decrypted message: '+msg
	if verbose: print '  Hash: '+hashmsg.encode('hex')
	if verbose: print '  Corresponds: '+str(checksumok)
	

	return [msg, checksumok]

import platform
def KeyboardInterruptText():
	if platform.system() == "Windows":
		return "Hit Ctrl-C or Ctrl-Z"
	return "Hit Ctrl-D"

def GetArg(a, d=''):
	for i in range(1,len(sys.argv)):
		if sys.argv[i-1]==a:
			if a in ['-i']:
				f=open(sys.argv[i],'r')
				content=f.read()
				f.close()
				return content
			return sys.argv[i]
	if a == '-i':
		print "Type the text to use. "+KeyboardInterruptText()+" to stop writing: "
		return ''.join(sys.stdin.readlines())
	if a == '-k':
		return raw_input("\nType the key to use: ")
	return d

def GetFlag(a, d=''):
	for i in range(1,len(sys.argv)):
		if sys.argv[i]==a:
			return True
	return False

def print_help(e=False):
	print 'jeeq.py '+jeeqversion
	print 'Encryption/decryption tool using Bitcoin keys'
	print 'usage:'
	print '   KEY GENERATION: '+sys.argv[0]+' -g [-v network number]'
	print '   ENCRYPTION:     '+sys.argv[0]+' -e -i input_file -o output_file -k public_key  [-v network number]'
	print '   DECRYPTION:     '+sys.argv[0]+' -d -i input_file -o output_file -k private_key [-v network number]'
	print ''
	print 'Missing arguments will be prompted.'
	print 'Public keys are NOT Bitcoin addresses, you NEED public keys.'
	if e:
		exit(0)

def generate_keys(curved=curvedicBtc, bitcoin=True, addv=0):
	rand = ( '%013x' % long(random.random() * 0xfffffffffffff) )*5
	pvk  = (long(rand,16) >> 4)%curved['r']
	G = Point( curved, curved['Gx'], curved['Gy'], curved['r'] )
	P = pvk*G
	btcaddresses=['','']
	if bitcoin:
		btcaddresses[0]=public_key_to_bc_address(P.ser(True), addv)
		btcaddresses[1]=public_key_to_bc_address(P.ser(False),addv)
	return ['%064x'%pvk, P.ser(True).encode('hex'), P.ser(False).encode('hex'), btcaddresses]

if __name__ == '__main__':
	curved=curvedicBtc

	# 
	# Usage:
	# 
	# encrypted = encrypt_message(pubkey, "hello world!")
	# 
	# output    = decrypt_message(pvk, base64d_msg, verbose=True)
	# 

	if GetFlag('--help') or GetFlag('-h'):
		print_help(True)

	if GetFlag('--generate-keys') or GetFlag('-g'):
		v=int(GetArg('-v',0))
		keys=generate_keys(addv=v)
		print 'Private key:              ', keys[0]
		print 'Compressed public key:    ', keys[1]
		print 'Uncompressed public key:  ', keys[2]
		print 'Compressed address:       ', keys[3][0]
		print 'Uncompressed address:     ', keys[3][1]
		exit(0)

	if GetFlag('-e'):
		addv=int(GetArg('-v',0))
		message=GetArg('-i')
		public_key=GetArg('-k')

		if len(public_key) in [66,130]:
			public_key=public_key.decode('hex')
		assert len(public_key) in [33,65], 'Bad public key'

		output=encrypt_message(public_key,message)

		output_file=GetArg('-o')
		if output_file:
			f=open(output_file,'w')
			f.write(output)
			f.close()
		print "\n\nEncrypted message to "+public_key_to_bc_address(public_key,addv)+":\n"+output


	elif GetFlag('-d'):
		addv=int(GetArg('-v',0))
		message=GetArg('-i')
		private_key=GetArg('-k')

		if len(private_key)==64:
			private_key=private_key.decode('hex')
		assert len(private_key)==32, 'Bad private key'

		output=decrypt_message(private_key, message, verbose=True)

		output_file=GetArg('-o')
		if output_file:
			f=open(output_file,'w')
			f.write(output[0])
			f.close()
		print "\nDecrypted message to "+public_key_to_bc_address(private_key,addv)+":\n"+output[0]

	else:
		print_help(True)



