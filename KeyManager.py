import socket
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes


def function(bin1, l):
    i = len(bin1)
    aux = bytearray(l-i)
    aux.extend(bin1)
    return bytes(aux)


iv = get_random_bytes(AES.block_size)
key1 = get_random_bytes(AES.block_size)
key2 = get_random_bytes(AES.block_size)
print(key1)
print(key2)
key3 = b'Sixteen byte key'
aes = AES.new(key3, AES.MODE_ECB)
host = socket.gethostname()
port = 5001  # initiate port no above 1024
server_socket = socket.socket()  # get instance
server_socket.bind((host, port))  # bind host address and port together
server_socket.listen(2)
conn, address = server_socket.accept()  # accept new connection

while True:
    keytype = conn.recv(1024).decode()
    print(keytype)
    if keytype == 'CBC':
        enkey = aes.encrypt(key1)
        eniv = aes.encrypt(iv)
        conn.send(enkey)
        conn.send(eniv)
    else:
        if keytype == 'OFB':
            enkey = aes.encrypt(key2)
            eniv = aes.encrypt(iv)
            conn.send(enkey)
            conn.send(eniv)
        else:
            conn.send(b'Optiune gresita')



conn.close()  # close the connection
