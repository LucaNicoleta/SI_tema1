import socket
from Cryptodome.Cipher import AES


# functia ce realizeaza xor pe biti
def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def server_program():
    # valorile cunoscute pt toate nodurile
    key = b'Sixteen byte key'
    qMAX = 15
    q=15
    #configurarea socketului
    host = socket.gethostname()
    port = 5000
    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(2)
    conn, address = server_socket.accept()

    decrypt = bytearray()
    while True:
        if q==qMAX:
            q=0
            #blocul de initializare
            aes = AES.new(key, AES.MODE_ECB)
            mod = conn.recv(1024).decode()
            enkey = conn.recv(1024)
            eniv = conn.recv(1024)

            key = aes.decrypt(enkey)
            iv = aes.decrypt(eniv)
            print(key)
            print(iv)
        ciphertext = conn.recv(AES.block_size)
        if ciphertext == b'':
            break
        if mod == 'CBC':
            aes1 = AES.new(key, AES.MODE_ECB)
            cip = aes1.decrypt(ciphertext)
            interm = byte_xor(cip, iv)
            decrypt.extend(interm)
            print(byte_xor(aes1.decrypt(ciphertext),iv))
            iv = ciphertext
        else:

            aes2=AES.new(key, AES.MODE_ECB)
            iv = aes2.encrypt(iv)
            cip = byte_xor(ciphertext, iv)
            decrypt.extend(cip)
            print(cip)
        q = q + 1
    conn.close()  # close the connection
    f2 = open("decrypted.txt", "w")
    f2.write(decrypt.decode())

if __name__ == '__main__':
    server_program()