import socket
from Cryptodome.Cipher import AES

#functia de padding
def padding(bin1,l):
    i=int(len(bin1)%AES.block_size)#aflu de cati biti am nevoie pt a completa
    aux = bytearray(bin1)
    aux.extend(bytearray([32] *(l-i)))#adaug l-i spatii la sfarsitul plaintextului
    return bytes(aux)


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def client_program():
    # valorile cunoscute pt toate nodurile
    key = b'Sixteen byte key'
    qMAX = 15
    q = 15
    host = socket.gethostname()
    port = 5000  # portul pt comunicarea cu nodul B
    B_socket = socket.socket()
    B_socket.connect((host, port))  # conectez cu B
    port2 = 5001 # portul pt comunicarea cu KeyManagerul
    KM_socket = socket.socket()
    KM_socket.connect((host, port2)) # conectez cu KeyManagerul

    plaintext = b'Implementati o infrastructura de comunicatie ce foloseste AES pentru criptarea traficului intre doua noduri A si B cu urmatoarele caracteristici: Context de initializare. Se considera un nod KM (key manager) care detine trei chei K1, K2 si K3. K1 este asociata cu modul de operare CBC. K2 este asociata cu modul de operare OFB. K3 este utilizata pentru criptarea cheilor K1 si K2. K3 este de asemenea detinuta din start si de nodurile A si B. Faza de initializare - Schimbul de chei. Pentru a initia o sesiune de comunicare securizata nodul A trimite un mesaj catre B in care comunica modul de operare (CBC sau OFB) si similar cere nodului KM cheia corespunzatoare. Cheia ceruta (K1 sau K2 in functie de modul de operare) este criptata ca un singur bloc cu AES de KM folosind cheia K3 si trimisa ca raspuns nodului A, ce o va trimite mai departe nodului B. A si B vor decripta cheia (K1 sau K2) la primire pentru a incepe comunicarea. '
    plaintext = padding(plaintext, AES.block_size)
    f = open("plaintext.txt", "r")
    plaintext = bytes(f.read().encode())
    plaintext = padding(plaintext, AES.block_size)

    nr = int(len(plaintext) / AES.block_size)
    i = 0
    aes1 = AES.new(key, AES.MODE_ECB)
    cipher = bytearray()
    while i < nr:
        if q== qMAX:
            q=0
            #blocul de initializare
              #cerem de la tastatura modul de operare
            op = input("Introduceti modul de operare:")
              # il transmitem KEyManagerului si nodului B
            KM_socket.send(op.encode())
            B_socket.send(op.encode())
              # primim de KeyManager cheia si vectorul de initializare
            enkey = KM_socket.recv(1024)
            eniv = KM_socket.recv(1024)
            # pe care le trimit mai departe la nodul B
            B_socket.send(enkey)
            B_socket.send(eniv)
            aes = AES.new(key, AES.MODE_ECB)
              #decriptez cheia si vectorul
            key = aes.decrypt(enkey)
            iv = aes.decrypt(eniv)
            print(key)
            print(iv)
        if op=='CBC':
            aes1 = AES.new(key, AES.MODE_ECB)
            #impart pe blocuri
            aux = plaintext[i * AES.block_size:(i + 1) * AES.block_size]
            #fac xor cu vectorul de intializare
            interm = byte_xor(aux, iv)
            #criptez rezultatul cu aes
            cip = aes1.encrypt(interm)
            print(cip)
            #trimit blocul criptat la B
            B_socket.send(cip)
            print(byte_xor(aes1.decrypt(cip),iv))

            cipher.extend(cip)
            #actualizez vectorul de initializare
            iv = cip
        else:
            aes1 = AES.new(key, AES.MODE_ECB)
            #impart pe blocuri
            aux = plaintext[i * AES.block_size:(i + 1) * AES.block_size]
            #criptez vectorul de initializare
            iv = aes1.encrypt(iv)
            #fac xor intre vector si blocul curent
            cip = byte_xor(aux, iv)
            print(cip)
            print(byte_xor(cip,iv))
            #trimit blocul criptat la B
            B_socket.send(cip)
            cipher.extend(cip)
        i = i + 1
        q = q + 1
    B_socket.close()  # inchid conexiunea cu celelalte noduri
    KM_socket.close()
    #copii intr-un fisier rezultatul criptarii
    f2 = open("ciphertext.txt", "w")
    f2.write(str(cipher))


if __name__ == '__main__':
    client_program()