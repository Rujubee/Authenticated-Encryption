from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC
import hashlib

def gerar_chave(senha, sal):
    #global sal
    #sal = get_random_bytes(16)

    chave_secreta = PBKDF2(senha, sal, hmac_hash_module=SHA256)
   # chave_secreta = PBKDF2(senha, sal, 16, count=1000000, hmac_hash_module=SHA256)
    return chave_secreta

def gerar_MAC(dados, chave):
    mac_tag = HMAC.new(chave, dados, digestmod=SHA256)

    return mac_tag.hexdigest()


def encriptar(dados, chave, chave_mac, modo, iv):

    if modo == 1:      #Encrypt-Then-Mac
        print('Você escolheu o modo Encrypt-Then-Mac')

        encrypter = AES.new(chave, AES.MODE_CBC, iv)
        ciphertext = encrypter.encrypt(pad(dados,16)) # Realizando o padding dos dados e encriptando

        tag = gerar_MAC(ciphertext, chave_mac) # Gerando a tag

        return ciphertext + b'\x00' + bytes(tag, 'utf8') # Retornando o texto cifrado concatenado com a tag. "b'\x00'" foi escolhido como o ponto que os separa. Isso também foi utilizado para os outros dois modos.
    elif modo == 2:
        print('Você escolheu o modo Encrypt-And-Mac')

        dados = pad(dados, 16)
        encrypter = AES.new(chave, AES.MODE_CBC, iv)
        ciphertext = encrypter.encrypt(dados)  # Encrypt

        tag = gerar_MAC(dados, chave)  # Gerando a tag a partir da mensagem antes da encriptação

        return ciphertext + b'\x00' + bytes(tag, 'utf8')
    elif modo == 3:
        print('Você escolheu o modo Mac-Then-Encrypt')

        dados = pad(dados, 16)
        tag = gerar_MAC(dados, chave)  # Assim como o Encrypt-And-Mac, a tag também é criada a partir dos dados antes da encriptação.

        tagging_dados = dados + b'\x00' + bytes(tag, 'utf-8') # Realizando o Mac

        encrypter = AES.new(chave, AES.MODE_CBC, iv)
        ciphertext = encrypter.encrypt(pad(tagging_dados, 16))  # Then-Encrypt

        return ciphertext

def decriptar(dados, chave, chave_mac, modo, iv):

    if modo == 1:
        ciphertext, tag = dados.split(b'\x00') # Separação do texto cifrado e da tag
        tag = tag.decode('ascii') # Decodificando a tag, visto que foi necessário ser convertida em bytes na encriptação. A mesma estratégia de separação é feita para os outros dois modos.

        if gerar_MAC(ciphertext, chave_mac) == tag: # Autenticação e decriptação
            print('[Mensagem encriptada e decriptada] \nA Autenticação foi realizada com sucesso!')  # True
            decrypter = AES.new(chave, AES.MODE_CBC, iv)
            decrypted_message = unpad(decrypter.decrypt(ciphertext), 16)
        else:
            print('[Falha na decriptação] \nA autenticação falhou!') # False
            return 0

    elif modo == 2:
        ciphertext, tag = dados.split(b'\x00')
        tag = tag.decode('ascii')

        decrypter = AES.new(chave, AES.MODE_CBC, iv)
        decrypted_message = decrypter.decrypt(ciphertext) # A decriptação é feita antes da autenticação pois o MAC foi gerado a partir da mensagem original

        if gerar_MAC(decrypted_message, chave) == tag:  # Autenticação da tag
            print('[Mensagem encriptada e decriptada] \nA Autenticação foi realizada com sucesso!') # True
            decrypted_message = unpad(decrypted_message, 16)
        else:
            print('[Falha na decriptação] \nA autenticação falhou!') # False
            return 0

    elif modo == 3:
        decrypter = AES.new(chave, AES.MODE_CBC, iv) # Primeiramente é necessário realizar a decriptação da mensagem concatenada à tag antes da separação e da autenticação
        decrypted_message = decrypter.decrypt(dados)

        decrypted_message = unpad(decrypted_message, 16)

        dados, tag = decrypted_message.split(b'\x00')  # Separação do texto decifrado e da tag
        tag = tag.decode('ascii')

        if gerar_MAC(dados, chave) == tag: # Como o mac foi gerado a partir da mensagem antes da encriptação, a mesma é utilizada na autenticação
            print('[Mensagem encriptada e decriptada] \nAutenticação foi realizada com sucesso!') # True
            decrypted_message = unpad(dados, 16)
        else:
            print('[Falha na decriptação] \nA autenticação falhou!') # False
            return 0

    return decrypted_message


###def main():
while True:

    dados_usuario = bytes(input("Digite a mensagem a ser encriptada: "), 'utf-8')
    #dados_usuario = b'brucebruce'

    senha_usuario = input('Informe uma senha para gerar a chave secreta: ')

    modo_encriptacao = int(input('Escolha o método de encriptação autenticada:\n (1) Encrypt-Then-Mac\n (2) Encrypt-And-Mac\n (3) Mac-Then-Encrypt\n'))

    iv = get_random_bytes(16)
    sal = get_random_bytes(16)
    chave_mac = gerar_chave(get_random_bytes(16), sal)

    chave_encriptada = gerar_chave(senha_usuario, sal)
    resultado_encriptacao = encriptar(dados_usuario, chave_encriptada, chave_mac, modo_encriptacao, iv)

    resultado_decriptacao = decriptar(resultado_encriptacao, chave_encriptada, chave_mac, modo_encriptacao, iv)
    assert(dados_usuario == resultado_decriptacao)


    continuar = input(print('\nDeseja realizar outra operação? [S/N]'))

    if continuar == 'N':
        break