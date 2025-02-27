import hashlib
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes

# Numero 4 de Fernet
e = 65537


# Función para generar claves RSA
def generate_keys(bits=1024):
    p = getPrime(bits, randfunc=get_random_bytes)
    q = getPrime(bits, randfunc=get_random_bytes)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    return n, d


# Función para cifrar un mensaje
def encrypt_message(message, public_key):
    n = public_key
    blocks = [message[i:i+128] for i in range(0, len(message), 128)]
    encrypted_blocks = [pow(bytes_to_long(block.encode()), e, n) for block in blocks]
    return encrypted_blocks


# Función para descifrar un mensaje
def decrypt_message(encrypted_blocks, public_key, private_key):
    n = public_key
    d = private_key
    decrypted_blocks = [long_to_bytes(pow(block, d, n)).decode() for block in encrypted_blocks]
    return "".join(decrypted_blocks)


# Función para generar el hash de un mensaje
def hash_message(message):
    return hex(int.from_bytes(hashlib.sha256(message.encode('utf-8')).digest(), byteorder='big'))


# Generamos claves para Bob
nB, dB = generate_keys()
print(f'Clave pública de Bob n: {nB}')
print(f'Clave privada de Bob d: {dB}')

message = "Hola Mundo"*105
print(f'\nMensaje original: {message}')

# Cifrado y descifrado
encrypted_blocks = encrypt_message(message, nB)
decrypted_message = decrypt_message(encrypted_blocks, nB, dB)
print(f'\nMensaje descifrado: {decrypted_message}')

# Verificación de integridad
original_hash = hash_message(message)
decrypted_hash = hash_message(decrypted_message)
print(f'\nHash original: {original_hash}')
print(f'Hash descifrado: {decrypted_hash}')
print(f'\n¿Los hashes coinciden? {original_hash == decrypted_hash}')