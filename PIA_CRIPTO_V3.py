import os
import sys
import sqlite3
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ------------------------------------------------------------
#
# El programa unicamente corre estando dentro del CMD o un compilador como PyCharm el cual fue utilizado
# para la creacion de este codigo
#
# Este fue mi PIA de Criptografia, pero posteriormente lo tome como un mini proyecto
# personal el cual puedo usar con diversos propositos, desde realizar otros pias hasta
# analizarlo para algun futuro PIA en el cual pueda hacer uso de este tanto para analizar como implementarlo.
#
# Este es una nueva version la cual exporte a un nuevo
#  documento para llevar una constancia de mi progreso
# esta nueva version hace uso de SQlite para almacenar
# los datos ya que previamente solo con
# fines de prueba y error usaba
# archivos .txt para almacenar los datos.
#
# Como un pequeño extra, se utilizo CHATGPT unicamente para hacer el cambio basico de archivos .txt a sqlite
# Aunque CHATGPT cambio muchas partes del codigo dejandolo mas limpio y ordenado de lo que estaba originalmente
# Foto adjunta a este codigo como prueba de que no estaba nada ordenado
#
# El codigo inicial que utiliza arhivos .txt lo realize en un perido de 3 meses en base a mis
# conocimientos y ayuda de algunos compañeros.
#
# ------------------------------------------------------------


def rot13_cipher(text):
    result = ""
    for char in text:
        if char.isalpha():
            if char.islower():
                encoded_char = chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
            else:
                encoded_char = chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
            result += encoded_char
        else:
            result += char
    return result


# Funcion para crear la tabla 'credentials' en la base de datos
def create_credentials_table():
    conn = sqlite3.connect('encriptado.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            username TEXT PRIMARY KEY,
            password TEXT
        )
    ''')
    conn.commit()
    conn.close()


# Funcion para validar las credenciales en la base de datos
def validate_credentials(rotUser, rotPass):
    conn = sqlite3.connect('encriptado.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM credentials WHERE username=? AND password=?', (rotUser, rotPass))
    result = cursor.fetchone() is not None
    conn.close()
    return result


# Funcion para almacenar las credenciales en la base de datos
def store_credentials(rotUser, rotPass):
    conn = sqlite3.connect('encriptado.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO credentials (username, password) VALUES (?, ?)', (rotUser, rotPass))
    conn.commit()
    conn.close()


# Funcion para almacenar la clave pública en la base de datos
def store_public_key(public_key):
    conn = sqlite3.connect('encriptado.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO keys (type, value) VALUES (?, ?)', ('public', str(public_key)))
    conn.commit()
    conn.close()


# Funcion para almacenar la clave privada en la base de datos
def store_private_key(private_key):
    conn = sqlite3.connect('encriptado.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO keys (type, value) VALUES (?, ?)', ('private', str(private_key)))
    conn.commit()
    conn.close()


# Funcion para cifrar un mensaje y almacenarlo en la base de datos
def encrypt_and_store_message(public_key, message):
    ephemeral_private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), public_key)
    Extra = b'UnaPiscaDeSal'  # esto puede cambiarse para modificar la sal dentro del texto a encriptar
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=Extra,
        info=b'',
        backend=default_backend()
    )
    encryption_key = kdf.derive(shared_secret)
    iv = os.urandom(12)
    cipher = AESGCM(encryption_key)
    ciphertext = cipher.encrypt(iv, message, None)
    encrypted_message = iv + ciphertext

    conn = sqlite3.connect('encriptado.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO messages (iv, ciphertext) VALUES (?, ?)', (iv, ciphertext))
    conn.commit()
    conn.close()

    return encrypted_message

# Funcion para almacenar el mensaje en texto plano en la base de datos
# [DEBE SER BORRADA, UNICAMENTE SIRVE PARA COMPROBAR QUE ESTE PROGRAMA FUNCIONA]
def store_plain_text_message(plain_text):
    conn = sqlite3.connect('encriptado.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO plain_text_messages (message) VALUES (?)', (plain_text,))
    conn.commit()
    conn.close()

# Función para crear la tabla 'keys' en la base de datos
def create_keys_table():
    conn = sqlite3.connect('encriptado.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            type TEXT,
            value TEXT
        )
    ''')
    conn.commit()
    conn.close()


# Función para crear la tabla 'messages' en la base de datos
def create_messages_table():
    conn = sqlite3.connect('encriptado.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            iv BLOB,
            ciphertext BLOB
        )
    ''')
    conn.commit()
    conn.close()

# Funcion para crear la tabla 'message' que almacena el mensaje en texto plano en la base de datos
# [DEBE SER BORRADA, UNICAMENTE SIRVE PARA COMPROBAR QUE ESTE PROGRAMA FUNCIONA]
def create_plain_text_messages_table():
    conn = sqlite3.connect('encriptado.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS plain_text_messages (
            message TEXT
        )
    ''')
    conn.commit()
    conn.close()


# Crear las tablas necesarias al inicio del programa
create_credentials_table()
create_keys_table()
create_messages_table()
create_plain_text_messages_table()  # esta tabla debe ser borrada para no exponer el mensaje original

selection = input('Escriba el numero deseado: (1 Loggin || 2 Registro): ')

if selection == '1':
    username = input('Ingrese usuario: ')
    password = input('Ingrese contraseña: ')
    rotUser = rot13_cipher(username)
    rotPass = rot13_cipher(password)

    if validate_credentials(rotUser, rotPass):
        print('Inicio de sesión exitoso!')

        private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
        public_key = private_key.public_key()

        message = input("Ingrese texto a encriptar:  ")
        store_plain_text_message(message)
        message_bytes = message.encode('utf-8')
        encrypted_message = encrypt_and_store_message(public_key, message_bytes)

        # Almacenar las claves en la base de datos
        store_public_key(public_key)
        store_private_key(private_key)

        print("El contenido se encriptó con éxito.")

    else:
        print("Usuario o contraseña no válidos, finalizando programa.")
        sys.exit(0)

elif selection == '2':
    username = input('Ingrese usuario: ')
    password = input('Ingrese contraseña: ')
    confirm_password = input('Confirme contraseña: ')

    if password == confirm_password:
        rotUser = rot13_cipher(username)
        rotPass = rot13_cipher(password)

        # Almacenar las credenciales en la base de datos
        store_credentials(rotUser, rotPass)

        print('Registro exitoso!')
    else:
        print('Las contraseñas no coinciden')
        sys.exit(0)

else:
    print('Selección no válida')
    sys.exit(0)
