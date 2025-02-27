import hashlib
import PyPDF2
from tasks.task1 import generate_keys

e = 65537


# Función para calcular el hash de un documento
def hash_document(document_path):
    with open(document_path, 'rb') as file:
        document = file.read()
    return int.from_bytes(hashlib.sha256(document).digest(), byteorder='big')


# Función para firmar un documento
def sign_document(document_path, public_key, private_key):
    n = public_key
    d = private_key
    hash_value = hash_document(document_path)
    signature = pow(hash_value, d, n)
    return signature


# Verificar la firma
def verify_signature(document_path, signature, public_key):
    n = public_key
    hash_value = hash_document(document_path)
    decrypted_hash = pow(signature, e, n)
    return hash_value == decrypted_hash


# Función para agregar la firma al PDF
def add_signature_to_pdf(document_path, signature, output_path):
    with open(document_path, 'rb') as file:
        reader = PyPDF2.PdfReader(file)
        writer = PyPDF2.PdfWriter()

        for page in reader.pages:
            writer.add_page(page)

        writer.add_metadata({"/Signature": str(signature)})

        with open(output_path, 'wb') as output:
            writer.write(output)


# Función para leer la firma desde el PDF
def read_signature_from_pdf(document_path):
    """Obtiene la firma desde los metadatos del PDF."""
    with open(document_path, 'rb') as file:
        reader = PyPDF2.PdfReader(file)
        metadata = reader.metadata
        return int(metadata.get("/Signature", 0))


# Generamos claves
alice_public, alice_private = generate_keys()
ac_public, ac_private = generate_keys()

# Ruta del documento a firmar
# M: message
document_path = "NDA.pdf"
signed_by_alice_path = "NDA_signed_by_alice.pdf"
signed_by_ac_path = "NDA_signed_by_ac.pdf"
print(f'Firmando el documento: {document_path}')

# Alice firma el documento
# Sa: Signature from Alice
alice_signature = sign_document(document_path, alice_public, alice_private)
add_signature_to_pdf(document_path, alice_signature, signed_by_alice_path)
print(f'Firma de Alice añadida al PDF: {alice_signature}')

# Verify using Alice's public key
# La Autoridad Certificadora verifica la firma de Alice
alice_signature_from_pdf = read_signature_from_pdf(signed_by_alice_path)
is_valid = verify_signature(document_path, alice_signature_from_pdf, alice_public)
print(f'¿Firma de Alice válida? {is_valid}')

# St: Signature from trusted center
# La AC firma el documento
ac_signature = sign_document(signed_by_alice_path, ac_public, ac_private)
add_signature_to_pdf(signed_by_alice_path, ac_signature, signed_by_ac_path)
print(f'Firma de la AC añadida al PDF: {ac_signature}')

# Verify using AC's public key
# Bob verifica la firma de la AC
ac_signature_from_pdf = read_signature_from_pdf(signed_by_ac_path)
is_ac_valid = verify_signature(signed_by_alice_path, ac_signature_from_pdf, ac_public)
print(f'¿Firma de la AC válida? {is_ac_valid}')
