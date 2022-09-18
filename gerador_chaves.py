"""Gerador de Chaves RSA

TODO: remover dependência com RSA
TODO: usar hashlib.sha3 para assinatura e verificação
TODO: como converter int <-> DER|PEM?
TODO: como gerar números primos de 1024 bits?
"""

import rsa

def gera_chaves(
    pasta: [str] = ['keys'],
    chave_pub: str = 'chavePub',
    chave_priv: str = 'chavePriv',
    formato: str = 'PEM'
) -> None:
    (pub_chave, priv_chave) = rsa.newkeys(nbits = 1024)

    with open(f'{"/".join(pasta)}/{chave_pub}.{formato.lower()}', 'wb') as pub_arquivo:
        pub_arquivo.write(pub_chave.save_pkcs1(formato))
    with open(f'{"/".join(pasta)}/{chave_priv}.{formato.lower()}', 'wb') as priv_arquivo:
        priv_arquivo.write(priv_chave.save_pkcs1(formato))

def carrega_chaves(
    pasta: [str] = ['keys'],
    chave_pub: str = 'chavePub',
    chave_priv: str = 'chavePriv',
    formato: str = 'PEM'
) -> (rsa.PublicKey, rsa.PrivateKey):
    with open(f'{"/".join(pasta)}/{chave_pub}.{formato.lower()}', 'rb') as pub_arquivo:
        pub_chave = rsa.PublicKey.load_pkcs1(pub_arquivo.read())

    with open(f'{"/".join(pasta)}/{chave_priv}.{formato.lower()}', 'rb') as priv_arquivo:
        priv_chave = rsa.PrivateKey.load_pkcs1(priv_arquivo.read())

    return pub_chave, priv_chave

def encripta(mensagem: str, chave_pub: rsa.PublicKey):
    return rsa.encrypt(mensagem.encode('ascii'), chave_pub)

def decripta(criptograma: bytes, chave_priv: rsa.PrivateKey):
    try:
        return rsa.decrypt(criptograma, chave_priv).decode('ascii')
    except DecryptionError:
        return False

def assina_sha1(mensagem: str, chave_priv: rsa.PrivateKey) -> bytes:
    return rsa.sign(mensagem.encode('ascii'), chave_priv, 'SHA-1')

def verifica_sha1(mensagem: str, assinatura: bytes, chave_pub: rsa.PublicKey) -> bool:
    try:
        return rsa.verify(mensagem.encode('ascii'), assinatura, chave_pub) == 'SHA-1'
    except VerificationError:
        return False

if __name__ == '__main__':
    gera_chaves(
        chave_pub='chaveAlinePub',
        chave_priv='chaveAlinePriv'
    )
    (aline_chave_pub, aline_chave_priv) = carrega_chaves(
        chave_pub='chaveAlinePub',
        chave_priv='chaveAlinePriv'
    )

    gera_chaves(
        chave_pub='chaveMarianaPub',
        chave_priv='chaveMarianaPriv'
    )
    (mariana_chave_pub, mariana_chave_priv) = carrega_chaves(
        chave_pub='chaveMarianaPub',
        chave_priv='chaveMarianaPriv'
    )
    
    """
    A |msg|-> B
    encripta(msg, b_chave_pub)
    assina_sha1(msg, a_chave_priv)
    
    decripta(criptograma, b_chave_priv)
    verifica_sha1(msg, assinatura, a_chave_pub)
    """

    mensagem = input('mensagem para criptografar: ')    
    criptograma = encripta(mensagem, mariana_chave_pub)

    assinatura = assina_sha1(mensagem, aline_chave_priv)

    texto_limpo = decripta(criptograma, mariana_chave_priv)

    print(f'Criptograma: {criptograma}')
    print(f'Assinatura: {assinatura}')
    if texto_limpo:
        print(f'Texto Limpo: {texto_limpo}')
    else:
        print('Não foi possível decodificar')

    if verifica_sha1(texto_limpo, assinatura, aline_chave_pub):
        print('Assinatura verificada')
    else:
        print('Não foi possível verificar a assinatura')
    