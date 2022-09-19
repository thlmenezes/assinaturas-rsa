"""Assina e Verifica Hashes
"""

import hashlib, transform, core, common
from typing import Protocol

class PublicKey(Protocol):
    n: int
    e: int

class PrivateKey(Protocol):
    n: int
    d: int

# Errors
class VerificationError(Exception):
    """Raised when verification fails."""

def _preenchimento_assinatura(mensagem: bytes, tamanho_desejado: int) -> bytes:
    """Preenche a mensagem para assinatura, retornando a mensagem preenchida.
    
    O preenchimento é feito com uma repetição de bytes FF
    
    >>> bloco = _preenchimento_assinatura(b'hello', 16)
    >>> len(bloco)
    16
    >>> bloco[0:2]
    b'\x00\x01'
    >>> bloco[-6:]
    b'\x00hello'
    >>> bloco[2:-6]
    b'\xff\xff\xff\xff\xff\xff\xff\xff'

    Raises:
        OverflowError: caso a mensagem seja maior do que o comprimento máximo (baseado no tamanho desejado)

    Returns:
        bytes: 00 01 PREENCHIMENTO 00 MENSAGEM
    """

    max_comprimento_msg = tamanho_desejado - 11
    comprimento_msg = len(mensagem)

    if comprimento_msg > max_comprimento_msg:
        raise OverflowError(
            f"{comprimento_msg} bytes needed for mensagem, " +
            f"but there is only space for {max_comprimento_msg}"
        )

    tamanho_preenchimento = tamanho_desejado - comprimento_msg - 3

    return b"".join([b"\x00\x01", tamanho_preenchimento * b"\xff", b"\x00", mensagem])

def _assina_hash(valor_hasheado: bytes, chave_priv: PrivateKey) -> bytes:    
    """Assina um valor hasheado pré computado com a chave privada

    Args:
        valor_hasheado (bytes): Valor hasheado pré computado a ser assinado
        chave_priv (PrivateKey): chave privada a ser usada na assinatura

    Raises:
        OverflowError: caso a chave privada seja pequena demais para conter o hash requisitado

    Returns:
        bytes: _description_
    """
    # Encrypt the hash with the private key
    tamanho_chave = common.byte_size(chave_priv.n)
    alinhado = _preenchimento_assinatura(valor_hasheado, tamanho_chave)

    payload = transform.bytes2int(alinhado)
    encriptado = core.encrypt_int(payload, chave_priv.d, chave_priv.n)
    bloco = transform.int2bytes(encriptado, tamanho_chave)

    return bloco

def _computa_hash(mensagem: bytes) -> bytes:
    """Retorna a mensagem "digerida" (digest).

    Args:
        mensagem (bytes): a mensagem assinada.

    Returns:
        bytes: a mensagem "digerida" (digest)
    """

    hasher = hashlib.sha3_256()
    hasher.update(mensagem)
    return hasher.digest()

def _assina_sha3(mensagem: bytes, chave_priv: PrivateKey) -> bytes:
    """Assina mensagem com a chave privada.
    
    Faz o hash da mensagem e assina com a chave dada,
    também conhecido como assinatura desvinculada
    (mensagem não é modificada no processo).

    Args:
        mensagem (bytes): mensagem a ser assinada
        chave_priv (PrivateKey): chave privada a ser utilizada na assinatura

    Raises:
        OverflowError: caso a chave privada seja pequena demais para conter o hash requisitado

    Returns:
        bytes: bloco de mensagem assinada
    """

    msg_hash = _computa_hash(mensagem)
    return _assina_hash(msg_hash, chave_priv)

def assina(mensagem: str, chave_priv: PrivateKey) -> bytes:
    return _assina_sha3(mensagem.encode('ascii'), chave_priv)

def _verifica(mensagem: bytes, assinatura: bytes, chave_pub: PublicKey) -> str:
    """Verifica que a assinatura é compatível com a mensagem

    Args:
        mensagem (bytes): a mensagem assinada
        assinatura (bytes): o bloco de assinatura, como criado em validador.assina
        chave_pub (PublicKey): a chave pública de quem, em tese, assinou a mensagem

    Raises:
        VerificationError: caso a assinatura não seja compatível com a mensagem.

    Returns:
        str: nome do algoritmo de hash utilizado
    """

    tamanho_chave = common.byte_size(chave_pub.n)
    encriptado = transform.bytes2int(assinatura)
    decifrado = core.decrypt_int(encriptado, chave_pub.e, chave_pub.n)
    assinatura_limpa = transform.int2bytes(decifrado, tamanho_chave)

    # Reconstrução do padded_hash esperado
    mensagem_hash = _computa_hash(mensagem)
    padded_hash = _preenchimento_assinatura(mensagem_hash, tamanho_chave)

    if len(assinatura) != tamanho_chave:
        raise VerificationError("Verificação Falhou")

    # Compara com a versão assinada
    if padded_hash != assinatura_limpa:
        raise VerificationError("Verificação Falhou")

    return 'SHA3-256'

def verifica(mensagem: str, assinatura: bytes, chave_pub: PublicKey) -> bool:
    try:
        return _verifica(mensagem.encode('ascii'), assinatura, chave_pub) == 'SHA3-256'
    except VerificationError:
        return False

__all__ = [
  "assina",
  "verifica"
]

if __name__ == "__main__":
    import doctest
    doctest.testmod()