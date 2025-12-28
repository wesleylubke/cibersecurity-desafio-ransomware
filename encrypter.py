#!/usr/bin/env python3
"""
Criptografa um arquivo e SUBSTITUI o original de forma segura.

Características:
- Criptografia autenticada AES-256-GCM (confidencialidade + integridade)
- Chave derivada de senha do usuário (PBKDF2)
- O arquivo original só é substituído APÓS a criptografia bem-sucedida
"""

import argparse
import getpass
import os
import struct
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# Identificador do arquivo criptografado
MAGIC = b"WENC"
# Versão do formato
VERSION = 1

# Parâmetros criptográficos
SALT_LEN = 16
NONCE_LEN = 12
KDF_ITERS = 200_000


def derivar_chave(senha: str, salt: bytes) -> bytes:
    """Deriva uma chave AES-256 a partir de uma senha."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERS,
    )
    return kdf.derive(senha.encode())


def criptografar_dados(dados: bytes, senha: str):
    """Criptografa os dados e retorna salt, nonce e texto cifrado."""
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    chave = derivar_chave(senha, salt)
    aesgcm = AESGCM(chave)
    dados_cifrados = aesgcm.encrypt(nonce, dados, None)
    return salt, nonce, dados_cifrados


def montar_cabecalho(salt: bytes, nonce: bytes) -> bytes:
    """Monta o cabeçalho com metadados necessários para descriptografia."""
    return b"".join([
        MAGIC,
        struct.pack(">B", VERSION),
        struct.pack(">B", len(salt)),
        struct.pack(">B", len(nonce)),
        struct.pack(">I", KDF_ITERS),
        salt,
        nonce,
    ])


def main():
    parser = argparse.ArgumentParser(
        description="Criptografa um arquivo e substitui o original (AES-256-GCM)."
    )
    parser.add_argument("input", help="Arquivo a ser criptografado (será substituído)")
    args = parser.parse_args()

    caminho = Path(args.input)
    if not caminho.is_file():
        print("Erro: arquivo não encontrado.")
        return 1

    senha = getpass.getpass("Digite a senha: ")
    confirmacao = getpass.getpass("Confirme a senha: ")
    if not senha or senha != confirmacao:
        print("Erro: senha inválida ou não confere.")
        return 2

    try:
        # Lê o conteúdo original
        dados = caminho.read_bytes()

        # Criptografa
        salt, nonce, dados_cifrados = criptografar_dados(dados, senha)
        cabecalho = montar_cabecalho(salt, nonce)

        # Escreve em arquivo temporário
        temporario = caminho.with_suffix(caminho.suffix + ".tmp")
        temporario.write_bytes(cabecalho + dados_cifrados)

        # Substitui o arquivo original apenas se tudo deu certo
        temporario.replace(caminho)

        print(f"Arquivo criptografado: {caminho}")
        return 0

    except Exception as erro:
        print(f"Falha na criptografia: {erro}")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
