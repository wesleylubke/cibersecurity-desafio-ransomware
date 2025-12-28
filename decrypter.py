#!/usr/bin/env python3
"""
Descriptografa um arquivo e SUBSTITUI o conteúdo criptografado pelo original.

Compatível com encrypter_replace.py (AES-256-GCM).
"""

import argparse
import getpass
import struct
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# Identificador do arquivo criptografado
MAGIC = b"WENC"
# Versão suportada
SUPPORTED_VERSION = 1


def derivar_chave(senha: str, salt: bytes, iteracoes: int) -> bytes:
    """Deriva a chave AES-256 a partir da senha e do salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iteracoes,
    )
    return kdf.derive(senha.encode())


def ler_cabecalho(blob: bytes):
    """Extrai informações do cabeçalho do arquivo criptografado."""
    if len(blob) < 11:
        raise ValueError("Arquivo inválido ou corrompido.")

    if blob[:4] != MAGIC:
        raise ValueError("O arquivo não está em um formato criptografado válido.")

    versao = blob[4]
    if versao != SUPPORTED_VERSION:
        raise ValueError("Versão do arquivo não suportada.")

    salt_len = blob[5]
    nonce_len = blob[6]
    iteracoes = struct.unpack(">I", blob[7:11])[0]

    inicio = 11
    salt = blob[inicio:inicio + salt_len]
    nonce = blob[inicio + salt_len:inicio + salt_len + nonce_len]

    tamanho_cabecalho = inicio + salt_len + nonce_len
    return tamanho_cabecalho, salt, nonce, iteracoes


def main():
    parser = argparse.ArgumentParser(
        description="Descriptografa um arquivo e substitui o conteúdo original."
    )
    parser.add_argument("input", help="Arquivo criptografado (será substituído)")
    args = parser.parse_args()

    caminho = Path(args.input)
    if not caminho.is_file():
        print("Erro: arquivo não encontrado.")
        return 1

    senha = getpass.getpass("Digite a senha: ")
    if not senha:
        print("Erro: senha vazia.")
        return 2

    try:
        # Lê o arquivo criptografado
        blob = caminho.read_bytes()

        # Extrai metadados do cabeçalho
        tamanho_cabecalho, salt, nonce, iteracoes = ler_cabecalho(blob)
        dados_cifrados = blob[tamanho_cabecalho:]

        # Deriva a chave e descriptografa
        chave = derivar_chave(senha, salt, iteracoes)
        aesgcm = AESGCM(chave)
        dados_originais = aesgcm.decrypt(nonce, dados_cifrados, None)

        # Escreve em arquivo temporário
        temporario = caminho.with_suffix(caminho.suffix + ".tmp")
        temporario.write_bytes(dados_originais)

        # Substitui o arquivo criptografado
        temporario.replace(caminho)

        print(f"Arquivo descriptografado: {caminho}")
        return 0

    except Exception as erro:
        print(f"Falha na descriptografia: {erro}")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
