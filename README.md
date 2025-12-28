# 🔐 Projeto de Criptografia de Arquivos em Python (AES-256-GCM)

Este projeto implementa um **sistema seguro de criptografia e descriptografia de arquivos** em Python, utilizando **AES-256-GCM** com **derivação de chave baseada em senha (PBKDF2)**.

O comportamento foi projetado para **substituir o arquivo original** após a operação, de forma **segura e controlada**, simulando cenários reais (ex.: ransomware didático), porém seguindo **boas práticas criptográficas**.

---

## 📌 Funcionalidades

- 🔒 Criptografia autenticada **AES-256-GCM**
- 🔑 Chave derivada de senha do usuário (**PBKDF2 + salt**)
- 🧾 Cabeçalho com metadados (salt, nonce, iterações)
- ♻️ Substituição segura do arquivo original (somente após sucesso)
- ❌ Nenhuma chave hardcoded
- 🛡️ Proteção contra corrupção e senha incorreta
- 💻 Compatível com Windows (Git Bash / PowerShell) e Linux (WSL)

---

## 📂 Arquivos do Projeto

```text
.
├── encrypter.py   # Criptografa e substitui o arquivo original
├── decrypter.py   # Descriptografa e restaura o arquivo
└── README.md
