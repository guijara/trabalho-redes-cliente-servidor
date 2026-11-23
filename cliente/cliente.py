import hashlib
import json
import os
import socket
import struct
import sys

PORTA = 5001
TAMANHO_BUFFER = 4096


def calcular_sha256(caminho_arquivo: str) -> str:
    """Calcula o hash SHA-256 lendo o arquivo em blocos (suporta arquivos grandes)."""
    hasher = hashlib.sha256()
    with open(caminho_arquivo, "rb") as arquivo:
        while bloco := arquivo.read(TAMANHO_BUFFER):
            hasher.update(bloco)
    return hasher.hexdigest()


def enviar_arquivo(ip_servidor: str, caminho_arquivo: str, corromper: bool = False) -> None:
    if not os.path.isfile(caminho_arquivo):
        print(f"[ERRO] Arquivo não encontrado: {caminho_arquivo}")
        sys.exit(1)

    nome_arquivo = os.path.basename(caminho_arquivo)
    tamanho_arquivo = os.path.getsize(caminho_arquivo)
    hash_arquivo = calcular_sha256(caminho_arquivo)

    print(f"[*] Arquivo: {nome_arquivo} ({tamanho_arquivo} bytes)")
    print(f"[*] SHA-256 local: {hash_arquivo}")

    # Se o arquivo for vazio (0 bytes) e o modo de teste estiver ativo, corrompe o hash
    hash_no_cabecalho = hash_arquivo
    if corromper and tamanho_arquivo == 0:
        hash_no_cabecalho = "0" * 64
        print("[TESTE] Arquivo vazio: enviando hash propositalmente adulterado.")

    # Monta o cabeçalho em JSON e empacota seu tamanho em 4 bytes (Big-Endian)
    cabecalho = {
        "nome_arquivo": nome_arquivo,
        "tamanho_arquivo": tamanho_arquivo,
        "sha256": hash_no_cabecalho,
    }
    cabecalho_bytes = json.dumps(cabecalho).encode("utf-8")
    tamanho_cabecalho_bytes = struct.pack("!I", len(cabecalho_bytes))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cliente:
        try:
            print(f"[*] Conectando a {ip_servidor}:{PORTA}...")
            cliente.connect((ip_servidor, PORTA))
        except (ConnectionRefusedError, socket.gaierror, OSError) as erro:
            print(f"[ERRO] Não foi possível conectar ao servidor: {erro}")
            sys.exit(1)

        # 1. Envia tamanho do cabeçalho (4 bytes) + cabeçalho JSON
        cliente.sendall(tamanho_cabecalho_bytes)
        cliente.sendall(cabecalho_bytes)

        # 2. Envia o conteúdo do arquivo em blocos de 4 KB
        ja_corrompeu = False
        with open(caminho_arquivo, "rb") as arquivo:
            while bloco := arquivo.read(TAMANHO_BUFFER):
                if corromper and not ja_corrompeu:
                    # Inverte todos os bits do primeiro byte apenas em memória (XOR 0xFF)
                    bloco = bytes([bloco[0] ^ 0xFF]) + bloco[1:]
                    ja_corrompeu = True
                    print("[TESTE] Simulando corrupção: 1 byte alterado durante o envio.")
                cliente.sendall(bloco)

        print("[*] Envio concluído. Aguardando validação do servidor...")

        # 3. Recebe o retorno do servidor confirmando ou rejeitando o arquivo
        resposta = cliente.recv(1024).decode("utf-8")
        print(f"[SERVIDOR] {resposta}")


def main() -> None:
    if len(sys.argv) not in (3, 4) or (len(sys.argv) == 4 and sys.argv[3] != "--corromper"):
        print("Uso: python3 cliente.py <ip-do-servidor> <arquivo> [--corromper]")
        sys.exit(1)

    ip_servidor = sys.argv[1]
    caminho_arquivo = sys.argv[2]
    corromper = len(sys.argv) == 4 and sys.argv[3] == "--corromper"

    enviar_arquivo(ip_servidor, caminho_arquivo, corromper)


if __name__ == "__main__":
    main()