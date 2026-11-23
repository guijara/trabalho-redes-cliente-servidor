import hashlib
import json
import os
import socket
import struct

HOST = "0.0.0.0"  # Aceita conexões locais (localhost) e da rede local
PORTA = 5001
TAMANHO_BUFFER = 4096

# Garante que o arquivo será salvo na pasta onde servidor.py está localizado,
# independentemente do diretório de onde o script foi executado.
DIRETORIO_SERVIDOR = os.path.dirname(os.path.abspath(__file__))


def receber_exato(conexao: socket.socket, quantidade: int) -> bytes:
    """Lê exatamente 'quantidade' bytes do socket TCP, lidando com leituras parciais."""
    dados = bytearray()
    while len(dados) < quantidade:
        restante = quantidade - len(dados)
        bloco = conexao.recv(min(TAMANHO_BUFFER, restante))
        if not bloco:
            raise ConnectionError("Conexão encerrada antes de receber todos os dados.")
        dados.extend(bloco)
    return bytes(dados)


def processar_cliente(conexao: socket.socket, endereco: tuple[str, int]) -> None:
    print(f"\n[+] Conexão estabelecida com {endereco[0]}:{endereco[1]}")

    # 1. Lê os 4 bytes iniciais que indicam o tamanho do cabeçalho JSON
    bytes_tamanho_cabecalho = receber_exato(conexao, 4)
    (tamanho_cabecalho,) = struct.unpack("!I", bytes_tamanho_cabecalho)

    # 2. Lê e decodifica o cabeçalho JSON com os metadados
    cabecalho_bruto = receber_exato(conexao, tamanho_cabecalho)
    cabecalho = json.loads(cabecalho_bruto.decode("utf-8"))

    # os.path.basename impede ataques de path traversal (ex: "../../arquivo.txt")
    nome_arquivo = os.path.basename(cabecalho["nome_arquivo"])
    tamanho_arquivo = int(cabecalho["tamanho_arquivo"])
    hash_recebido = cabecalho["sha256"]

    if not nome_arquivo:
        raise ValueError("Nome de arquivo inválido recebido no cabeçalho.")

    print(f"[*] Recebendo '{nome_arquivo}' ({tamanho_arquivo} bytes)...")

    # 3. Recebe o conteúdo completo do arquivo em memória (sem gravar em disco ainda)
    dados_arquivo = receber_exato(conexao, tamanho_arquivo)

    # 4. Calcula o SHA-256 dos bytes recebidos e compara com o enviado pelo cliente
    hash_calculado = hashlib.sha256(dados_arquivo).hexdigest()

    print(f"    Hash enviado pelo cliente : {hash_recebido}")
    print(f"    Hash calculado no servidor: {hash_calculado}")

    if hash_calculado == hash_recebido:
        caminho_destino = os.path.join(DIRETORIO_SERVIDOR, nome_arquivo)
        with open(caminho_destino, "wb") as arquivo:
            arquivo.write(dados_arquivo)

        print(f"[OK] Integridade confirmada! Arquivo salvo em: {caminho_destino}")
        conexao.sendall("OK: Hash verificado. Arquivo salvo no servidor.".encode("utf-8"))
    else:
        print("[ERRO] Hashes divergentes! O arquivo NÃO foi salvo no servidor.")
        conexao.sendall(
            "ERRO: Integridade comprometida (hash divergente). Arquivo descartado.".encode("utf-8")
        )


def iniciar_servidor() -> None:
    # AF_INET = IPv4 | SOCK_STREAM = TCP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as servidor:
        # SO_REUSEADDR permite reiniciar o servidor imediatamente na mesma porta
        # sem esperar o estado TCP TIME_WAIT expirar.
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        servidor.bind((HOST, PORTA))
        servidor.listen(1)  # 1 conexão por vez (sem threads)

        print(f"Servidor TCP aguardando conexões em {HOST}:{PORTA}...")
        print(f"Diretório de salvamento: {DIRETORIO_SERVIDOR}")
        print("Pressione Ctrl+C para encerrar.\n")

        try:
            while True:
                conexao, endereco = servidor.accept()
                with conexao:
                    try:
                        processar_cliente(conexao, endereco)
                    except (ConnectionError, ValueError, KeyError, json.JSONDecodeError) as erro:
                        print(f"[!] Falha na comunicação com {endereco}: {erro}")
        except KeyboardInterrupt:
            print("\nServidor encerrado pelo usuário.")


if __name__ == "__main__":
    iniciar_servidor()