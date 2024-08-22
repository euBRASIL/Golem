import streamlit as st
import ecdsa
import hashlib
import base58
import json
import sys
import requests
from tqdm import tqdm

# Variáveis globais
conta40 = 0
conta50 = 0

def corresponde(str1, str2):
    len_str1 = len(str1)
    len_str2 = len(str2)
    min_len = min(len_str1, len_str2)
    matching_chars = sum(1 for c1, c2 in zip(str1, str2) if c1 == c2)
    return (matching_chars / min_len) * 100

def analisar_chave(chave):
    global conta40
    global conta50

    credito = 0
    for bit in chave:
        if bit == '1':
            credito += 1

    if 30 < credito < 40: 
        conta40 += 1
    if 40 < credito < 50: 
        conta50 += 1

    return credito

def chavebitcoin(iniciohex, finalhex, premio):
    inicioint = int(iniciohex, 16)
    finalint  = int(finalhex, 16)
    read_size = 10000000
    skip_size = 1000000000000000

    numerocompleto = 0
    semDesafio = 0

    current = inicioint
    while current <= finalint:
        questao = min(current + read_size - 1, finalint)
        for privadaint in tqdm(range(current, questao + 1), desc="Progresso", unit="chaves"):
            privadahex = format(privadaint, 'x').zfill(64)
            privadabyt  = bytes.fromhex(privadahex)

            saldo = analisar_chave(bin(privadaint))

            if 30 < saldo < 32 or 33 < saldo < 35:
                sk = ecdsa.SigningKey.from_string(privadabyt, curve=ecdsa.SECP256k1)
                vk = sk.get_verifying_key()

                publicabyt = bytes.fromhex("04") + vk.to_string()
                algoritmo = hashlib.sha256(publicabyt).digest()
                ripemd160 = hashlib.new('ripemd160', algoritmo).digest()
                ripemd160_hex = ripemd160.hex()

                #if ripemd160_hex.startswith("1c05e9f") or ripemd160_hex.startswith("20d45a6"):
                extendida = b'\x00' + ripemd160
                checksum  = hashlib.sha256(hashlib.sha256(extendida).digest()).digest()[:4]
                address   = extendida + checksum
                bitcoin   = base58.b58encode(address).decode()

                percentual = corresponde(premio, bitcoin)

                if percentual > numerocompleto:
                    numerocompleto = percentual
                    wallet = bitcoin

                if percentual > 26 and bitcoin.startswith("13"):
                    valor_saldo = abs(saldo)

                    st.write(f"Chave Privada (hexadecimal)  : {privadahex}")
                    st.write(f"Endereço Bitcoin  (credito)  : {bitcoin}")
                    st.write(f"Percentual de Correspondência: {percentual:.2f}%")
                    st.write(f"Conta(bits): {valor_saldo} bits")
                    st.write("")

                    # base_url = "https://cryptoreal.eletron-bit.workers.dev/put"
                    dns_url  = "https://dns.eletron-bit.workers.dev/put"

                    # url_completa = f"{base_url}/{bitcoin}/{privadahex}"
                    dns_completo = f"{dns_url}/{privadaint}/{privadahex}"

                    # response_url = requests.get(url_completa)
                    response_dns = requests.get(dns_completo)

                    st.write(f"Status :  {response_dns.status_code}") #{response_url.status_code} /
                    st.write(f"Credito de 40 bits: {conta40}")
                    st.write(f"Credito de 50 bits: {conta50}")
                    st.write(f"Distância (decimal) : {privadaint}")
                    st.write("")

            if semDesafio > 99000000:
                st.write(f"Credito de 40 bits: {conta40}")
                st.write(f"Credito de 50 bits: {conta50}")
                st.write(f"Distância (decimal) : {privadaint}")
                semDesafio = 1
            else:
                semDesafio += 1

        current += read_size + skip_size

if __name__ == "__main__":
    st.title("Análise de Chaves Bitcoin")
    iniciohex = st.text_input("Hexadecimal Inicial", value="000000000000000000000000000000000000000000000003701ff973d0e11ec1")
    finalhex  = st.text_input("Hexadecimal Final", value="0000000000000000000000000000000000000000000000040000000000000000")
    premio    = st.text_input("Prêmio Bitcoin", value="13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so")
    
    if st.button("Iniciar Análise"):
        chavebitcoin(iniciohex, finalhex, premio)
