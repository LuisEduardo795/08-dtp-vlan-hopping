# 08 — Ataque DTP VLAN Hopping
Ataque DTP — negocia trunk y salta VLANs - Convertir puerto acceso en trunk


## Objetivo del Laboratorio
Demostrar cómo un atacante puede explotar el protocolo DTP para
negociar un enlace trunk con el switch, convirtiendo un puerto
de acceso en trunk y ganando acceso a todas las VLANs de la red
sin autorización.

---

## Objetivo del Script
Enviar mensajes DTP Desirable para negociar un trunk con el switch
y luego enviar frames 802.1Q etiquetados hacia VLANs restringidas.

### Parámetros

| Parámetro | Descripción | Default |
|-----------|-------------|---------|
| `-i` | Interfaz de red | Obligatorio |
| `-c` | Mensajes DTP a enviar | 10 |
| `-d` | Delay entre mensajes (seg) | 1.0 |
| `--target-vlan` | VLAN objetivo para hopping | 10 |
| `--skip-hop` | Solo negociar trunk sin VLAN hop | False |

### Requisitos
- Python 3.8+
- Scapy: `pip3 install scapy`
- Puerto conectado al switch en modo dinámico (no hardcoded access)
- Ejecutar como root

---

## Topología de Red

```
[Ubuntu-Atacante]──e0/0──[SW-Core]──e0/1──[Linux-Victima VLAN 10]
 192.168.67.50                          └──e0/2──[Linux-Victima VLAN 20]
```

| Dispositivo | Interfaz | VLAN | IP |
|---|---|---|---|
| Ubuntu-Atacante | ens3 | 1 | 192.168.67.50/24 |
| SW-Core | e0/0 - e0/2 | — | — |
| Linux-Victima 1 | ens3 | 10 | 192.168.67.60/24 |


---

## Funcionamiento del Script

1. Envía mensajes DTP con status `0x83` (Desirable/Trunk)
2. El switch en modo `dynamic auto` o `dynamic desirable` acepta
3. El puerto se convierte en trunk
4. El atacante puede enviar frames 802.1Q a cualquier VLAN
5. Puede acceder a VLANs restringidas (VLAN 10, 20, etc.)

```
NORMAL:
Puerto e0/0 → modo access VLAN 1 → solo ve VLAN 1

ATACADO:
Puerto e0/0 → modo trunk → ve TODAS las VLANs
```

---

## Uso

```bash
# Negociar trunk y hacer hopping a VLAN 10
sudo python3 dtp_vlan_hopping.py -i ens3 --target-vlan 10

# Solo negociar trunk
sudo python3 dtp_vlan_hopping.py -i ens3 --skip-hop

# Verificar en el switch
show interfaces trunk
show dtp interface e0/0
```

---

## Capturas de Pantalla

### Ataque en ejecución
![DTP ataque](capturas/dtp_ataque.png)

### Puerto convertido en trunk
![Trunk negociado](capturas/dtp_trunk.png)

---

## Contramedidas

```cisco
! Deshabilitar DTP en todos los puertos de acceso
interface range FastEthernet0/1-24
 switchport mode access
 switchport nonegotiate

! Para puertos trunk legítimos también deshabilitar negociación
interface GigabitEthernet0/1
 switchport mode trunk
 switchport nonegotiate

! Verificar
show dtp interface
show interfaces trunk
```

---

## Video Demostración
https://youtu.be/13gFsTbe2Wk

---

## Referencias
- [Cisco DTP Documentation](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst6500/ios/12-2SX/configuration/guide/book/trunk.html)
- [VLAN Hopping Attack](https://en.wikipedia.org/wiki/VLAN_hopping)
