# TFM — Exemples

Autor del TFM: Eduard Romero Prats.
Base reutilitzada: Daniel Rontomé, TFM_prowler, commit a3c65a77bb08b3614d476d5e39f4f51917ce387c.
https://github.com/rontomano/TFM_prowler/tree/a3c65a77bb08b3614d476d5e39f4f51917ce387c

## Què incorpora

El control network_vm_admin_access_restricted avalua els permisos d'entrada acumulats dels grups
de seguretat d'una NIC, respecte d'una política externa d'orígens IPv4 i ports TCP.
És un primer prototip, no una validació completa ni una eina de correcció automàtica.
Un mateix control tracta permisos excessius i combinacions de grups permissives.
No s'ha compromès un segon control independent.

## Evidències reals incloses

Entorn registrat: Ubuntu 24.04.5 AArch64, OpenNebula 6.10.0.1 i Prowler 5.5.0.
Servidor: VM 2, NIC 0, 172.16.100.4; client: 172.16.100.5.
Política: TCP/22 només des de 172.16.100.1/32.

| Cas | Control | Resultat registrat |
|---|---|---|
| Només grup 100 | Nou | PASS |
| Grups 0 i 100 | Original network_public_ip | PASS |
| Grups 0 i 100 | Nou | FAIL |
| Retirada del grup 0 | Nou | PASS |

Els informes originals CSV, JSON-OCSF i HTML són a evidencies/. Els CSV
s'han comprovat abans d'empaquetar: control, estat i identificador del recurs nou.
No s'han generat dades d'auditoria sintètiques per completar el lliurament.
El PASS del control d'adreçament i el FAIL del nou corresponen a propietats diferents.

Els registres funcionals acrediten connexió TCP del client amb els grups combinats
(codigo_nc=0), timeout amb el restrictiu (codigo_nc=1) i SSH administratiu correcte.
La prova restrictiva es va fer abans de l'última restauració: després d'aquesta
restauració només s'ha repetit l'auditoria, no la comprovació funcional.

Al preparar aquest paquet s'han tornat a executar 35 proves automatitzades.
El registre nou és evidencies/proves-automatitzades-exportacio.log. Aquestes proves
utilitzen dades controlades i no són 35 experiments de xarxa reals.
exportacio.json identifica les versions i les evidències incorporades.

## Revisió sense desplegar OpenNebula

Llegir el mòdul admin_access.py, les metadades, la política YAML i els tests.
Els informes HTML permeten consultar les troballes amb un navegador local.
Les regles del control no fan connexions de prova ni modifiquen recursos.

## Instal·lació sobre la base reutilitzada

Cal Python 3.10 o superior, Git i les dependències del repositori original.
Des de la carpeta descomprimida, preparar una còpia separada del repositori:

```bash
git clone https://github.com/rontomano/TFM_prowler.git prowler-base
git -C prowler-base checkout a3c65a77bb08b3614d476d5e39f4f51917ce387c
python3 install.py --repo prowler-base --dry-run
python3 install.py --repo prowler-base
```

L'instal·lador afegeix fitxers, comprova els hash i no substitueix fitxers diferents.
Instal·lar les dependències de Prowler amb Poetry segons la seva documentació.
Des de prowler-base, executar:

```bash
poetry run python tests/providers/opennebula/services/network/test_admin_access.py
```

## Auditoria en un entorn OpenNebula propi

Adaptar tfm_examples/opennebula-admin-policy.yaml als identificadors, ports i orígens
de l'entorn. El paquet no inclou credencials. Cal preparar el fitxer de credencials
del proveïdor en una ubicació externa al repositori. Exemple d'execució:

```bash
poetry run python prowler-cli.py opennebula \
  --credentials-file /ruta/externa/opennebula.ini \
  --config-file tfm_examples/opennebula-admin-policy.yaml \
  --checks network_vm_admin_access_restricted \
  --output-directory resultats-prova
```

## Abast i limitacions

- Objectius VM/NIC explícits, VM ACTIVE/RUNNING, controlador fw, IPv4 i ports TCP.
- Es contrasten regles copiades, catàleg i estat de propagació informat per l'API.
- Les lectures de l'API no són una instantània transaccional del tallafoc del node.
- PASS: absència de permisos fora de política en l'abast avaluable; no certifica
  disponibilitat, autenticació, exposició a Internet ni tota la ruta de xarxa.
- MANUAL: dades o característiques que impedeixen justificar una conclusió.
- NETWORK_ID com a origen, IPv6 i altres controladors no estan implementats.
- El testimoni 0.0.0.0 del FAIL és un valor calculat, no el client real de prova.
- Pendent: cas real amb només grup 0, repetició funcional després de restaurar,
  ampliació d'excepcions i casos límit i revisió dels permisos mínims de consulta.

