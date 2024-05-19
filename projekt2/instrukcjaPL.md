```markdown
# Skrypt Bezpieczeństwa

Ten skrypt bezpieczeństwa pozwala osobom bez doświadczenia w cyberbezpieczeństwie uruchamiać podstawowe programy bezpieczeństwa. Obejmuje funkcje takie jak skanowanie portów, pingowanie, sniffing pakietów, uruchamianie Nmap i inne.

## Wymagania

- Python 3.x
- Wymagane moduły Pythona: `argparse`, `logging`, `datetime`, `subprocess`, `os`, `threading`, `socket`
- Scapy (do manipulacji pakietami): `pip install scapy`
- Metasploit Framework: Postępuj zgodnie z instrukcjami instalacji na [stronie Metasploit](https://www.metasploit.com/)

## Użycie

Skrypt można uruchomić na dwa sposoby:
1. **Menu interaktywne**: Uruchamia interfejs oparty na menu.
2. **Argumenty wiersza poleceń**: Uruchamianie konkretnych funkcji bezpośrednio z wiersza poleceń.

### Uruchamianie Menu Interaktywnego

Aby uruchomić menu interaktywne, użyj:
```bash
python security_script.py menu
```

### Uruchamianie Konkretnych Funkcji za Pomocą Argumentów w Wierszu Poleceń

#### 1. Uruchom Skanowanie Portów
Skanuje porty od 1 do 1024 na docelowym adresie IP.
```bash
python security_script.py port_scan <docelowy_ip>
```
**Przykład:**
```bash
python security_script.py port_scan 192.168.1.1
```
**Do czego to jest potrzebne:** Pozwala znaleźć otwarte porty, które mogą być podatne na ataki.

#### 2. Pingowanie Strony lub Komputera
Pingowanie określonego celu, aby sprawdzić, czy jest osiągalny.
```bash
python security_script.py ping <docelowy_ip_lub_url>
```
**Przykład:**
```bash
python security_script.py ping google.com
```
**Do czego to jest potrzebne:** Umożliwia sprawdzenie łączności sieciowej i czy cel jest aktywny.

#### 3. Włączenie Sniffingu Pakietów
Włącza sniffing pakietów na określonym interfejsie sieciowym.
```bash
python security_script.py sniff <interfejs>
```
**Przykład:**
```bash
python security_script.py sniff eth0
```
**Do czego to jest potrzebne:** Umożliwia monitorowanie ruchu sieciowego i wykrywanie anomalii.

#### 4. Uruchom Nmap
Uruchamia Nmap na określonym adresie IP.
```bash
python security_script.py nmap <docelowy_ip>
```
**Przykład:**
```bash
python security_script.py nmap 192.168.1.1
``]
**Do czego to jest potrzebne:** Pomaga w odkrywaniu hostów i usług w sieci komputerowej.

#### 5. Uruchom Konsolę MSF
Uruchamia konsolę Metasploit Framework.
```bash
python security_script.py msf
```
**Do czego to jest potrzebne:** Umożliwia przeprowadzenie testów penetracyjnych i badań bezpieczeństwa.

#### 6. Instalacja Zalecanych Narzędzi Bezpieczeństwa
Instaluje zalecane narzędzia bezpieczeństwa, takie jak Nmap, Wireshark i Metasploit.
```bash
python security_script.py install_tools
```
**Do czego to jest potrzebne:** Umożliwia skonfigurowanie środowiska do testowania bezpieczeństwa.

#### 7. Uruchom Dowolny Zainstalowany Program Bezpieczeństwa
Uruchamia dowolny zainstalowany program bezpieczeństwa wskazany przez użytkownika.
```bash
python security_script.py run_program <nazwa_programu>
```
**Przykład:**
```bash
python security_script.py run_program nmap
```
**Do czego to jest potrzebne:** Umożliwia uruchamianie narzędzi bezpieczeństwa dostępnych w systemie.

#### 8. Uruchom SCAPY
Uruchamia program Scapy do manipulacji pakietami.
```bash
python security_script.py scapy
``]
**Do czego to jest potrzebne:** Pozwala na tworzenie, wysyłanie i sniffing pakietów sieciowych.

#### 9. Wyłącz lub Zrestartuj Urządzenie
Wyłącza lub restartuje urządzenie zgodnie z wyborem użytkownika.
```bash
python security_script.py shutdown <akcja>
``]
**Przykład:**
```bash
python security_script.py shutdown shutdown
``]
lub
```bash
python security_script.py shutdown restart
``]
**Do czego to jest potrzebne:** Umożliwia zdalne zarządzanie stanem zasilania systemu.

#### 10. Wyświetl Log
Wyświetla bieżący log działań wykonanych przez skrypt bezpieczeństwa.
```bash
python security_script.py display_log
``]
**Do czego to jest potrzebne:** Umożliwia przeglądanie wykonanych działań i ich wyników.



