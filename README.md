# ISA-2015
## Repozitář pro školní projekt do předmětu ISA.

Nástroj pro monitorování RIP a RIPng

Autor: **Jakub Stejskal**

Hodnocení: 15/15


**Seznam souborů:**
- Makefile
- myripsniffer.cpp
- myripresponse.cpp
- myriprequest.cpp
- tables.h
- readme
- manual.pdf
	
**Makefile:**
- $ make - přeloží program
- $ make clean - vyčistí složku
	
Program je potřebné spustit s právy administrátora!

**Spuštění:**

```./myripsniffer -i "rozhraní"```

Jako rozhraní je myšleno rozhraní, na kterém bude program odchytávat

```./myripresponse -i "rozhraní" -r "IP adresa/delka masky" -m "metrika" -t "tag" -p "heslo" -n "IP adresa dalšího hopu"```

Parametry -i, -m, -n, -p, -t  jsou nepovinné!

Příklad parametru -r -> -r 10.10.10.0/24

```./myriprequest -i "rozhraní" -r "IP adresa/delka masky" -d "cilová adresa"```

Všechny parametry jsou nepovinné, pokud -d není zadáno je datagram poslán na adresu multicastu (všem)
Bohužel tuto část se mi nepovedlo celu dokončit a proto nefunguje přesně jak má. V dokumentaci bohužel také není zmíněná z časové tísně.
