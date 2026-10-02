"""Passwort-Prüfer.

Prüft, ob ein Passwort in bekannten Datenlecks vorkommt (Have I Been Pwned),
und bewertet zusätzlich Länge und Zeichenarten.

Das Passwort verlässt dabei nie den eigenen Rechner: Es werden nur die ersten
fünf Zeichen des SHA-1-Hashes an die Schnittstelle geschickt (k-Anonymität).
"""

import getpass
import hashlib
import sys
import urllib.error
import urllib.request

API_URL = "https://api.pwnedpasswords.com/range/"
PRAEFIX_LAENGE = 5


def sha1_hash(passwort):
    """Gibt den SHA-1-Hash des Passworts als 40 Hex-Zeichen in Großbuchstaben zurück."""
    return hashlib.sha1(passwort.encode("utf-8")).hexdigest().upper()


def hole_hash_liste(praefix):
    """Fragt bei Have I Been Pwned alle Hashes ab, die mit dem Präfix beginnen.

    Die Antwort ist Text mit einer Zeile pro Hash im Format "REST:ANZAHL".
    """
    anfrage = urllib.request.Request(
        API_URL + praefix,
        headers={
            "User-Agent": "passwort-pruefer-lernprojekt",
            # Füllt die Antwort mit Platzhaltern (Anzahl 0) auf, damit man aus
            # der Antwortgröße nicht auf das Präfix schließen kann.
            "Add-Padding": "true",
        },
    )
    with urllib.request.urlopen(anfrage, timeout=10) as antwort:
        return antwort.read().decode("utf-8")


def zaehle_treffer(antwort_text, rest):
    """Sucht den Rest des Hashes in der Antwort und gibt die Anzahl der Funde zurück."""
    for zeile in antwort_text.splitlines():
        hash_rest, _, anzahl = zeile.partition(":")
        if hash_rest.strip().upper() == rest:
            return int(anzahl)
    return 0


def pruefe_datenlecks(passwort):
    """Gibt zurück, wie oft das Passwort in bekannten Datenlecks vorkam (0 = nie)."""
    hash_wert = sha1_hash(passwort)
    praefix = hash_wert[:PRAEFIX_LAENGE]
    rest = hash_wert[PRAEFIX_LAENGE:]
    # Nur das Präfix geht ins Netz, der Vergleich mit dem Rest passiert lokal.
    return zaehle_treffer(hole_hash_liste(praefix), rest)


def bewerte_staerke(passwort):
    """Bewertet Länge und Zeichenarten.

    Gibt (punkte, stufe, hinweise) zurück. Maximal sind 7 Punkte möglich:
    bis zu 3 für die Länge und je 1 für jede der vier Zeichenarten.
    """
    punkte = 0
    hinweise = []

    laenge = len(passwort)
    if laenge >= 16:
        punkte += 3
    elif laenge >= 12:
        punkte += 2
        hinweise.append("Ab 16 Zeichen wäre es noch sicherer.")
    elif laenge >= 8:
        punkte += 1
        hinweise.append("Mindestens 12 Zeichen verwenden.")
    else:
        hinweise.append("Zu kurz: mindestens 8, besser 12 oder mehr Zeichen verwenden.")

    zeichenarten = {
        "Kleinbuchstaben": any(z.islower() for z in passwort),
        "Großbuchstaben": any(z.isupper() for z in passwort),
        "Ziffern": any(z.isdigit() for z in passwort),
        "Sonderzeichen": any(not z.isalnum() for z in passwort),
    }
    for name, vorhanden in zeichenarten.items():
        if vorhanden:
            punkte += 1
        else:
            hinweise.append(f"{name} fehlen.")

    if laenge < 8 or punkte <= 3:
        stufe = "schwach"
    elif punkte <= 5:
        stufe = "mittel"
    else:
        stufe = "stark"

    return punkte, stufe, hinweise


def frage_passwort():
    """Fragt das Passwort verdeckt ab und zeigt für jedes Zeichen einen Stern."""
    if sys.version_info >= (3, 14):
        return getpass.getpass("Passwort: ", echo_char="*")
    # echo_char gibt es erst ab Python 3.14, ältere Versionen zeigen nichts an.
    return getpass.getpass("Passwort (Eingabe bleibt unsichtbar): ")


def main():
    passwort = frage_passwort()
    if not passwort:
        print("Kein Passwort eingegeben.")
        return 1

    punkte, stufe, hinweise = bewerte_staerke(passwort)
    print(f"\nStärke: {stufe} ({punkte} von 7 Punkten, {len(passwort)} Zeichen)")
    for hinweis in hinweise:
        print(f"  - {hinweis}")

    try:
        anzahl = pruefe_datenlecks(passwort)
    except (urllib.error.URLError, TimeoutError) as fehler:
        print(f"\nDatenleck-Prüfung nicht möglich: {fehler}")
        return 1

    if anzahl:
        anzahl_text = f"{anzahl:,}".replace(",", ".")
        print(f"\nDatenlecks: {anzahl_text}-mal gefunden.")
        print("Dieses Passwort nicht mehr verwenden, egal wie stark es aussieht.")
    else:
        print("\nDatenlecks: nicht gefunden.")
        if stufe != "stark":
            print("Es ist nicht geleakt, sollte aber noch stärker gewählt werden.")

    return 0


if __name__ == "__main__":
    rueckgabe = main()
    # Beim Start per Doppelklick schließt Windows das Fenster sofort nach
    # Programmende. Die Pause hält es offen, bis das Ergebnis gelesen wurde.
    input("\nZum Beenden Enter drücken ...")
    sys.exit(rueckgabe)
