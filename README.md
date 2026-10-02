# Passwort-Prüfer

Ein kleines Python-Programm für die Kommandozeile. Es prüft, ob ein Passwort in
bekannten Datenlecks vorkommt, und bewertet zusätzlich Länge und Zeichenarten.

Das Passwort verlässt dabei nie den eigenen Rechner.

## Was das Programm macht

1. Es fragt das Passwort verdeckt ab (`getpass`). Statt der Zeichen erscheint
   für jedes getippte Zeichen ein Stern, so sieht man die bisherige Länge.
2. Es berechnet den SHA-1-Hash des Passworts (`hashlib`).
3. Es schickt nur die ersten fünf Zeichen des Hashes an die Schnittstelle von
   [Have I Been Pwned](https://haveibeenpwned.com/Passwords) und bekommt alle
   bekannten Hashes zurück, die so anfangen.
4. Es sucht den Rest des Hashes lokal in der Antwort und gibt aus, ob und wie
   oft das Passwort in Datenlecks vorkam.
5. Es bewertet Länge und Zeichenarten und gibt Hinweise zur Verbesserung.

## Warum nur fünf Zeichen? (k-Anonymität)

Ein SHA-1-Hash hat 40 Hex-Zeichen. Zu jedem Anfang aus fünf Zeichen gibt es in
der Datenbank mehrere hundert bis über tausend verschiedene Hashes. Der Server
sieht also nur, dass irgendeiner dieser vielen Hashes gemeint ist, aber nicht
welcher. Der eigentliche Vergleich passiert auf dem eigenen Rechner.

Beispiel mit dem Passwort `password`:

```
SHA-1-Hash:        5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
an die API:        5BAA6
lokal verglichen:       1E4C9B93F3F0682250B6CF8331B7EE68FD8
```

Zusätzlich sendet das Programm den Header `Add-Padding: true`. Die Schnittstelle
füllt die Antwort dann mit Platzhaltern (Anzahl 0) auf, damit sich aus der
Größe der Antwort nichts über das Präfix ableiten lässt.

## Bewertung der Stärke

Maximal sind 7 Punkte möglich:

| Kriterium | Punkte |
| --- | --- |
| Länge ab 8 / ab 12 / ab 16 Zeichen | 1 / 2 / 3 |
| Kleinbuchstaben enthalten | 1 |
| Großbuchstaben enthalten | 1 |
| Ziffern enthalten | 1 |
| Sonderzeichen enthalten | 1 |

| Punkte | Stufe |
| --- | --- |
| 0 bis 3, oder kürzer als 8 Zeichen | schwach |
| 4 bis 5 | mittel |
| 6 bis 7 | stark |

Wichtig: Ein Passwort, das in einem Datenleck vorkommt, ist unsicher, auch wenn
es nach diesen Regeln stark aussieht. `Passwort1!` erreicht zum Beispiel 5 Punkte
und taucht trotzdem tausendfach in Datenlecks auf.

## Benutzung

Voraussetzung ist Python 3.8 oder neuer. Die Sterne bei der Eingabe gibt es ab
Python 3.14, ältere Versionen zeigen beim Tippen nichts an. Es werden nur Module aus der
Standardbibliothek verwendet, es muss nichts installiert werden.

```
python passwort_pruefer.py
```

Beispielausgabe:

```
Passwort: **********

Stärke: mittel (5 von 7 Punkten, 10 Zeichen)
  - Mindestens 12 Zeichen verwenden.

Datenlecks: 10.000-mal gefunden.
Dieses Passwort nicht mehr verwenden, egal wie stark es aussieht.

Zum Beenden Enter drücken ...
```

Die Pause am Ende sorgt dafür, dass das Fenster auch beim Start per Doppelklick
offen bleibt, bis das Ergebnis gelesen wurde.

Hinweis: Das Programm sollte in einem echten Terminal gestartet werden
(PowerShell, Eingabeaufforderung, Bash). In manchen Entwicklungsumgebungen kann
`getpass` die Eingabe nicht verbergen und gibt dann eine Warnung aus.

## Tests

Die Tests brauchen keine Internetverbindung, die Antwort der Schnittstelle wird
simuliert.

```
python -m unittest -v
```

## Aufbau

| Datei | Inhalt |
| --- | --- |
| `passwort_pruefer.py` | Das Programm |
| `test_passwort_pruefer.py` | Tests für Hash, Suche in der Antwort und Bewertung |

## Grenzen

- "Nicht gefunden" heißt nur, dass das Passwort in den bekannten Datenlecks
  nicht vorkommt. Es ist kein Beweis, dass es sicher ist.
- Die Bewertung zählt nur Länge und Zeichenarten. Muster wie `Sommer2026!`
  oder Tastaturfolgen erkennt sie nicht.
- SHA-1 wird hier verwendet, weil die Schnittstelle es so vorgibt. Zum
  Speichern von Passwörtern ist SHA-1 nicht geeignet.
