"""Tests für den Passwort-Prüfer. Laufen ohne Internetverbindung."""

import sys
import unittest
from unittest import mock

import passwort_pruefer

# SHA-1 von "password": 5BAA6 + 1E4C9B93F3F0682250B6CF8331B7EE68FD8
BEISPIEL_ANTWORT = (
    "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n"
    "1E4C9B93F3F0682250B6CF8331B7EE68FD8:52256179\r\n"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\r\n"
)


class Sha1HashTest(unittest.TestCase):
    def test_bekannter_hash(self):
        self.assertEqual(
            passwort_pruefer.sha1_hash("password"),
            "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8",
        )

    def test_umlaute(self):
        self.assertEqual(len(passwort_pruefer.sha1_hash("Grüße")), 40)


class ZaehleTrefferTest(unittest.TestCase):
    def test_treffer(self):
        rest = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
        self.assertEqual(passwort_pruefer.zaehle_treffer(BEISPIEL_ANTWORT, rest), 52256179)

    def test_kein_treffer(self):
        rest = "A" * 35
        self.assertEqual(passwort_pruefer.zaehle_treffer(BEISPIEL_ANTWORT, rest), 0)

    def test_platzhalter_zaehlt_nicht(self):
        rest = "F" * 35
        self.assertEqual(passwort_pruefer.zaehle_treffer(BEISPIEL_ANTWORT, rest), 0)


class PruefeDatenlecksTest(unittest.TestCase):
    def test_nur_praefix_wird_gesendet(self):
        with mock.patch.object(
            passwort_pruefer, "hole_hash_liste", return_value=BEISPIEL_ANTWORT
        ) as hole:
            anzahl = passwort_pruefer.pruefe_datenlecks("password")
        hole.assert_called_once_with("5BAA6")
        self.assertEqual(anzahl, 52256179)


class FragePasswortTest(unittest.TestCase):
    @unittest.skipIf(sys.version_info < (3, 14), "Sterne gibt es erst ab Python 3.14")
    def test_eingabe_wird_mit_sternen_angezeigt(self):
        with mock.patch("getpass.getpass", return_value="geheim") as abfrage:
            self.assertEqual(passwort_pruefer.frage_passwort(), "geheim")
        abfrage.assert_called_once_with("Passwort: ", echo_char="*")


class BewerteStaerkeTest(unittest.TestCase):
    def test_kurz_ist_immer_schwach(self):
        punkte, stufe, _ = passwort_pruefer.bewerte_staerke("aB3!")
        self.assertEqual(punkte, 4)
        self.assertEqual(stufe, "schwach")

    def test_nur_kleinbuchstaben(self):
        punkte, stufe, hinweise = passwort_pruefer.bewerte_staerke("password")
        self.assertEqual(punkte, 2)
        self.assertEqual(stufe, "schwach")
        self.assertIn("Ziffern fehlen.", hinweise)

    def test_mittel(self):
        punkte, stufe, _ = passwort_pruefer.bewerte_staerke("Passwort1!")
        self.assertEqual(punkte, 5)
        self.assertEqual(stufe, "mittel")

    def test_stark(self):
        punkte, stufe, hinweise = passwort_pruefer.bewerte_staerke("Korrekt-Pferd-Batterie-9")
        self.assertEqual(punkte, 7)
        self.assertEqual(stufe, "stark")
        self.assertEqual(hinweise, [])


if __name__ == "__main__":
    unittest.main()
