
 Projekt: “Biometryczny sejf” – system do zabezpieczania plików odciskiem palca
  Cel:

Aplikacja, która pozwala zaszyfrować i odszyfrować pliki tylko wtedy, gdy użytkownik poda pasujący odcisk palca.
  Jak to działa:
1. Rejestracja odcisku

    Użytkownik wybiera plik (np. PDF).

    Wgrywa odcisk palca → generowany jest szablon (template) z MegaMatcher.

    Generujesz z szablonu hash lub używasz go jako klucza szyfrującego.

    Plik zostaje zaszyfrowany i zapisany jako .secure.

2. Odszyfrowanie

    Użytkownik ładuje plik .secure.

    Wgrywa swój odcisk.

    Aplikacja porównuje szablony:

        Jeśli match: odszyfrowuje plik i zapisuje go jako oryginał.

        Jeśli nie match: komunikat o błędzie.

  Technicznie:

    Fingerprint → template: MegaMatcher (np. NFTemplate)

    Porównanie: NFMatcher.Verify(template1, template2)

    Szyfrowanie: Python (cryptography.fernet) lub C# (System.Security.Cryptography)

    Hash szablonu: np. SHA-256(template bytes) → klucz AES

  GUI:

    Streamlit (web), Tkinter (desktop), lub WPF (Windows)

    Funkcje:

        Wczytaj plik

        Wczytaj odcisk

        Szyfruj

        Deszyfruj




