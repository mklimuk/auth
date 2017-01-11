# language: pl
Funkcja: odczyt katalogu szablonów
  W celu wykorzystania szablonów
  Jako administrator
  Potrzebuję możliwości pobrania katalogu

  Scenariusz: Pusty katalog
    Zakładając brak szablonów
    Kiedy pobiorę katalog
    Wtedy na liście będzie 0 szablonów

  Scenariusz: Kilka elementów w katalogu
    Zakładając że w katalogu znajduje się 5 szablonów
    Kiedy pobiorę katalog
    Wtedy na liście będzie 5 szablonów
