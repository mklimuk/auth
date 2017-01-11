# language: pl
Funkcja: dodanie szablonu do katalogu
  W celu wykorzystania szablonów komunikatów
  Jako administrator
  Potrzebuję możliwości dodawania szablonów do katalogu

  Scenariusz: Dodaj jeden
    Zakładając brak szablonów
    Kiedy dodam do grupy "test", kategorii "info, testowe", w języku "pl" szablon o tytule "test pierwszy", opisie "to jest pierwszy testowy komunikat" i treści "test"
    I pobiorę katalog
    Wtedy na liście będzie 1 szablon
    I w grupie "test" będzie 1 szablon
    I w kategorii "info" będzie 1 szablon
    I w kategorii "testowe" będzie 1 szablon
