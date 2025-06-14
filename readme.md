# Biometrical-Security-Systems
Reports in LaTeX for suject "Biometrical Security-Systems" for my college. Additionaly, Info how to do them

## Instalacja LaTeXa

- Krok 1: Zainstaluj LaTeX
  - MiKTeX (Windows) – https://miktex.org/
  - TeX Live (Linux/macOS/Windows) – https://www.tug.org/texlive/
  - MacTeX (macOS) – https://www.tug.org/mactex/

- Krok 2:
  - TeXstudio (darmowy, polecany dla początkujących)(używany przezemnie)
  - Overleaf (online: https://www.overleaf.com/) – nie wymaga instalacji. 

## Główne

Główną częścią sprawozdań jest plik praca.tex. W nim znajdują się style, biblioteki itd. Ale dla nas najważniejszym jest to, że właśnie w tym pliku dodajemy po kolei sprawozdania do każdego labu:
```
\include{chapters\Lab00X}
```

Poza dodawaniem sprawozdań, w tym pliku należy dokładnie sprawdzić wszystkie miejsca na wpisanie danych osobistych i je zmienić pod siebie.

## Krótko o LaTeXu

LaTeX jest fajnym narzędziem do robienia takiego rodu rzeczy. Jest bardzo prosty w formatowaniu:

```
\command{foo}
```
Każde polecenie w LaTeX rozpoczyna się od backslasha, następnie samo polecenie, a wewnąrz klamer wpisujesz dane do polecenia. Normalny tekst piszęmy poprostu normalnie, jak w .txt pliku.

O używanych przezemnie poleceniach LaTeX znajdziesz na końcu instrukcji.

## Sprawozdania

Sprawozdania to są pliki .tex znajdujące się w katalogu "chapters". Żeby stworzyć kolejne sprawozdanie, używamy mojego szablonu "Lab00X.tex"(Zapisz jako, oraz skopiować .aux plik ze zmianą nazwy).

- Jako pierwszy krok, należy zmodyfikować tablice na samym początku sprawozdania. Dodać temat, imię, nazwisko, etc.
  ```
  \begin{table}[H]
      \centering
      \renewcommand{\tabularxcolumn}[1]{m{#1}}  % Dostosowanie kolumny do zawartości
      \newcolumntype{C}{>{\centering\arraybackslash}X}
      \begin{tabularx}{\linewidth}{|C|C|}
          \hline
          \multicolumn{2}{|c|}{\makecell{\textbf{\Large{Biometryczne Systemy Zabezpieczeń}} \\ \textbf{Ćwiczenia Laboratoryjne}}} \\ \hline
          \multicolumn{1}{|l|}{Temat}                    &              TEMAT            \\ \hline
          \multicolumn{1}{|l|}{Ćwiczenie nr:}                    &      0X                   \\ \hline
          \multicolumn{1}{|l|}{Autorzy:}                         &   \@author                              \\ \hline
          \multicolumn{1}{|l|}{Grupa laboratoryjna}                       &       02               \\ \hline
          \multicolumn{1}{|l|}{Zespół nr. }                       &    XX                  \\ \hline
          \multicolumn{1}{|l|}{Data wykonana ćwiczenia}         &  XX.04.2025     \\ \hline
          \multicolumn{1}{|l|}{Data oddania ćwiczenia  }         &   13.05.2025     \\ \hline
      \end{tabularx}
  \end{table}
  ```
- Następnie uzupełnić podsekcje ze wstępem teoretycznym oraz używanym narzędziem.
  ```
  \section{Cel ćwiczenia}
  
  \section{Wstęp teoretyczny}
  
  \section{Opis wykorzystywanego oprogramowania i narzędzi}
  ```
- Następnie należy skopiować podsekcje {Zadanie X} i po kolei wykonywać wymaganie zadania.
  ```
  \section{Zadania do wykonania samodzielnego}
  
  \subsection{Zadanie X}
  
  \subsubsection{Treść}
  
  \subsubsection{Przykładowy program}
  
  \subsubsection{Obrazy}
  ```
  - Wszystkie pliku matlabowe powinny się znajdywac w "src/Lab00X", łatwo później je wykorzystywać do dalszej pracy w robieniu sprawozdań.
  - Dla wstawienia przykładowego programu MatLab oraz obrazów patrz koniec instrukcji.

## Użyteczne polecenia LaTeX

- Sekcje - używane przezemnie w postaci:
  ```
  \section{sekcja}
  \subsection{subsekcja}
  \subsubsection{subsubsekcja}
  ```
- Listy:
  - Unordered list
  ```
  \begin{itemize}
  	\item Raz
  	\item Dwa
  	\item Trzy
  \end{itemize}
  ```
  - Ordered list
  ```
  \begin{enumerate}
	  \item Raz
	  \item Dwa
	  \item Trzy
  \end{enumerate}
  ```
  - Listy można zagnieżdżać tyle ile jest potrzebne
- Programy
  ```
  \lstinputlisting[style= matlabStyle, caption= Wczytanie obrazu i stworzenie konwersji, label=Lab002_l1]{src/Lab002/zadanie1.m}
  ```
- Obrazy - używam jedego ze sposobów na zamieszanie obrazów:
  ```
  \begin{figure}[H]
  	\centering
  	\begin{subfigure}[t]{0.45\linewidth}
  		\centering
  		\includegraphics[width=\linewidth]{src/Lab002/zadanie1images/filtracja_3x3.png}
  		\caption{Filtracja splotowa 3x3}
  		\label{fig:3x3}
  	\end{subfigure}
  	\hfill
  	\begin{subfigure}[t]{0.45\linewidth}
  		\centering
  		\includegraphics[width=\linewidth]{src/Lab002/zadanie1images/filtracja_5x5.png}
  		\caption{Filtracja splotowa 5x5}
  		\label{fig:5x5}
  	\end{subfigure}
  \end{figure}
  ```
  - Zamieszcza to dwa obrazy w jednym rzędzie.
