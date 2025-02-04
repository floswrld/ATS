import pandas as pd
import json

excel_datei = "20241111_alle_Datenpunkte.xlsx"     # Name/ Pfad der Excel-Datei
json_datei  = "CLEANED_UP_SHORTEND_20241111_alle_Datenpunkte.json"      # Name/ Pfad der Ausgabedatei

df = pd.read_excel(excel_datei, header=None, engine="openpyxl")

# Annahme: In Zeile 2 (Index 1) befinden sich die Namen der Messreihen, beginnend ab Spalte 2 (Index 1)
messreihen_namen = df.iloc[1, 1:]

# Daten beginnen ab Zeile 13 (Index 12) und gehen bis Zeile 2220
daten_df = df.iloc[12:2220].reset_index(drop=True)
datumsspalte = daten_df.iloc[:, 0]

ergebnis = {}

# Schleife nur über Spalten 2 bis 12 (d.h. in daten_df: Spaltenindex 2 bis 12)
# Hinweis: Da in daten_df die erste Spalte (Index 0) das Datum enthält,
# entspricht Spalte 2 (Index 2) der dritten Spalte der Excel-Datei.
for spalte in range(1, 2):
    # Für den Namen der Messreihe muss der Index um 1 korrigiert werden, 
    # da messreihen_namen ab Spalte 2 (Excel) beginnt und somit der erste Name bei Index 0 liegt.
    name = messreihen_namen.iloc[spalte - 1]
    
    messwerte = {}
    
    for i, datum in enumerate(datumsspalte):
        wert = daten_df.iat[i, spalte]
        
        if pd.notnull(datum):
            if isinstance(datum, pd.Timestamp):
                datum_str = datum.strftime("%d.%m.%Y %H:%M:%S")
            else:
                datum_str = str(datum)
        else:
            datum_str = ""
        
        messwerte[datum_str] = wert

    ergebnis[name] = messwerte

with open(json_datei, "w", encoding="utf-8") as f:
    json.dump(ergebnis, f, ensure_ascii=False, indent=4)

print(f"JSON-Datei wurde erfolgreich als '{json_datei}' erstellt.")
