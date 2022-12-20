# IcyCore Analyzing Tool

# English Version (Deutsche Version weiter unten.)

This project started on the 13th April 2021 as an example for job applications for myself.

It is a framework for analyzing processes that are 32-bit and have protection against normal debuggers.

It is written with the new C++20 standard in mind.

Currently, it has the following features which will continue to be expanded upon in the future:

# Dynamic System Calls

This allows you to perform system calls for NTAPI functions.

It removes the possible interactions of the process you want to analyze, intercepting calls via hooks on NTAPI functions.

Currently, it needs to be updated so that it does not crash the IcyCore analyzing tool if the function you want to perform a system call with is hooked.

It works by allocating a new code section, copies the full function into that new code section, and calls that instead.

Future implementation will include rebuilding the function body and copying that into the allocated code section.

# Wow64Transition hooking (Heavensgate hooking)

This allows us to dynamically hook any NTAPI function that performs a system call.

System calls from 32-bit must be converted to 64-bit.

First, we hook the code snippet that is responsible for jumping into the 64-bit address space.

From there we manipulate the return address so that it points to our hooking function before ultimately returning to the callee.

Doing this allows us to modify the parameters and return results before the intended callee receives them.

# MemoryAddress

This class allows you to handle memory addresses easier, such as:

•	Offsetting them by x amount of bytes.

•	Dereferencing the memory address in the class.

•	Checking if the current address has certain bytes.

# MemoryModules

This is a class that will hold basic information about a module (dynamic-linked libraries).

It is in a namespace because there are sub-functions that will grab all the modules that are currently loaded from the process environment block and push them back into an unordered_map.

It allows you to get functions from the export table without calling WINAPI and find certain sequences within the memory.

More applications are to come.


# Future goals

•	A UI that allows you to dynamically hook any memory address that you supply to it.

•	Stealth module injection into any process

•	Virtual Method and Table hooking.

•	Proper detour hooking.

•	More overall customizability via scripting or DLL loading.


More to come in the future. Thanks for reading!

# German Version

Dieses Projekt startete am 13ten April 2021 als ein Projekt Beispiel für Ausbildungsbewerbungen. Für mich selbst.

IcyCore ist ein Analysen Framework um Prozesse die 32-bit sind und sich gegen herkömmlich Debugger schützen vernünftig analysieren zu können.

Es wird geschrieben mit dem neuen C++20 Standart im Hinterkopf.

Momentan hat es diese Features wozu noch weiter hinzukommen werden:

# Dynamic System Calls

Dynamic System Calls erlaubt uns direkt System Calls für NTAPI Funktionen durchzuführen

Wenn wir normalerweise die Funktion aus dem Export Table holen und die so aufrufen könnte der Prozess diese abfangen mit einer herkömmlichen Detour Hook.

Die Methode wie der System Call durchgeführt wird muss noch geändert werden. Wenn die Funktion Detour Hooked ist mit der man einen System Call durchführen möchte wird das Programm abstürzen.

Es funktioniert da wir eine neue Code Sektion erstellt und die komplette Funktion einfach in die neues Code Sektion reinkopiert und diese anstattdessen aufruft.

Zukünftige implementation wird sein das die Funktion nachgestellt wird und dann in eine neue Code Sektion kopiert wird und diese stattdessen aufgerufen wird.

# Wow64Transition hooking (Heavensgate hooking)

Hiermit können wir jeden System Call abfangen der im Prozess stattfindet.

System calls müssen von 32-bit in 64-bit umgewandelt werden deshalb hooken wir die Code Sektion die dafür verantwortlich ist in den 64-bit Address Space zu springen.

Von dort aus manipulieren wir die Rückkehraddresse so das diese zur jeweiligen Ersatz Funktion hinführt bevor diese wieder zurück zum Aufrufer geht.

Das erlaubt uns die Argumente zu manipulieren und das return result zu verändern bevor der Aufrufer dieses bekommt.

# MemoryAddress

Diese Klasse wird benutzt um einfacher Memory Addressen benutzen zu können zum Beispiel:

•	Die Addresse um ein paar Bytes versetzten.

• Die Addresse Dereferenzieren.

• Die Addresse überprüfen ob eine bestimmte Byte Sequenz besteht.

Und noch mehr Funktionen die bald hinzugefügt werden!

# MemoryModules

Dies ist eine Klasse welche basische Informationen über Modules (dynamisch verknüpfte Bibliotheken) besitzen wird.

Es ist in einem namespace da es sub-funktionen gibt die alle Module aus dem Prozessblock holt und diese in eine unordered_map platziert.

MemoryModules erlaubt es dir zum Bespiel Funktionen von einem Module aus dem Export Table zu holen ohne GetProcAddress aufzurufen.

# Zukünftige Ziele

• Ein User Interface was es einem erlaubt dynamische jede Memory Address zu hooken und zu überprüfen.

• Versteckte Module injection in egal welchem Prozess.

• Virtuelle Methoden und Table hooking.

• Vernünftiges Detour Hooking.

• Mehr Anpassbarkeit für das ganze Programm durch Skripting oder DLL loading.

Danke für das lesen dieser README!
