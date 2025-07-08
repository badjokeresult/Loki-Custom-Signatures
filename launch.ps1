Start-Process -FilePath ".\loki-upgrader.exe"

Copy-Item .\bizone-landscape.yar .\signature-base\yara
Copy-Item .\c2-bizone-landscape.txt .\signature-base\iocs
Copy-Item .\filename-bizone-landscape.txt .\signature-base\iocs
Copy-Item .\c2-kaspersky-asian-apt.txt .\signature-base\iocs
Copy-Item .\filename-kaspersky-asian-apt.txt .\signature-base\iocs
Copy-Item .\hash-kaspersky-asian-apt.txt .\signature-base\iocs

Get-Content .\keywords.txt >> .\signature-base\iocs\keywords.txt
Start-Process -FilePath ".\loki.exe" -ArgumentList "--allhds"
