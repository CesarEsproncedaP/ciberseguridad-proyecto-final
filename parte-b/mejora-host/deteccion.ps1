$desde = (Get-Date).AddMinutes(-10)
$ev = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625,4656; StartTime=$desde} -ErrorAction SilentlyContinue
$n = ($ev | Measure-Object).Count
"[{0}] Eventos en los ultimos 10 min: {1}" -f (Get-Date), $n
if ($n -ge 3) {
  $msg = "[{0}] ALERTA: {1} eventos de acceso fallido" -f (Get-Date), $n
  Write-Host $msg -ForegroundColor Red
  Add-Content C:\DAutoLab\alertas.log $msg
}
